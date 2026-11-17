use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::Engine;

use anyhow::Context;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRoot {
    pub der: Vec<u8>,
    pub sha256: [u8; 32],
}

impl NativeRoot {
    pub fn fingerprint(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

#[derive(Debug, Default)]
pub struct NativeRoots {
    pub roots: Vec<NativeRoot>,
    pub errors: Vec<String>,
}

pub fn load_native_roots() -> NativeRoots {
    let loaded = rustls_native_certs::load_native_certs();

    let roots = loaded
        .certs
        .into_iter()
        .map(|cert| {
            let der = cert.as_ref().to_vec();
            let sha256 = Sha256::digest(&der).into();
            NativeRoot { der, sha256 }
        })
        .collect();

    let errors = loaded
        .errors
        .into_iter()
        .map(|error| error.to_string())
        .collect();

    NativeRoots { roots, errors }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedChain {
    pub end_entity: Vec<u8>,
    pub intermediates: Vec<Vec<u8>>,
}

pub type CapturedChain = Arc<Mutex<Option<PresentedChain>>>;

#[derive(Debug)]
pub struct CapturingWebPkiVerifier {
    inner: Arc<WebPkiServerVerifier>,
    captured: CapturedChain,
}

impl CapturingWebPkiVerifier {
    pub fn new(
        captured: CapturedChain,
        extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
        webpki_roots: bool,
    ) -> anyhow::Result<Self> {
        let mut roots = if webpki_roots {
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        } else {
            rustls::RootCertStore::empty()
        };

        for root in extra_roots {
            roots
                .add(root)
                .context("could not add extra TLS probe root")?;
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .context("could not build WebPKI certificate verifier")?;

        Ok(Self { inner, captured })
    }
}

impl ServerCertVerifier for CapturingWebPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );

        if matches!(
            result,
            Err(Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        ) {
            let chain = PresentedChain {
                end_entity: end_entity.as_ref().to_vec(),
                intermediates: intermediates
                    .iter()
                    .map(|cert| cert.as_ref().to_vec())
                    .collect(),
            };

            *self
                .captured
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(chain);
        }

        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub fn capturing_tls_connector(
    captured: CapturedChain,
    extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
) -> anyhow::Result<whatsapp_rust::transport::Connector> {
    capturing_tls_connector_with_roots(captured, extra_roots, true)
}

fn capturing_tls_connector_with_roots(
    captured: CapturedChain,
    extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    webpki_roots: bool,
) -> anyhow::Result<whatsapp_rust::transport::Connector> {
    use tokio_rustls::TlsConnector;
    use whatsapp_rust::transport::Connector;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let verifier = Arc::new(CapturingWebPkiVerifier::new(captured, extra_roots, webpki_roots)?);

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    config.resumption = rustls::client::Resumption::in_memory_sessions(16);

    Ok(Connector::Rustls(TlsConnector::from(Arc::new(config))))
}

pub async fn probe_server_chain_with_roots(
    host: &str,
    port: u16,
    extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    webpki_roots: bool,
) -> anyhow::Result<Option<PresentedChain>> {
    let proxy = crate::proxy::from_settings().or_else(|| crate::proxy::from_env(host));
    probe_server_chain_via(host, port, extra_roots, proxy, std::time::Duration::from_secs(10), webpki_roots).await
}

async fn probe_server_chain_via(
    host: &str,
    port: u16,
    extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    proxy: Option<crate::proxy::Proxy>,
    timeout: std::time::Duration,
    webpki_roots: bool,
) -> anyhow::Result<Option<PresentedChain>> {
    let captured: CapturedChain = Arc::new(Mutex::new(None));
    let connector = capturing_tls_connector_with_roots(Arc::clone(&captured), extra_roots, webpki_roots)?;

    let probe = async {
        let stream = match proxy {
            Some(proxy) => proxy.connect(host, port).await,
            None => tokio::net::TcpStream::connect((host, port)).await,
        }
        .with_context(|| format!("could not connect to {host}:{port} for TLS probe"))?;
        connector
            .wrap(host, stream)
            .await
            .map_err(anyhow::Error::from)
    };

    match tokio::time::timeout(timeout, probe).await {
        Err(_) => Err(anyhow::anyhow!("TLS probe for {host} timed out")),
        Ok(Ok(_)) => Ok(None),
        Ok(Err(error)) => {
            let chain = captured
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone();

            match chain {
                Some(chain) => Ok(Some(chain)),
                None => Err(anyhow::anyhow!(
                    "TLS probe failed before a certificate chain was captured: {error}"
                )),
            }
        }
    }
}

pub async fn probe_server_chain(host: &str, port: u16) -> anyhow::Result<Option<PresentedChain>> {
    probe_server_chain_with_roots(host, port, std::iter::empty(), true).await
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: [u8; 32],
}

impl CertificateInfo {
    pub fn fingerprint(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

pub fn certificate_info(der: &[u8]) -> anyhow::Result<CertificateInfo> {
    let (remaining, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("could not parse X.509 certificate: {error}"))?;

    anyhow::ensure!(
        remaining.is_empty(),
        "X.509 certificate contained unexpected trailing data"
    );

    Ok(CertificateInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        sha256: Sha256::digest(der).into(),
    })
}

pub fn find_presented_native_root(
    chain: &PresentedChain,
    native_roots: &[NativeRoot],
) -> Option<NativeRoot> {
    chain
        .intermediates
        .iter()
        .rev()
        .chain(std::iter::once(&chain.end_entity))
        .find_map(|presented| {
            let sha256: [u8; 32] = Sha256::digest(presented).into();

            native_roots
                .iter()
                .find(|root| root.sha256 == sha256 && root.der.as_slice() == presented.as_slice())
                .cloned()
        })
}

pub fn find_presented_root_candidate(chain: &PresentedChain) -> Option<NativeRoot> {
    chain
        .intermediates
        .iter()
        .rev()
        .chain(std::iter::once(&chain.end_entity))
        .find_map(|presented| {
            let (remaining, cert) = x509_parser::parse_x509_certificate(presented).ok()?;

            if !remaining.is_empty()
                || !cert.is_ca()
                || cert.subject() != cert.issuer()
                || cert.verify_signature(None).is_err()
            {
                return None;
            }

            let der = presented.clone();
            let sha256 = Sha256::digest(&der).into();

            Some(NativeRoot { der, sha256 })
        })
}

pub fn find_root_candidate(chain: &PresentedChain) -> anyhow::Result<Option<NativeRoot>> {
    let native = load_native_roots();

    if let Some(root) = find_presented_native_root(chain, &native.roots) {
        return Ok(Some(root));
    }

    Ok(find_presented_root_candidate(chain))
}

pub fn find_validated_root_candidate(
    host: &str,
    chain: &PresentedChain,
) -> anyhow::Result<Option<NativeRoot>> {
    let native = load_native_roots();
    let presented = find_presented_root_candidate(chain);
    for root in presented.into_iter().chain(native.roots) {
        let Ok((remaining, cert)) = x509_parser::parse_x509_certificate(&root.der) else {
            continue;
        };
        if remaining.is_empty()
            && cert.is_ca()
            && candidate_validates_presented_chain(host, chain, &root).is_ok()
        {
            return Ok(Some(root));
        }
    }
    Ok(None)
}

pub fn candidate_validates_presented_chain(
    host: &str,
    chain: &PresentedChain,
    root: &NativeRoot,
) -> anyhow::Result<()> {
    let mut roots = rustls::RootCertStore::empty();

    roots
        .add(CertificateDer::from(root.der.clone()))
        .context("could not add candidate root certificate")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .context("could not build candidate certificate verifier")?;

    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid TLS server name {host}: {error}"))?;

    let end_entity = CertificateDer::from(chain.end_entity.as_slice());

    // The trusted root belongs in RootCertStore, not in the untrusted
    // intermediate list, even if the server sent it as part of its chain.
    let intermediates: Vec<_> = chain
        .intermediates
        .iter()
        .filter(|cert| cert.as_slice() != root.der.as_slice())
        .map(|cert| CertificateDer::from(cert.as_slice()))
        .collect();

    verifier
        .verify_server_cert(
            &end_entity,
            &intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "candidate root does not validate the presented chain for {host}: {error}"
            )
        })?;

    Ok(())
}

const TRUST_FILE_VERSION: u32 = 1;
pub(crate) static TRUST_FILE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedEnterpriseCa {
    // Complete DER certificate (encoded as base64)
    // certificates explicitly approved by the user go here
    pub certificate_der_base64: String,

    // Uppercase colon-separated SHA-256 fingerprint shown during approval
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseCaTrust {
    pub version: u32,
    pub approved_roots: Vec<ApprovedEnterpriseCa>,
}

impl Default for EnterpriseCaTrust {
    fn default() -> Self {
        Self {
            version: TRUST_FILE_VERSION,
            approved_roots: Vec::new(),
        }
    }
}

impl ApprovedEnterpriseCa {
    pub fn native_root(&self) -> anyhow::Result<NativeRoot> {
        let der = base64::engine::general_purpose::STANDARD
            .decode(&self.certificate_der_base64)
            .context("approved enterprise CA contains invalid base64")?;

        let sha256: [u8; 32] = Sha256::digest(&der).into();

        let root = NativeRoot { der, sha256 };

        anyhow::ensure!(
            root.fingerprint() == self.sha256,
            "approved enterprise CA fingerprint does not match its certificate"
        );

        Ok(root)
    }
}

impl EnterpriseCaTrust {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents =
            std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;

        let trust: Self = serde_json::from_slice(&contents)
            .with_context(|| format!("could not parse {}", path.display()))?;

        anyhow::ensure!(
            trust.version == TRUST_FILE_VERSION,
            "unsupported enterprise CA trust-file version {}",
            trust.version
        );

        // Treat the whole file as invalid if even one stored certificate was modified or corrupted. NEVER SILENTLY TRUST PART OF IT
        for approved in &trust.approved_roots {
            approved.native_root()?;
        }

        Ok(trust)
    }

    pub fn native_roots(&self) -> anyhow::Result<Vec<NativeRoot>> {
        self.approved_roots
            .iter()
            .map(ApprovedEnterpriseCa::native_root)
            .collect()
    }
}

impl ApprovedEnterpriseCa {
    pub fn from_native_root(root: &NativeRoot) -> Self {
        Self {
            certificate_der_base64: base64::engine::general_purpose::STANDARD.encode(&root.der),
            sha256: root.fingerprint(),
        }
    }
}

impl EnterpriseCaTrust {
    pub fn is_approved(&self, root: &NativeRoot) -> bool {
        let fingerprint = root.fingerprint();

        self.approved_roots
            .iter()
            .any(|approved| approved.sha256 == fingerprint)
    }

    pub fn approve(&mut self, root: &NativeRoot) -> bool {
        let fingerprint = root.fingerprint();

        if self
            .approved_roots
            .iter()
            .any(|approved| approved.sha256 == fingerprint)
        {
            return false;
        }

        self.approved_roots
            .push(ApprovedEnterpriseCa::from_native_root(root));

        true
    }

    pub fn contents(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).context("could not serialize enterprise CA trust file")
    }
}

impl EnterpriseCaTrust {
    /// Replaces the trust file whole, rather than modifying it in place.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let contents = self.contents().map_err(std::io::Error::other)?;
        fastframe_file::write(path, contents)
    }

    /// Queues the replacement through ZapFast's background file writer.
    pub fn save_to(&self, files: &fastframe_file::Writer, path: &Path) -> std::io::Result<()> {
        let contents = self.contents().map_err(std::io::Error::other)?;

        files.write(path, contents, fastframe_file::Access::Default);

        Ok(())
    }
}

pub fn approved_tls_connector(
    trust: &EnterpriseCaTrust,
) -> anyhow::Result<whatsapp_rust::transport::Connector> {
    use tokio_rustls::TlsConnector;
    use whatsapp_rust::transport::Connector;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    for root in trust.native_roots()? {
        roots
            .add(CertificateDer::from(root.der))
            .context("could not add approved enterprise CA")?;
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    config.resumption = rustls::client::Resumption::in_memory_sessions(16);

    Ok(Connector::Rustls(TlsConnector::from(Arc::new(config))))
}

pub fn approve_and_save(path: &Path, root: &NativeRoot) -> anyhow::Result<bool> {
    let _guard = TRUST_FILE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut trust = EnterpriseCaTrust::load(path)?;

    let added = trust.approve(root);

    if added {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }

        trust
            .save(path)
            .with_context(|| format!("could not save {}", path.display()))?;
    }

    Ok(added)
}

pub fn load_approved_tls_connector(
    path: &Path,
) -> anyhow::Result<Option<whatsapp_rust::transport::Connector>> {
    let trust = EnterpriseCaTrust::load(path)?;

    if trust.approved_roots.is_empty() {
        return Ok(None);
    }

    approved_tls_connector(&trust).map(Some)
}

pub fn add_approved_certificates_to_blocking_builder(
    mut builder: reqwest::blocking::ClientBuilder,
    trust: &EnterpriseCaTrust,
) -> anyhow::Result<reqwest::blocking::ClientBuilder> {
    for root in trust.native_roots()? {
        let certificate = reqwest::Certificate::from_der(&root.der)
            .context("could not parse approved enterprise CA for reqwest")?;
        builder = builder.add_root_certificate(certificate);
    }

    Ok(builder)
}

pub fn add_approved_certificates_to_async_builder(
    mut builder: reqwest::ClientBuilder,
    trust: &EnterpriseCaTrust,
) -> anyhow::Result<reqwest::ClientBuilder> {
    for root in trust.native_roots()? {
        let certificate = reqwest::Certificate::from_der(&root.der)
            .context("could not parse approved enterprise CA for reqwest")?;
        builder = builder.add_root_certificate(certificate);
    }

    Ok(builder)
}

pub fn approved_reqwest_client(
    trust: &EnterpriseCaTrust,
) -> anyhow::Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10));

    if let Some(proxy) = crate::proxy::reqwest_proxy() {
        builder = builder.proxy(proxy);
    }

    builder = add_approved_certificates_to_blocking_builder(builder, trust)?;

    builder
        .build()
        .context("could not build approved enterprise HTTP client")
}

const APPROVED_HTTP_MAX_BODY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
#[derive(Clone, Debug)]
pub struct ApprovedReqwestHttpClient {
    client: reqwest::blocking::Client,
}

impl ApprovedReqwestHttpClient {
    pub async fn new(trust: &EnterpriseCaTrust) -> anyhow::Result<Self> {
        let trust = trust.clone();

        let client = tokio::task::spawn_blocking(move || approved_reqwest_client(&trust))
            .await
            .context("approved enterprise HTTP client builder task failed")??;

        Ok(Self { client })
    }
}

#[whatsapp_rust::async_trait]
impl whatsapp_rust::http::HttpClient for ApprovedReqwestHttpClient {
    async fn execute(
        &self,
        request: whatsapp_rust::http::HttpRequest,
    ) -> anyhow::Result<whatsapp_rust::http::HttpResponse> {
        let client = self.client.clone();

        tokio::task::spawn_blocking(move || {
            let mut builder = match request.method.as_str() {
                "GET" => client.get(&request.url),
                "POST" => client.post(&request.url),
                method => {
                    anyhow::bail!("Unsupported HTTP method: {method}");
                }
            };

            for (key, value) in &request.headers {
                builder = builder.header(key, value);
            }

            if request.method == "POST" {
                builder = builder.body(request.body.map(|body| body.to_vec()).unwrap_or_default());
            }

            let mut response = builder.send()?;
            let status = response.status().as_u16();

            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut response, &mut body)?;

            Ok(whatsapp_rust::http::HttpResponse::new(status, body))
        })
        .await?
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn execute_streaming(
        &self,
        request: whatsapp_rust::http::HttpRequest,
    ) -> anyhow::Result<whatsapp_rust::wacore::net::StreamingHttpResponse> {
        if request.method != "GET" {
            anyhow::bail!("Streaming only supports GET, got: {}", request.method);
        }

        let mut builder = self.client.get(&request.url);

        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }

        let response = builder.send()?;
        let status = response.status().as_u16();

        let reader = std::io::Read::take(response, APPROVED_HTTP_MAX_BODY_BYTES);

        Ok(whatsapp_rust::wacore::net::StreamingHttpResponse::new(
            status,
            Box::new(reader),
        ))
    }

    fn supports_upload_streaming(&self) -> bool {
        true
    }

    fn execute_upload(
        &self,
        request: whatsapp_rust::http::HttpRequest,
        body: whatsapp_rust::wacore::net::UploadBody,
        content_length: u64,
    ) -> anyhow::Result<whatsapp_rust::http::HttpResponse> {
        if request.method != "POST" {
            anyhow::bail!(
                "Upload streaming only supports POST, got: {}",
                request.method
            );
        }

        let mut builder = self.client.post(&request.url);

        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }

        let body = reqwest::blocking::Body::sized(body, content_length);

        let mut response = builder.body(body).send()?;
        let status = response.status().as_u16();

        let mut response_body = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(&mut response, APPROVED_HTTP_MAX_BODY_BYTES),
            &mut response_body,
        )?;

        Ok(whatsapp_rust::http::HttpResponse::new(
            status,
            response_body,
        ))
    }
}

#[cfg(test)]
mod approval_tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn fixture() -> (CertificateDer<'static>, CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut ca = rcgen::CertificateParams::default();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
        let issuer = rcgen::CertifiedIssuer::self_signed(ca, rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["web.whatsapp.com".into()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        (
            issuer.der().clone(),
            leaf.der().clone(),
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        )
    }

    #[test]
    fn candidate_must_validate_the_chain_and_hostname() {
        let (ca, leaf, _) = fixture();
        let root = NativeRoot { sha256: Sha256::digest(ca.as_ref()).into(), der: ca.as_ref().to_vec() };
        let chain = PresentedChain { end_entity: leaf.as_ref().to_vec(), intermediates: vec![root.der.clone()] };
        assert!(candidate_validates_presented_chain("web.whatsapp.com", &chain, &root).is_ok());
        assert!(candidate_validates_presented_chain("wrong.example", &chain, &root).is_err());
        assert_eq!(find_validated_root_candidate("web.whatsapp.com", &chain).unwrap(), Some(root));
        assert!(find_validated_root_candidate("wrong.example", &chain).unwrap().is_none());
    }

    #[tokio::test]
    async fn probe_uses_proxy_and_respects_approved_roots_and_timeout() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca, leaf, key) = fixture();
        let config = rustls::ServerConfig::builder().with_no_client_auth()
            .with_single_cert(vec![leaf, ca.clone()], key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        for approved in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = crate::proxy::Proxy::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
            let acceptor = acceptor.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") { request.push(stream.read_u8().await.unwrap()); }
                assert!(request.starts_with(b"CONNECT web.whatsapp.com:443 HTTP/1.1\r\n"));
                stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                let _ = acceptor.accept(stream).await;
            });
            let roots = if approved { vec![ca.clone()] } else { vec![] };
            let chain = probe_server_chain_via("web.whatsapp.com", 443, roots, Some(proxy), std::time::Duration::from_secs(2), true).await.unwrap();
            assert_eq!(chain.is_some(), !approved);
            server.await.unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = crate::proxy::Proxy::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { let (_stream, _) = listener.accept().await.unwrap(); std::future::pending::<()>().await; });
        let error = probe_server_chain_via("web.whatsapp.com", 443, vec![], Some(proxy), std::time::Duration::from_millis(50), true).await.unwrap_err();
        assert!(error.to_string().contains("timed out"));
        server.abort();
    }
}
