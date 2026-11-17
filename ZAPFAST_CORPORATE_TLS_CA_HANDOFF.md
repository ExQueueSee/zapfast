# Zapfast Corporate TLS / Custom CA Support — Codex Handoff

_Last updated: 2026-11-12_

## Purpose

This document is the handoff for continuing the Zapfast corporate TLS interception / custom CA work in Codex.

The goal is to make **Zapfast itself** work safely on networks that perform TLS inspection, without modifying `whatsapp-rust`, without hard-coding any company/vendor certificates, and without silently trusting unknown certificate authorities.

The required security model is:

1. Try normal TLS verification first.
2. Only if normal verification fails, capture / probe the presented TLS chain.
3. Identify a plausible root CA candidate.
4. Validate that the candidate can actually validate the presented chain for the requested host.
5. Show the candidate to the user with certificate details.
6. Require explicit user approval.
7. Persist only explicitly approved CA roots.
8. Retry the original operation using normal WebPKI roots **plus** the approved roots.
9. Never auto-trust a MITM/interception certificate.

This is intentionally **fail-closed + explicit user approval**.

---

# Important project rule

## Do NOT modify `whatsapp-rust`

`whatsapp-rust` is an upstream dependency and separate repository.

This task must remain a **Zapfast-only implementation**.

It is acceptable to inspect `whatsapp-rust` read-only when necessary to understand APIs / transport behavior, but:

- no fork
- no source patches
- no local dependency modifications
- no changes committed to `whatsapp-rust`

Zapfast must inject its own TLS connector / HTTP client / trust logic through the APIs already exposed by `whatsapp-rust`.

---

# Repository and trust data

The dependency and its pinned revision are in `Cargo.toml` and `Cargo.lock`.
On Windows, Zapfast stores approved roots in its user configuration directory
in `enterprise-ca.json`. Each installation has its own approvals.

This handoff records the state of the November 12 snapshot. Read the current
source before following its implementation plan. The WIP branch includes later
changes.

---

# `enterprise_ca.rs` — existing architecture

The project already has a reusable enterprise/custom CA subsystem.

Important types / helpers include:

```rust
NativeRoot
NativeRoots
PresentedChain
CertificateInfo
EnterpriseCaTrust
ApprovedEnterpriseCa
```

Important helpers include:

```rust
load_native_roots()
probe_server_chain(...)
probe_server_chain_with_roots(...)
approved_tls_connector(...)
approved_reqwest_client(...)
add_approved_certificates_to_blocking_builder(...)
approve_and_save(...)
find_presented_native_root(...)
find_presented_root_candidate(...)
find_root_candidate(...)
find_validated_root_candidate(...)
candidate_validates_presented_chain(...)
certificate_info(...)
```

`EnterpriseCaTrust::is_approved(...)` was added during the recent work.

---

# `x509-parser` change

`x509-parser` did not enable signature verification by default.

Current `Cargo.toml` change:

```toml
x509-parser = { version = "0.18.1", features = ["verify"] }
```

This is required for cryptographic verification of self-signed root candidates using:

```rust
cert.verify_signature(None)
```

---

# Root candidate logic currently implemented

A presented-chain root candidate is accepted as a **candidate only** if:

- the DER parses completely
- it is a CA
- `subject == issuer`
- its self-signature verifies cryptographically

Conceptually:

```rust
pub fn find_presented_root_candidate(chain: &PresentedChain) -> Option<NativeRoot>
```

Then:

```rust
candidate_validates_presented_chain(host, chain, &root)
```

must succeed before prompting the user.

Important:

**This does not establish trust.**

A malicious MITM can create a self-signed CA and a valid forged leaf chain.

The explicit user approval is still the trust boundary.

---

# Probe support for extra trusted roots

The TLS probe now accepts optional extra roots.

This was needed because Signal sticker CDN uses its own pinned / special CA.

Added conceptually:

```rust
probe_server_chain_with_roots(
    host,
    port,
    extra_roots,
)
```

The original:

```rust
probe_server_chain(host, port)
```

remains as a wrapper using no extra roots.

This avoids incorrectly treating Signal's own expected CA as a MITM/interception CA.

---

# Signal sticker import — completed implementation

This was the first complete end-to-end approval flow.

## Root cause originally observed

Signal sticker imports failed with TLS validation:

```text
InvalidCertificate(UnknownIssuer)
```

A corporate TLS proxy intercepted `cdn.signal.org` and other hosts during testing.

The real HTTP content was reachable; TLS trust was the blocker.

A temporary hard-coded test CA proved the diagnosis, but that code was removed.

---

## Sticker HTTP client

Sticker import was moved from `ureq` to a `reqwest::blocking::Client`.

The client trusts:

- Signal's own sticker CDN CA
- plus user-approved Zapfast CAs

It also preserves proxy configuration.

Conceptually:

```rust
fn signal_client(
    trust: Option<&EnterpriseCaTrust>,
) -> Result<reqwest::blocking::Client, String>
```

---

## Signal-specific probe roots

`SIGNAL_CA` is converted to a rustls `CertificateDer` for probing:

```rust
signal_probe_roots()
```

This ensures normal Signal TLS is considered valid before attempting an interception candidate.

---

## Typed Signal import errors

Added:

```rust
pub(super) enum SignalImportError {
    Request(String),
    Other(String),
}
```

Reason:

Do NOT launch a CA approval probe for unrelated failures.

Current classification:

### `Request`

Only request `.send()` failures.

This may represent:

- TLS verification failure
- connection-level network failure

and therefore may justify a secondary TLS probe.

### `Other`

Examples:

- HTTP 404/500
- response read failure
- parse/decrypt failure
- invalid URL
- disk/write failure
- trust-file load failure
- task failure

These do **not** trigger a CA prompt.

---

# Sticker approval flow — verified end-to-end

Current behavior:

```text
Signal sticker import
    ↓
normal request fails
    ↓
error is SignalImportError::Request
    ↓
probe cdn.signal.org using Signal CA as an extra expected root
    ↓
normal TLS still fails
    ↓
capture chain
    ↓
find validated root candidate
    ↓
check candidate is not already approved
    ↓
Event::EnterpriseCaApprovalRequired
    ↓
UI prompt
    ↓
user Approve
    ↓
approve_and_save(...)
    ↓
Command::ImportStickerUrl retry
    ↓
pack downloads successfully
```

This has been tested successfully on the real corporate network.

---

# Approval prompt wording

The UI must NOT claim the CA is an "enterprise CA".

Zapfast cannot know whether the certificate comes from:

- an organization
- corporate firewall
- proxy
- antivirus
- security product
- malicious MITM attacker

Current user-facing title was corrected to:

```text
Trust this certificate authority?
```

The body explicitly warns that the CA could be from:

- organization
- network security software
- proxy
- antivirus
- man-in-the-middle attacker

The final warning should remain conceptually:

```text
Only approve this certificate authority if you recognize and trust it.

Approving it allows this certificate authority to authenticate intercepted HTTPS traffic for Zapfast.
```

The prompt shows:

- Host
- Subject
- Issuer
- Valid from
- Valid until
- SHA-256 fingerprint

Internal Rust names may still contain `EnterpriseCa`; the important part is not to misrepresent it in user-facing UI.

---

# UI / backend types added

## `backend::Event`

```rust
EnterpriseCaApprovalRequired {
    host: String,
    root: NativeRoot,
    certificate: CertificateInfo,
    retry_url: String,
}
```

Currently this retry payload is sticker-oriented and should likely become generic later.

## `backend::Command`

```rust
ApproveEnterpriseCa {
    root: NativeRoot,
    retry_url: String,
}
```

Again, currently sticker-oriented.

## `model::Dialog`

```rust
ConfirmEnterpriseCa {
    host: String,
    root: NativeRoot,
    certificate: Box<CertificateInfo>,
    retry_url: String,
}
```

`CertificateInfo` is boxed because otherwise Clippy flagged a large enum variant through `Overlay`.

## `model::Action`

```rust
ApproveEnterpriseCa {
    root: NativeRoot,
    retry_url: String,
},
CancelEnterpriseCa,
```

Cancel currently clears:

```rust
sticker_import_pending = false
```

---

# Why `Box<CertificateInfo>` exists

Running:

```powershell
cargo clippy --lib -- -D warnings
```

initially produced:

```text
large size difference between variants
```

because `Dialog::ConfirmEnterpriseCa` increased the size of the whole `Dialog` enum.

Only `CertificateInfo` was boxed instead of redesigning the whole `Overlay`.

Clippy is now clean.

---

# Existing main WhatsApp custom CA support

The **main WhatsApp connection already supports approved CAs**.

Current startup path in `src/backend/worker.rs`:

```rust
let enterprise_ca_trust =
    EnterpriseCaTrust::load(&self.enterprise_ca_file)
```

If approved roots exist:

### WebSocket

```rust
approved_tls_connector(&enterprise_ca_trust)
```

### WhatsApp HTTP

```rust
ApprovedReqwestHttpClient::new(&enterprise_ca_trust)
```

Then the correct combination is used for:

- proxy + approved CA
- proxy + normal trust
- direct + approved CA
- direct + normal trust

The builder currently chooses among all four combinations.

This means the **trust consumption side already exists**.

What is still missing is the **fresh-install / unknown-CA approval flow** for the main WhatsApp connection.

---

# Very important next implementation target

## Main WhatsApp connection: fresh CA approval

Current problem:

On a fresh install or empty `enterprise-ca.json`:

```text
corporate TLS interception
    ↓
WhatsApp connection fails
    ↓
no automatic custom CA approval prompt
```

The desired behavior is:

```text
Connect WhatsApp
    ↓
normal TLS verification
    ↓
TLS fails
    ↓
probe the actual target through the correct network route
    ↓
valid CA candidate discovered
    ↓
show generic trust prompt
    ↓
Approve
    ↓
persist root
    ↓
restart / retry WhatsApp connection
```

Cancel must:

- not save the CA
- not leave connection state stuck
- keep failure behavior understandable

Approved CA must not prompt again.

---

# IMPORTANT: do not jump straight into the WhatsApp popup yet

Before implementation, perform a complete **Zapfast outbound-network audit**.

The last discussion explicitly decided to stop making local assumptions and enumerate every network path first.

---

# Required audit plan

## 1. Enumerate every outbound network path in Zapfast

Search all current Zapfast code for:

- `reqwest`
- `ureq`
- rustls / `TlsConnector`
- `TcpStream`
- `.get(`
- `.post(`
- `.send(`
- `.call(`
- HTTP client constructors
- custom transport factories
- WebSocket connections
- `https://`
- `wss://`
- direct download helpers
- updater/network helpers

Build a matrix for every discovered path.

At minimum inspect:

- main WhatsApp WebSocket
- WhatsApp HTTP API
- media / attachment download
- avatar / profile picture download
- WhatsApp sticker/media CDN
- Signal sticker import
- link preview
- updater
- GIPHY
- any other external API
- any other custom download path

For every path record:

1. host / host class
2. TLS/HTTP client used
3. WebPKI used?
4. approved roots used?
5. proxy behavior
6. failure type propagated?
7. safe retry possible?

Do not assume previous patches are still present. Verify the **current source**.

---

# 2. Audit trust consumption vs trust creation separately

There are two different questions:

## A. Can this path USE an already approved CA?

Many paths may already support this.

## B. Can this path CREATE a new trust approval prompt safely?

These must NOT be treated as equivalent.

Example:

A link preview to an arbitrary attacker-controlled website may be allowed to **use an already approved CA**, but it must not necessarily be allowed to trigger:

```text
"Trust this CA globally in Zapfast?"
```

Otherwise an attacker could send a URL that causes a global trust prompt.

---

# 3. Classify network paths by prompt eligibility

Suggested categories:

## Known Zapfast / WhatsApp infrastructure

Possible trust-prompt source.

Examples:

- WhatsApp WebSocket
- WhatsApp HTTP endpoints
- possibly official Zapfast update endpoints

## Explicit user-triggered known service

Possible trust-prompt source.

Example:

- Signal sticker import

## Arbitrary remote URL

Usually should NOT be allowed to create a global trust prompt.

Examples:

- arbitrary link preview
- attacker-controlled URL in a message

Existing approved CA may still be used if appropriate.

---

# 4. Probe must become proxy-aware before claiming the system is generic

Current generic probe uses:

```rust
TcpStream::connect((host, port))
```

This is NOT sufficient for a fully generic solution.

If the real request uses:

- HTTP CONNECT proxy
- SOCKS5
- SOCKS5h
- configured Zapfast proxy
- environment proxy
- NO_PROXY

then the probe should follow the **same network route**.

Otherwise:

```text
real request → proxy → sees MITM CA

probe → direct → sees public certificate
```

and detection becomes wrong.

Audit / design this before generalizing approval beyond the current Signal direct-path behavior.

---

# 5. Main WhatsApp approval flow must distinguish TLS failure from unrelated connection errors

Do not show a CA prompt merely because WhatsApp failed to connect.

Potential failures include:

- DNS
- timeout
- connection refused
- proxy auth
- proxy tunnel failure
- protocol error
- WebSocket failure unrelated to certificate validation
- server rejection

Desired pattern:

```text
main operation failed
    ↓
run explicit TLS probe
    ↓
only if probe proves normal certificate verification fails
    ↓
find validated candidate
    ↓
prompt
```

This is safer than parsing arbitrary error strings.

---

# 6. Re-check root candidate completeness

Current presented-chain candidate logic only finds self-signed roots that are actually present in the chain.

But TLS servers often do **not** send the root certificate.

Need to evaluate whether the generic candidate logic should also:

- load native roots
- test which native root can validate the presented chain
- support chains where the root is not presented
- handle cross-signed roots / multiple possible roots

Do not weaken the explicit approval model while solving this.

---

# 7. Security tests required

Before considering this complete, cover:

- normal home/hotspot network → no prompt
- fresh corporate network → prompt
- Approve → retry succeeds
- restart → no repeat prompt
- Cancel → no persistence
- already-approved CA + unrelated timeout → no prompt
- HTTP 404 → no prompt
- DNS failure → no prompt
- invalid/self-signed leaf → no prompt
- non-CA candidate → no prompt
- invalid self-signature → no prompt
- hostname mismatch → no prompt
- candidate cannot validate chain → no prompt
- native root absent from presented chain → expected behavior
- direct
- HTTP proxy
- SOCKS5
- SOCKS5h
- NO_PROXY
- Signal normal public network → no prompt
- Signal corporate MITM → prompt
- arbitrary link-preview self-signed endpoint → no global trust prompt
- malformed trust file → fail closed
- duplicate approval → no duplicate entry

---

# 8. Persistence safety audit

Test:

- file missing
- file empty
- invalid JSON
- unsupported version
- invalid base64
- fingerprint mismatch
- duplicate CA
- restart reload

Malformed trust data must fail closed.

Never disable normal WebPKI verification.

---

# 9. UI / concurrency audit

Main connection approval can race with:

- an existing dialog
- account switch
- account becoming inactive
- repeated connection attempts
- multiple simultaneous TLS failures
- stale async completion

Need to ensure:

- no dialog overwrite
- no duplicate prompt storm
- no stale prompt
- retry only applies to the operation that requested trust
- Cancel clears pending state correctly
- closing the dialog through any alternative UI path does not leave state stuck

The existing `live` guard used for sticker approval is relevant.

---

# 10. Updater requires extra security review

Do not blindly add trust-prompt creation to update traffic.

First verify:

- update artifact signature / hash validation
- source host
- redirect policy
- whether TLS is the only authenticity layer

Approved CA consumption may be acceptable, but automatic trust-prompt creation for background updates may not be.

---

# 11. Trust scope question

Current approved CAs are effectively Zapfast-wide roots for clients that consume `EnterpriseCaTrust`.

The popup warning is written accordingly.

Audit whether this should remain:

```text
global Zapfast CA trust
```

or become:

```text
CA + host scope
```

Do not redesign this unless there is a concrete security/architecture reason.

---

# 12. Settings / revoke support — intentionally deferred

The user wants this eventually:

```text
Settings → Trusted Certificate Authorities
```

Possible UI:

- Subject
- Issuer
- validity
- SHA-256 fingerprint
- Remove / Revoke button
- confirmation dialog

Revoke must cause future clients/reconnections to stop trusting the CA.

But **do this last**, after the generic TLS approval / network coverage work is finished.

---

# Current verification status

The following have all succeeded after the recent implementation:

```text
cargo check
```

```text
cargo test sticker_import --lib
```

```text
cargo test --lib
```

Only expected ignored tests were seen, including network/notification/manual-file tests.

```text
cargo clippy --lib -- -D warnings
```

Clean.

```text
cargo fmt
```

Applied.

```text
git diff --check
```

No actual whitespace errors; only Windows LF/CRLF warnings.

Real runtime test:

- Zapfast launched successfully
- Signal sticker import succeeded
- approved CA persisted
- after restart the CA popup did not repeat
- subsequent sticker import succeeded directly

---

# Git hygiene

Before final commit / PR:

- no local `.cer/.crt/.pem` debug files
- no hard-coded fingerprints
- no user filesystem paths
- no temporary TLS debug logging
- no unrelated rustfmt changes
- no `whatsapp-rust` modifications

---

# Recommended next move in Codex

Do **not** immediately implement the WhatsApp popup.

First perform the complete current-source network audit described above and write a short internal matrix of every outbound connection path.

Then decide, per path:

```text
already-approved CA consumption?
new trust prompt allowed?
retry strategy?
proxy-aware probe strategy?
```

After that, implement the main WhatsApp fresh-install CA approval path first.

Proceed step-by-step: one focused change/test at a time rather than a large patch dump.
