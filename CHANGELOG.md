# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.23.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.23.0...sspi-v0.23.1)] - 2026-10-27

### <!-- 0 -->Security

- Add support for IAKerb extension for Kerberos client ([#751](https://github.com/Devolutions/sspi-rs/issues/751)) ([a738671298](https://github.com/Devolutions/sspi-rs/commit/a7386712984473147e9d94636859452b98a6fc8f)) 

  This PR adds support for the IAKERB extension according to the [IAKERB
  specification](https://datatracker.ietf.org/doc/html/draft-ietf-kitten-iakerb-03).
  
  The main changes are focused on the `Kerberos` state machine.
  Previously, the `Preauthentication` state handled the entire KDC message
  exchange withing a single async `intialize_security_context` call. This
  approach does not work with IAKERB, where KDC messages are exchanged via
  a server that acts as a proxy. The `Preauthentication` state has
  therefore been split into multiple states, allowing the state machine to
  save `Kerberos` state between KDC message exchanges.
  
  Additionaly, the `AS` and `TGS` exchanges have been extracted into
  separate state machines. These new state machines are KDC
  transport-agnostic and can be used with both external KDC and an IAKERB
  proxy.
  
  ## What is IAKERB
  IAKERB extends Kerberos to support scenarios where the client cannot
  directly access the KDC. Instead, KDC messages are encapsulated in
  GSS-API tokens and exchanged through an IAKERB proxy. The server
  forwards these messages to the LocalKDC, allowing the client to obtain
  the required Kerberos tickets without direct network access to the KDC.
  
  Microsoft recently introduced IAKERB support in Windows Insider builds
  as part of its effort to reduce NTLM dependency:
  https://techcommunity.microsoft.com/blog/windows-itpro-blog/reducing-ntlm-dependency-iakerb-and-localkdc-in-windows-insider-preview/4524615.
  
  ## Related PRs
  * picky-rs: https://github.com/Devolutions/picky-rs/pull/531
  * IronRDP: https://github.com/Devolutions/IronRDP/pull/1987

### <!-- 1 -->Features

- Add Remote Credential Guard client and Restricted Admin modes ([#778](https://github.com/Devolutions/sspi-rs/issues/778)) ([9b664dd014](https://github.com/Devolutions/sspi-rs/commit/9b664dd0140846fff4f2f21659c8f94d3c05a673)) 

  ## Summary
  
  - Add opt-in `CredSspMode::RemoteGuard` with Kerberos-only initial
  Negotiate authentication, mandatory peer MIC validation, and no NTLM or
  ordinary password-delegation fallback.
  - Construct type-6 `TSRemoteGuardCreds`, including a computer-account
  `HOST/<target>` service ticket and a forwarded TGT in the protected
  `KERB_TICKET_LOGON`/`KRB-CRED` path.
  - Add `sspi::rcg::RemoteGuardSession`: one-time ownership transfer of
  the established CredSSP protection context, preserving its enctype,
  acceptor subkey, identity binding, and consumed send/receive sequence
  numbers. Expose bounded message protection and session-authorized
  redirected Kerberos operations.
  - Provide explicit, default-off NTLMv2 supplementation and redirected
  operations. This does not enable NTLM for initial RCG authentication.
  - Make Restricted Admin (`CredSspMode::CredentialLess`) consistently
  emit empty type-1 password credentials for password, smart-card, and
  keytab authentication sources. Add explicit mode selection, optional
  NTLM policy, target binding, and session handoff to `SspiCredSsp`, while
  retaining ordinary delegation as its default.
  - Forward SSPI credential acquisition/custom identity installation to
  the inner provider, and prevent RCG identity replacement once
  authentication starts. Update README and API support/limitation
  documentation.
  
  ## Credential isolation and native contract corrections
  
  - Keep reusable TGT keys and the CredSSP protection key client-owned; do
  not add generic key export or clone a live protection context. Poisoning
  clears all session stores and disables further operations.
  - Match the documented/native service-ticket reply contract: ordinary
  service session keys are returned in the decrypted KDC reply for
  protected RDPEAR delivery; TGT/referral keys remain opaque. Follow-up
  service operations authorize only retained keys/handles from this
  session, with disjoint reference namespaces and strict role/enctype
  checks.
  - Apply the caller's signed authenticator skew directly to UTC without
  adding the cached KDC offset again.
  - Reject peer-supplied TGS authenticator subkeys explicitly: a
  peer-known subkey would otherwise let the remote host decrypt TGT
  replies outside client key isolation. Service AP-REQ subkeys and TGS
  requests without a subkey remain supported.
  - Treat unused native NTLM credential-key metadata as opaque while
  retaining strict flags and exact session-bound secret-reference
  validation; never use or export the received key material.
  
  ## Validation
  
  Deterministic local/synthetic fixtures only, including an in-memory
  TLS/SPNEGO/Kerberos peer and KDC. No new live domain authentication
  attempts, real credential inspection, or sensitive fixture files.
  
  With `SSPI_RS_IS_RUNNING_TESTS=true` and `CARGO_INCREMENTAL=0`:
  
  ```powershell
  cargo test -p sspi --lib --locked --offline --features 'network_client,__test-data,tsssp,scard' -- 'rcg::' 'remote_guard' 'credential_less' 'sspi_cred_ssp' 'credssp::ts_request::test::'
  cargo test -p sspi --test sspi --locked --offline --features 'network_client,__test-data,tsssp,scard' -- 'client_server::credssp::'
  cargo clippy -p sspi --lib --locked --offline --features 'network_client,__test-data,tsssp,scard' -- -D warnings
  cargo fmt -p sspi -- --check
  git diff --check
  ```
  
  - Combined features: **171 library tests + 20 CredSSP integration tests
  passed**, zero failures or ignored tests; overlapping selectors are not
  double-counted.
  - Baseline `network_client,__test-data`: **157 selected library tests +
  11 integration tests passed**.
  - Covers exact credential encoding, Kerberos-only rejection paths,
  optional NTLM identity/name binding, NTLM-only Restricted Admin,
  one-time live sequencing handoff and continuing TLS use, both AES key
  sizes/application tags, key-store capacity/authorization/collisions,
  skew boundaries, replay/integrity failure, and poisoning.
  - Production Clippy, formatting, whitespace, and changed-line style
  checks passed. Public docs build with existing unrelated rustdoc
  warnings.
  
  ## Interoperability boundaries
  
  - Earlier bounded Windows integration verified initial RCG logon and
  optional redirected NTLMv2 authentication on a fresh target logon. This
  is not proof of general native-layout or operation interoperability.
  - **Successful outbound native Kerberos authentication remains
  unverified.** The service-key/skew corrections in this PR have synthetic
  local validation, not a new Windows re-probe.
  - Reconnecting to an existing target logon retained an old credential
  binding in the tested setup; fresh target logon is required. No reusable
  credential state is transferred between connections.
  - Peer-supplied TGS authenticator subkeys intentionally remain
  unsupported rather than weakening isolation.
  - These are Rust client APIs, not server-side type-6 import, native
  extended-credential FFI support, or RDP connector/DVC transport wiring.
  Connectors must request the corresponding RDP mode, require server
  capability support, and protect RDPEAR using the handed-off live
  context.
  - No dependency/lockfile, intent-file, other-crate, or other-repository
  changes; no release publication.
  
  ---------

### <!-- 4 -->Bug Fixes

- Drop local qualifier before a qualified name ([#767](https://github.com/Devolutions/sspi-rs/issues/767)) ([d87a57a704](https://github.com/Devolutions/sspi-rs/commit/d87a57a7042cbefd1f794a9c3657b33d3cee8037)) 

- Enforce the sequence number of MIC token only for acce… ([#772](https://github.com/Devolutions/sspi-rs/issues/772)) ([08d8622794](https://github.com/Devolutions/sspi-rs/commit/08d862279488dcdd0030050d7047bef85686a57a)) 

  This PR fixes [#748](https://github.com/Devolutions/sspi-rs/issues/748)
  by enforcing sequence number verification only on the acceptor side. The
  initiator verifies the MIC checksum without enforcing the sequence
  number.
  
  ---------

- Interoperate with MIT and Heimdal KDCs ([#768](https://github.com/Devolutions/sspi-rs/issues/768)) ([cf91195338](https://github.com/Devolutions/sspi-rs/commit/cf91195338f62a8b01ca5024e06f97c150e03225)) 

  ## Summary
  
  Two client fixes for password logons against MIT and Heimdal KDCs, found
  while using `sspi` for SASL/GSSAPI binds to Active Directory and
  MIT/Heimdal realms. Each currently makes every such logon fail.
  
  - **Reuse the pre-authentication salt for AS-REP decryption.** MIT and
  Heimdal send PA-ETYPE-INFO2 only in `KDC_ERR_PREAUTH_REQUIRED`, not in
  the AS-REP. The client then derived the AS-REP key with an empty salt
  and failed with `Bad integrity: calculated hmac is different than
  provided`. The AS exchange now keeps the pre-authentication salt in the
  PA-DATA options, and the client falls back to it when the AS-REP has
  none.
  - **Accept an AS-REP enc-part tagged `EncTGSRepPart`.** The MIT KDC
  encodes the AS-REP enc-part with APPLICATION 26 for backwards
  compatibility, and the client failed with `Expected Application number
  tag 25 but got: 26`. It now accepts both tags.
  
  ### About the `EncTGSRepPart` fallback
  
  I know this fallback was removed during the review of #681 ("We should
  not expect `EncTgsRepPart` during AS exchange"). The MIT KDC however
  always sends it, so without the fallback no AS exchange with an MIT KDC
  can succeed:
  
  - MIT krb5,
  [`src/lib/krb5/asn.1/asn1_k_encode.c`](https://github.com/krb5/krb5/blob/master/src/lib/krb5/asn.1/asn1_k_encode.c):
  "For backwards compatibility, we encode both EncASRepPart and
  EncTGSRepPart with application tag 26. On decode, we accept either app
  tag". The encoder is `MAKE_ENCODER(encode_krb5_enc_kdc_rep_part,
  enc_tgs_rep_part)`, used for both reply types.
  - [RFC 4120 section
  5.4.2](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2): "Some
  implementations unconditionally send an encrypted EncTGSRepPart
  (application tag number 26) in this field regardless of whether the
  reply is a AS-REP or a TGS-REP. In the interest of compatibility,
  implementors MAY relax the check on the tag number of the decrypted
  ENC-PART."
  
  The fallback only applies after the enc-part decrypted with the AS-REP
  key usage, and the TGS path is unchanged.
  
  ## Review and validation
  
  - The test `KdcMock` gets two options reproducing each KDC behavior
  (`omit_as_rep_etype_info2`, `tgs_rep_enc_part_in_as_rep`), each covered
  by an end-to-end client/server authentication test. Without the fix,
  each test fails with the error quoted above.
  - Also verified against real MIT and Heimdal KDCs (LDAP SASL/GSSAPI
  binds).
  - `cargo test -q -p sspi -p kdc --features network_client,__test-data`
  - `cargo check -q -p sspi --all-targets --features
  network_client,dns_resolver,scard,__test-data` (`--all-features` also
  enables `tsssp`, which only builds on Windows)
  - `cargo clippy -q -p sspi -p kdc --features network_client,__test-data
  --lib --tests -- -D warnings -A unreachable-pub -A
  clippy::non-ascii-literal`
  - `cargo clippy --manifest-path ffi/Cargo.toml -- -D warnings -D
  clippy::print_stdout`
  - `cargo fmt --all -- --check`

- Complete AS-REP interoperability follow-ups ([#777](https://github.com/Devolutions/sspi-rs/issues/777)) ([e7ec8e45fd](https://github.com/Devolutions/sspi-rs/commit/e7ec8e45fdd83ef91cd1d90a381892a3557ef8fc)) 

  ## Summary
  
  Follow up on [#768](https://github.com/Devolutions/sspi-rs/pull/768),
  based on freshly fetched `origin/master` at
  `[[cf91195338f62a8b01ca5024e06f97c150e03225](https://github.com/Devolutions/sspi-rs/commit/cf91195338f62a8b01ca5024e06f97c150e03225)](https://github.com/Devolutions/sspi-rs/commit/[cf91195338f62a8b01ca5024e06f97c150e03225](https://github.com/Devolutions/sspi-rs/commit/cf91195338f62a8b01ca5024e06f97c150e03225))`, including that merged PR.
  
  - Carry the negotiated preauthentication salt out of the AS exchange for
  password changes and password-backed U2U acceptor TGT acquisition, using
  the same reply-salt selection helper as the direct/IAKerb client.
  - Distinguish an absent PA-ETYPE-INFO2 hint, an omitted salt field, and
  an explicitly empty salt. Retain the existing public extractor
  signatures.
  - Share authenticated AS-REP decryption between password/keytab and the
  actual PKINIT-facing PKU2U extractors, accepting application tags 25 and
  26 without weakening decryption or nonce handling.
  - Add 27 deterministic regressions, reusing the KDC mocks and
  direct/IAKerb flows. Fix the reported test-target Clippy findings and
  the RFC section-title capitalization.
  
  ## Salt semantics
  
  RFC 4120 section 4, “Encryption and Checksum Specifications”, defines
  the default salt as the realm followed by principal components without
  separators; section 5.2.7.5, “PA-ETYPE-INFO2”, defines the optional salt
  field.
  
  | Reply information | Salt used |
  | --- | --- |
  | PA-ETYPE-INFO2 absent | Salt used for preauthentication |
  | Entry present, salt field absent | Default from the reply client realm
  and principal components |
  | Salt explicitly empty | Empty salt, even when preauthentication used a
  different salt |
  | Salt explicitly nonempty | Reply-provided salt, taking precedence over
  preauthentication |
  
  The preauthentication path also distinguishes an absent hint from a
  present entry requesting the principal's default salt. Existing
  explicit-salt/tag-25 behavior and the IAKerb state machine are retained.
  
  ## Requirement coverage
  
  | Requirement | Deterministic evidence |
  | --- | --- |
  | Password-change salt fallback |
  `kerberos_change_password_uses_negotiated_salt_without_as_rep_hint`
  invokes the actual password-change consumer and decrypts/asserts the
  outgoing ticket, authenticator, and exact new-password bytes |
  | Password-backed U2U acceptor TGT acquisition |
  `kerberos_u2u_server_acquires_tgt_with_password_without_as_rep_hint`
  starts without a preinstalled ticket-decryption key, acquires the
  acceptor TGT, and completes authentication plus encrypted application
  traffic |
  | Combined missing reply hint and tag 26 |
  `kerberos_auth_without_as_rep_etype_info2_with_tgs_rep_enc_part_in_as_rep`
  |
  | The same combination through IAKerb |
  `iakerb_auth_without_as_rep_etype_info2_with_tgs_rep_enc_part_in_as_rep`,
  including cookies/transcript and encrypted application traffic |
  | Explicit-empty and custom reply salts override a different preauth
  salt | `kerberos_auth_with_explicit_empty_as_rep_salt`,
  `kerberos_auth_with_custom_as_rep_salt`,
  `extract_encryption_params_from_as_rep_with_salt_preserves_explicit_reply_salt`
  |
  | Omitted reply salt field uses the reply-principal default |
  `kerberos_auth_with_missing_as_rep_salt_field`,
  `extract_encryption_params_from_as_rep_with_salt_defaults_missing_reply_salt_field`
  assert case-preserving, separator-free realm/multicomponent-principal
  concatenation |
  | Missing versus empty preauth salt |
  `extract_preauth_salt_distinguishes_absent_default_empty_and_custom`,
  `kerberos_auth_with_missing_preauth_salt_field`,
  `kerberos_auth_with_explicit_empty_preauth_salt` |
  | Password/keytab and shared decoder tag compatibility |
  `kerberos_password_extractor_returns_expected_session_key_for_both_application_tags`,
  `kerberos_derived_key_extractor_returns_expected_session_key_for_both_application_tags`,
  `decrypt_as_rep_preserves_fields_for_both_application_tags` |
  | Actual PKINIT-facing key-only and key+nonce decoding |
  `pku2u_public_key_extractor_returns_expected_session_key_for_both_application_tags`,
  `pku2u_key_and_nonce_extractor_preserves_nonce_boundaries` |
  | Invalid tags, wrong keys, tampering, and nonce overflow still fail |
  `kerberos_session_key_extractors_reject_unsupported_application_tag`,
  `pku2u_session_key_extractors_reject_unsupported_application_tag`,
  `kerberos_session_key_extractors_reject_wrong_key_and_tampered_ciphertext`,
  `pku2u_session_key_extractors_reject_wrong_key_and_tampered_ciphertext`,
  `pku2u_nonce_extractor_rejects_nonce_above_u32_max` |
  | Public compatibility wrappers and malformed metadata |
  `extract_salt_from_krb_error_preserves_legacy_optional_string_contract`,
  `extract_encryption_params_from_as_rep_preserves_one_argument_api`,
  `salt_extractors_reject_invalid_challenges`,
  `reply_encryption_params_reject_malformed_or_missing_values` |
  | Cleanup | RFC title is `KRB_KDC_REP definition`; checked IAKerb
  `usize::try_from` conversion and structured trace logging in the common
  test helper; strict Clippy passes |
  
  ## Validation
  
  Local Windows validation with VsDevShell initialized in each build
  process; `AWS_LC_SYS_NO_ASM=true`, `CMAKE_GENERATOR=Ninja`, and
  `SSPI_RS_IS_RUNNING_TESTS=true` for tests:
  
  - `cargo test --locked -q -p sspi --lib --features
  network_client,dns_resolver,scard,tsssp,__test-data`: **307 passed, 0
  failed**.
  - `cargo test --locked -q -p sspi --test sspi --features
  network_client,dns_resolver,scard,tsssp,__test-data
  client_server::kerberos:: -- --test-threads=1`: **22 passed, 0 failed**.
  - Scoped extractor runs: **16 Kerberos tests** and **7 PKU2U tests**
  passed. The affected password-change and U2U tests were also rerun after
  the final Clippy cleanup.
  - `cargo clippy --locked -q -p sspi --lib --test sspi --features
  network_client,dns_resolver,scard,tsssp,__test-data -- -D warnings -D
  clippy::print_stdout`: passed.
  - `cargo check --locked -q -p sspi --no-default-features`: passed.
  - `cargo fmt --all -- --check` and `git diff --check`: passed; style
  review passed.
  - Standalone `tools/wasm-testcompile` fresh dependency resolution
  selected **picky-krb 0.13.0**; both `cargo check` and `cargo build` with
  `--locked --target wasm32-unknown-unknown` passed. The full `check.ps1`
  import scan was not run (`wasm2wat` is unavailable).
  
  Formatting emits the existing stable-rustfmt warnings for nightly-only
  options. Cargo emits nonfatal incremental-cache access-denied notes;
  WASM compilation also emits the existing `encode_digest` dead-code
  warning.
  
  ## Investigated without changes
  
  - **WASM dependency failure:** current master already requires
  `picky-krb = "0.13"` (raised in #772), which excludes the older 0.12.4
  release lacking `InvalidMechanismOid`. Fresh resolution and an actual
  standalone wasm32 build succeeded. No additional pin, lockfile change,
  or external workspace dependency is warranted.
  - **Dependency-fetch hang:** the reported historical macOS winscard
  timeout remains an infrastructure symptom, not a reproduced source
  failure. The historical failed-run jobs API returned HTTP 502, so its
  detailed logs could not be revalidated here. The later run
  [39320794389](https://github.com/Devolutions/sspi-rs/actions/runs/39320794389)
  has successful WASM and Windows/macOS/Linux winscard jobs; the
  RustCrypto/KDFs dependency is already revision-locked. No speculative
  timeout/retry infrastructure or dependency update was added.
  
  No live Windows/MIT/Heimdal KDC validation was performed. Explicit-empty
  reply salt is a theoretical deterministic case, not a claimed real-world
  reproduction. Password-change coverage verifies the encrypted outgoing
  request, not a completed password update on a KDC.

- Decode PKU2U AuthPack as Diffie-Hellman ([#786](https://github.com/Devolutions/sspi-rs/issues/786)) ([f740f00451](https://github.com/Devolutions/sspi-rs/commit/f740f004515f6c96f831a6056aab236233f63927)) 

  Use the Diffie-Hellman AuthPack alias introduced by picky-krb 0.13.1 so
  fresh dependency resolutions compile.
  Raise the minimum version to keep the decoder type available.



## [[0.23.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.22.1...sspi-v0.23.0)] - 2026-10-01

### <!-- 1 -->Features

- [**breaking**] Upgrade `winscard` to 0.4, so the public `From<winscard::Error> for sspi::Error` conversion now uses the `winscard` 0.4 error type ([#755](https://github.com/Devolutions/sspi-rs/issues/755)) ([37ebbb8dcd](https://github.com/Devolutions/sspi-rs/commit/37ebbb8dcd07de8bdbacf2662508683213d6590c))

### <!-- 4 -->Bug Fixes

- Encode the Kerberos KDC-REQ nonce as a minimal DER positive 32-bit integer, fixing intermittent `KRB_AP_ERR_MODIFIED` failures from Windows KDCs ([#759](https://github.com/Devolutions/sspi-rs/issues/759)) ([c724a94076](https://github.com/Devolutions/sspi-rs/commit/c724a940763a115f4458195663aba69c49c20b4f))
- Accept AP-REP sequence numbers of any valid DER length, fixing intermittent mutual authentication failures against Windows acceptors ([#759](https://github.com/Devolutions/sspi-rs/issues/759)) ([c724a94076](https://github.com/Devolutions/sspi-rs/commit/c724a940763a115f4458195663aba69c49c20b4f))



## [[0.22.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.22.0...sspi-v0.22.1)] - 2026-09-29

### <!-- 4 -->Bug Fixes

- Preserve the NTLM RC4 sealing state across MIC generation and verification ([#753](https://github.com/Devolutions/sspi-rs/issues/753)) ([5b2b137e13](https://github.com/Devolutions/sspi-rs/commit/5b2b137e13b6839790049727bdb742e967cb1248))

  Generating or verifying a MIC no longer resets the NTLM RC4 sealing
  handles, so a message sealed right after a MIC keeps the correct state.
  CredSSP relies on this: it wraps `pubKeyAuth` after the initiator sends
  its `mechListMIC` but before it verifies the acceptor's MIC, and the
  previous reset dropped the advanced send state, corrupting the next
  wrapped message. Sequence numbers are unchanged.

- Recover from KDC clock skew during the Kerberos AS exchange ([#757](https://github.com/Devolutions/sspi-rs/issues/757)) ([24c9c52352](https://github.com/Devolutions/sspi-rs/commit/24c9c5235204174e8d64b685c7633794a07fcc68))

  When a KDC rejects encrypted AS pre-authentication with
  `KRB_AP_ERR_SKEW`, the client derives the KDC time offset from the
  error's `stime`/`susec` and retries once; a second skew error or any
  other error is returned as before. The offset is applied to password,
  keytab, and smart-card pre-authentication timestamps, and to subsequent
  TGS, AP, and password-change authenticators, so Kerberos logon succeeds
  when the local clock differs from the KDC's.

## [[0.22.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.21.3...sspi-v0.22.0)] - 2026-09-15

### <!-- 1 -->Features

- Add PKU2U acceptor support with configurable additional credentials and trusted client and server certificates ([#733](https://github.com/Devolutions/sspi-rs/issues/733)) ([03ee8d0128](https://github.com/Devolutions/sspi-rs/commit/03ee8d012835d9d46f69a181e3b199427c7b0856))

- Expose `Pku2uCredential` and `Pku2uPrivateKey` for PKU2U authentication configuration ([#733](https://github.com/Devolutions/sspi-rs/issues/733)) ([03ee8d0128](https://github.com/Devolutions/sspi-rs/commit/03ee8d012835d9d46f69a181e3b199427c7b0856))

### <!-- 2 -->Improvements

- [**breaking**] Make `credssp::ts_request::TsRequest::buffer_len()` return `Result<u16>` ([#721](https://github.com/Devolutions/sspi-rs/issues/721)) ([a9dfaec9b0](https://github.com/Devolutions/sspi-rs/commit/a9dfaec9b04ce06a487f6091890f9a1baf620005))

- [**breaking**] Change `kerberos::MAX_SIGNATURE` and `kerberos::SECURITY_TRAILER` to `u8` ([#721](https://github.com/Devolutions/sspi-rs/issues/721)) ([a9dfaec9b0](https://github.com/Devolutions/sspi-rs/commit/a9dfaec9b04ce06a487f6091890f9a1baf620005))

### <!-- 4 -->Bug Fixes

- Preserve peer sequence numbers during Kerberos AP-REP and MIC validation ([#717](https://github.com/Devolutions/sspi-rs/issues/717)) ([6d177082ed](https://github.com/Devolutions/sspi-rs/commit/6d177082edba57563f8be310ca4776673b247d82))

- Accept `@` in down-level account names ([#719](https://github.com/Devolutions/sspi-rs/issues/719)) ([4878c50503](https://github.com/Devolutions/sspi-rs/commit/4878c50503b204bba95def66ca7d45e6d396f898))

- Map `ClientRequestFlags::EXTENDED_ERROR` and `ClientRequestFlags::IDENTIFY` to Kerberos GSS request flags ([#736](https://github.com/Devolutions/sspi-rs/issues/736)) ([0fb18798dd](https://github.com/Devolutions/sspi-rs/commit/0fb18798ddc40c487e0503631b93879c975af398))

- Generate and validate Kerberos MICs using the negotiated AES key size ([#737](https://github.com/Devolutions/sspi-rs/issues/737)) ([7a3de33074](https://github.com/Devolutions/sspi-rs/commit/7a3de330748fd9f8848507765ec2824be5c56f40))

### <!-- 7 -->Build

- [**breaking**] Raise the minimum supported Rust version to 1.93 ([#715](https://github.com/Devolutions/sspi-rs/issues/715)) ([5f85f13a15](https://github.com/Devolutions/sspi-rs/commit/5f85f13a15255cab1185801b64b0437fd9605a3f))



## [[0.21.3](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.21.2...sspi-v0.21.3)] - 2026-07-16

### <!-- 1 -->Features

- Add format-tagged Username::parts view ([#709](https://github.com/Devolutions/sspi-rs/issues/709)) ([80492e4c61](https://github.com/Devolutions/sspi-rs/commit/80492e4c616f7e475391d9b877759b463733fe82)) 

  Add `UsernameParts`, a format-tagged, borrowed view into a `Username`,
  and `Username::parts()` returning it. Each variant only exposes the
  fields that are meaningful for its user name format, so a UPN suffix can
  no longer be mistaken for a NetBIOS domain: the `UserPrincipalName` arm
  has a `suffix` (and the full `upn`) but no "domain" field, while
  `DownLevelLogonName` carries an `Option<netbios_domain>` that models
  accurately the no-separator case. Matching is exhaustive over the two
  Microsoft user name formats.

## [[0.21.2](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.21.1...sspi-v0.21.2)] - 2026-07-15

### <!-- 4 -->Bug Fixes

- Classify UPN keytab principals as NT_ENTERPRISE ([#475](https://github.com/Devolutions/sspi-rs/issues/475)) ([491cf36fea](https://github.com/Devolutions/sspi-rs/commit/491cf36feafb01dac9490842d2472acc3602ffcb)) 

  The keytab credentials branch passed keytab.principal.account_name() to
  get_client_principal_name_type, which strips the @suffix of a UPN. Without
  the @, the principal was misclassified as NT_PRINCIPAL instead of
  NT_ENTERPRISE (MS-KILE 3.3.5.6.1).

- Avoid panic on short SRV record RDATA on macOS ([#706](https://github.com/Devolutions/sspi-rs/issues/706)) ([a4ab1bbf0c](https://github.com/Devolutions/sspi-rs/commit/a4ab1bbf0c1c214e921a3189264885c7c278e909))

## [[0.21.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.21.0...sspi-v0.21.1)] - 2026-06-26

### <!-- 1 -->Features

- Add support for SECPKG_ATTR_NAMES ([#676](https://github.com/Devolutions/sspi-rs/issues/676)) ([be6315d475](https://github.com/Devolutions/sspi-rs/commit/be6315d475d7c4ce4c571220e2cfd7cb0881b7c7)) 

- Add keytab client credentials and standards-compliant SASL/GSSAPI acceptor support ([#681](https://github.com/Devolutions/sspi-rs/issues/681)) ([d95f249622](https://github.com/Devolutions/sspi-rs/commit/d95f2496226d45fd4d02437c0c84afe870d9f510)) 

  Extends the `sspi` Kerberos implementation to interoperate with standards-compliant SASL/GSSAPI (RFC 4752 / RFC 4121) peers by adding keytab-backed client credentials, supporting integrity-only (unsealed) `GSS_Wrap` tokens, and allowing acceptors to validate tickets for multiple configured service principals.

- Support for Kerberos cross realm referral ([#694](https://github.com/Devolutions/sspi-rs/issues/694)) ([797365417f](https://github.com/Devolutions/sspi-rs/commit/797365417f6f75ee175eb0f8eb01d0c0b907d01f)) 

### <!-- 4 -->Bug Fixes

- Ntlm: NTLM_SSP_NEGOTIATE_KEY_EXCH flag usage ([#670](https://github.com/Devolutions/sspi-rs/issues/670)) ([a26a3692b0](https://github.com/Devolutions/sspi-rs/commit/a26a3692b029c5617f75a6dc618e5c7f78d3bc1b)) 

- Package list handling ([#677](https://github.com/Devolutions/sspi-rs/issues/677)) ([ee75161bcd](https://github.com/Devolutions/sspi-rs/commit/ee75161bcdce0998b9173701129c0c7d607e1f17)) 

- Disable `mechListMIC` for NTLM guest logon in negotiate module ([#680](https://github.com/Devolutions/sspi-rs/issues/680)) ([80bdedf387](https://github.com/Devolutions/sspi-rs/commit/80bdedf387da7341b95ff947d3bf68f48a0bc404)) 

- Read channel bindings on the client authenticate step ([#695](https://github.com/Devolutions/sspi-rs/issues/695)) ([82741f6630](https://github.com/Devolutions/sspi-rs/commit/82741f6630c9b6038064caf8f508ac50e9f59738)) 

### <!-- 7 -->Build

- Advance RustCrypto pins to the current rc.18/rc.33/rc.10 cluster ([#692](https://github.com/Devolutions/sspi-rs/issues/692)) ([095e3f341c](https://github.com/Devolutions/sspi-rs/commit/095e3f341c74d57daafb015bfb0226188e9e8e18)) 

- Update RC and crypto dependencies to latest versions ([#699](https://github.com/Devolutions/sspi-rs/issues/699)) ([c5922db0f4](https://github.com/Devolutions/sspi-rs/commit/c5922db0f4921323856a041c5e2987e569e62056)) 

## [[0.21.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.20.1...sspi-v0.21.0)] - 2026-05-06

### <!-- 4 -->Bug Fixes

- [**breaking**] Remove redundant PKCS#1 padding when signing hashes ([#660](https://github.com/Devolutions/sspi-rs/issues/660)) ([9e8a108f02](https://github.com/Devolutions/sspi-rs/commit/9e8a108f02704fdbcab23d0fadb2c0d3f5514c0e)) 



## [[0.20.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.20.0...sspi-v0.20.1)] - 2026-04-29

### <!-- 7 -->Build

- Upgrade picky and RustCrypto dependencies ([#655](https://github.com/Devolutions/sspi-rs/issues/655)) ([26765bbe1f](https://github.com/Devolutions/sspi-rs/commit/26765bbe1f57f490ba1c37703eda8267c3b2dfb6)) 



## [[0.20.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.19.2...sspi-v0.20.0)] - 2026-04-27

### <!-- 4 -->Bug Fixes

- [**breaking**] Remove legacy UTF-16 helpers ([#648](https://github.com/Devolutions/sspi-rs/issues/648)) ([b8f21e1bf3](https://github.com/Devolutions/sspi-rs/commit/b8f21e1bf33eea2f66a1818c3c190bca5be6e568)) 

- Add KDC connect timeout to prevent 75s hang on unreachable KDC ([#647](https://github.com/Devolutions/sspi-rs/issues/647)) ([abb9ffe16d](https://github.com/Devolutions/sspi-rs/commit/abb9ffe16d86941290466c7a53b56d1f0b738f18)) 


## [[0.19.2](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.19.1...sspi-v0.19.2)] - 2026-03-26

### <!-- 4 -->Bug Fixes

- Fall back to NTLM when the target SPN is an IP address ([#637](https://github.com/Devolutions/sspi-rs/issues/637)) ([67dbac66cc](https://github.com/Devolutions/sspi-rs/commit/67dbac66cc98cb4fcec9864f345290e52745122e)) 

## [[0.19.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.19.0...sspi-v0.19.1)] - 2026-03-23

### <!-- 4 -->Bug Fixes

- Improve NTLM fallback ([#627](https://github.com/Devolutions/sspi-rs/issues/627)) ([88bb31796c](https://github.com/Devolutions/sspi-rs/commit/88bb31796c9bfb0d248b6e32eedbd166d8603679)) 

  Improved SPNEGO/Negotiate authentication resilience by introducing
  an explicit Kerberos-first attempt with a controlled fallback to NTLM for
  a defined set of Kerberos failure conditions (per the referenced FreeRDP
  behavior), and updates the Kerberos/SPNEGO token flow to support
  that behavior reliably.

- Handle ISC_REQ_USE_DCE_STYLE and SECBUFFER_READONLY in EncryptMessage ([#629](https://github.com/Devolutions/sspi-rs/issues/629)) ([93e962be78](https://github.com/Devolutions/sspi-rs/commit/93e962be78d6b43bf41e9e30d4935903786602c7)) 

  Adjusts the NTLM SSPI implementation to better interoperate with RPC/FreeRDP over RD Gateway by (a) treating `ISC_REQ_USE_DCE_STYLE` as implying sealing/signing, and (b) allowing `EncryptMessage` to operate in sign-only mode when all `SECBUFFER_DATA` buffers are marked `SECBUFFER_READONLY`.

## [[0.19.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.9...sspi-v0.19.0)] - 2026-03-13

### <!-- 1 -->Features

- [**breaking**] Introduce UTF-16 strings helpers and refactor auth identity types ([#606](https://github.com/Devolutions/sspi-rs/issues/606)) ([1bfee5e545](https://github.com/Devolutions/sspi-rs/commit/1bfee5e545c4a97ae631fe734b3bcf45b4b486f9)) 

## [[0.18.9](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.8...sspi-v0.18.9)] - 2026-03-06

### <!-- 1 -->Features

- Support multiple credential candidates ([#611](https://github.com/Devolutions/sspi-rs/issues/611)) ([2ded76b767](https://github.com/Devolutions/sspi-rs/commit/2ded76b76734110d45de2270d3c782c561fe54d1)) 

  Enable the CredSSP server-side NTLM flow to authenticate against a bounded set of
  concurrently-valid credential candidates for a single user, selecting the one
  the client proves knowledge of.

### <!-- 4 -->Bug Fixes

- Include full error source chain in reqwest client build error ([#621](https://github.com/Devolutions/sspi-rs/issues/621)) ([3ba4886776](https://github.com/Devolutions/sspi-rs/commit/3ba4886776600f06b1a338b06ed4f828bd001588)) 

- Remove NTLM password length heuristic ([#619](https://github.com/Devolutions/sspi-rs/issues/619)) ([c607a229da](https://github.com/Devolutions/sspi-rs/commit/c607a229da8f5fd394f4be4c26fe7e5b90805df7)) 

  `compute_ntlm_v2_hash` treats passwords longer than 512 bytes as
  pre-computed NT hashes and tries to decode them with
  `convert_password_hash`. This silently breaks authentication for any
  plaintext password that exceeds that threshold (e.g. long JWT tokens).

## [[0.18.8](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.7...sspi-v0.18.8)] - 2026-02-26

### <!-- 1 -->Features

- Improve domain->realm mapping in kerberos backend ([#604](https://github.com/Devolutions/sspi-rs/issues/604)) ([50cff70f0e](https://github.com/Devolutions/sspi-rs/commit/50cff70f0e64df4630320883f3846872a68d7e27)) 

### <!-- 4 -->Bug Fixes

- Correct Negotiate (SPNEGO) implementation ([#600](https://github.com/Devolutions/sspi-rs/issues/600)) ([c016e18863](https://github.com/Devolutions/sspi-rs/commit/c016e188633b202c1de7fd84ae1f4f7253fe5dd2)) 

### <!-- 7 -->Build

- Update dependencies

## [[0.18.7](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.6...sspi-v0.18.7)] - 2026-01-16

### <!-- 1 -->Features

- NT Hash Authentication ([#585](https://github.com/Devolutions/sspi-rs/issues/585)) ([21b45e16dc](https://github.com/Devolutions/sspi-rs/commit/21b45e16dcee7171cd9ae70df37cee8cdf41df0e)) 

  Adds support for NT hash (pass-the-hash) authentication,
  allowing authentication using pre-computed NT hashes instead of
  plaintext passwords.

## [[0.18.6](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.5...sspi-v0.18.6)] - 2026-01-05

### <!-- 4 -->Bug Fixes

- Accept variable-length MsvAvSingleHost AvPair ([#580](https://github.com/Devolutions/sspi-rs/issues/580)) ([28f8d74b8c](https://github.com/Devolutions/sspi-rs/commit/28f8d74b8c4f982e047f0bc7738498ac217f6553)) 

  Windows 11 Build 26200+ sends an 80-byte MsvAvSingleHost structure
  instead of the traditional 48 bytes. Per MS-NLMP specification, fields
  after MachineID MUST be ignored on receipt.
  
  This change:
  - Changes SingleHost from fixed [u8; 48] to Vec<u8>
  - Relaxes validation from == 48 to >= 48 bytes
  - Preserves full data for round-trip serialization
  
  Fixes RDP credential injection failures when clients use Windows 11
  Build 26200 or later.

## [[0.18.5](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.4...sspi-v0.18.5)] - 2025-12-11

### <!-- 4 -->Bug Fixes

- Don't use eprintln on unknown packages ([#558](https://github.com/Devolutions/sspi-rs/issues/558)) ([df6181291c](https://github.com/Devolutions/sspi-rs/commit/df6181291ccf6f9fb2a0a59151b43676663b2d74)) 

- Use `String::from_utf16_lossy` over `String::from_utf16` to avoid changing the meaning of some buffers in case of invalid UTF-16 input ([#568](https://github.com/Devolutions/sspi-rs/issues/568)) ([a4889f5b1e](https://github.com/Devolutions/sspi-rs/commit/a4889f5b1e802395b09954f5846d1a6433546281)) 

### <!-- 7 -->Build

- Update dependencies

## [[0.18.4](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.3...sspi-v0.18.4)] - 2025-11-18

### <!-- 7 -->Build

- Exclude cryptoki for WASM ([#545](https://github.com/Devolutions/sspi-rs/issues/545)) ([9e4a84a9ee](https://github.com/Devolutions/sspi-rs/commit/9e4a84a9ee07c81da07e799e3e209094c9045c83)) 

  This fixes builds for the wasm32 target.

## [[0.18.3](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.2...sspi-v0.18.3)] - 2025-11-07

### <!-- 1 -->Features

- Add `NT_ENTERPRISE` support in server-side Kerberos ([#535](https://github.com/Devolutions/sspi-rs/issues/535)) ([40785e3123](https://github.com/Devolutions/sspi-rs/commit/40785e3123e381180ac9a75e99248a0287fc5d71)) 

  This is needed when want to connect using FQDN instead of down-level logon name.

### <!-- 3 -->Revert

- Implement `Default` for `SmartCardType` ([#534](https://github.com/Devolutions/sspi-rs/issues/534)) ([7280f7a67b](https://github.com/Devolutions/sspi-rs/commit/7280f7a67b100719052ade72333d373bf956541f)) 

  It actually does not make sense to implement Default for SmartCardType.
  A user-provided PIN must be set.
  
  Release 0.18.2 was yanked.

### <!-- 4 -->Bug Fixes

- TLS 1.3 support in TSSSP module ([#536](https://github.com/Devolutions/sspi-rs/issues/536)) ([0605cf01f8](https://github.com/Devolutions/sspi-rs/commit/0605cf01f861aca8191e3134fb885bde5eb50506)) 

  * Adds `CipherSuite::TLS13_AES_256_GCM_SHA384` support.
  * Fixes TLS packet header validation: TLS 1.3 uses TLS 1.2 version in the packet header.

- Pin leftover pre-release crypto crates ([#538](https://github.com/Devolutions/sspi-rs/issues/538)) ([6fc91fa977](https://github.com/Devolutions/sspi-rs/commit/6fc91fa977d217b04cdce23e66d56a8a398988e3)) 

  The patch version upgrade is not allowed to bring breaking changes, but
  this rule doesn't work for an `rc` version. So we should pin the `rc`
  versions, to not allow _cargo_ update to a new `rc` automatically.

## [[0.18.2](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.1...sspi-v0.18.2)] - 2025-11-04 (Yanked)

### <!-- 1 -->Features

- Implement `Default` for `SmartCardType` ([#532](https://github.com/Devolutions/sspi-rs/issues/532)) ([3555b377e8](https://github.com/Devolutions/sspi-rs/commit/3555b377e8aeb5a8c376b2ecec9dcb1a2fd79560)) 

## [[0.18.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.18.0...sspi-v0.18.1)] - 2025-10-29

### <!-- 7 -->Build

- Bump hickory-resolver from 0.24.4 to 0.25.2 ([#426](https://github.com/Devolutions/sspi-rs/issues/426)) ([59857e66c2](https://github.com/Devolutions/sspi-rs/commit/59857e66c29e9130af2d24e3c7d79858ce1b55cd)) 

## [[0.18.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.17.0...sspi-v0.18.0)] - 2025-10-14

### <!-- 4 -->Bug Fixes

- DH client default parameters: remove leading zero ([#514](https://github.com/Devolutions/sspi-rs/issues/514)) ([8114b570bc](https://github.com/Devolutions/sspi-rs/commit/8114b570bcfa4320b4972c300705a5e93e762965)) 

- [**breaking**] Async network client returns `!Send` future ([#513](https://github.com/Devolutions/sspi-rs/issues/513)) ([218ddf3e79](https://github.com/Devolutions/sspi-rs/commit/218ddf3e792580caf1f094ff197a3790f61248e5)) 

### <!-- 7 -->Build

- Bump picky to the latest version ([#516](https://github.com/Devolutions/sspi-rs/issues/516)) ([972e04b153](https://github.com/Devolutions/sspi-rs/commit/972e04b15393acf2028ae7fde0f55d104e8a9294)) 

- Bump the patch group across 1 directory with 2 updates ([#519](https://github.com/Devolutions/sspi-rs/issues/519)) ([aaa6e78617](https://github.com/Devolutions/sspi-rs/commit/aaa6e78617b17ee0870c3044f2ac6922c6831017)) 

## [[0.17.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.16.1...sspi-v0.17.0)] - 2025-10-06

### <!-- 1 -->Features

- Data sigining using scard (#491) ([6728fb525c](https://github.com/Devolutions/sspi-rs/commit/6728fb525cedc96b395eed5dc4a8ea357b036b36)) 

### <!-- 4 -->Bug Fixes

- [**breaking**] Move `cert_utils` from `sspi` crate to `ffi` (#507) ([c9337c8f64](https://github.com/Devolutions/sspi-rs/commit/c9337c8f64a6236396242275847989a35db735ac)) 

- [**breaking**] Fix lifetimes in initialize_security_context_impl (#495) ([370951c1b0](https://github.com/Devolutions/sspi-rs/commit/370951c1b017bfef4276185b374345e8b6b1e532)) 

### <!-- 7 -->Build

- Bump the windows crates

- Bump the crypto dependencies (#489) ([1ecba764ec](https://github.com/Devolutions/sspi-rs/commit/1ecba764ec3b04e147ae76d018414afa8bec5f88)) 

## [[0.16.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.16.0...sspi-v0.16.1)] - 2025-08-19

### <!-- 1 -->Features

- Add method to set the channel bindings for a session (#479) ([0c0e225fe7](https://github.com/Devolutions/sspi-rs/commit/0c0e225fe7d7ddffc18ad0176deba207edaf3524)) 

  Setting and sending the CBs is described in Sec. 3.1.5.2.1 of the NTLM spec, admittedly in a slightly confusing way, which may seem to suggest that the bindings are somehow part of the CHALLENGE message, but they are not: knowledge of CBs is strictly local to the client, therefore the client should send them in AUTHENTICATE.

## [[0.16.0](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.14...sspi-v0.16.0)] - 2025-07-07

### <!-- 1 -->Features

- Server-side Kerberos implementation (#440) ([943a297edd](https://github.com/Devolutions/sspi-rs/commit/943a297eddad91bf6dfa02bdb53b422453df0ed9)) 

### <!-- 4 -->Bug Fixes

- Server-side Kerberos fixes (#457) ([27ce28dad5](https://github.com/Devolutions/sspi-rs/commit/27ce28dad5aa490d094b4ea1db5a315ea1478264)) 

- Kerberos server MIC token generation and validation (#464) ([12fbd706a8](https://github.com/Devolutions/sspi-rs/commit/12fbd706a8e807b4e4ea9b6bb39f4bace60afd9a)) 

- Kerberos server WRAP token generation and validation (#463) ([4bbe4071c8](https://github.com/Devolutions/sspi-rs/commit/4bbe4071c80172ee2c85552ef1060a65394a45c0)) 

## [[0.15.14](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.13...sspi-v0.15.14)] - 2025-07-01

### <!-- 7 -->Build

- Update picky-krb to 0.11 (#460) ([5157bee02b](https://github.com/Devolutions/sspi-rs/commit/5157bee02b0383571c726801bda15f0dd9dc7934)) 



## [[0.15.13](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.12...sspi-v0.15.13)] - 2025-06-23

### <!-- 7 -->Build

- Bump windows-sys from 0.59.0 to 0.60.2 in the windows group across 1 directory (#455) ([5744c8b4b3](https://github.com/Devolutions/sspi-rs/commit/5744c8b4b3aa5a47a2a25e9375434333de769002)) 

## [[0.15.12](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.11...sspi-v0.15.12)] - 2025-06-20

### <!-- 4 -->Bug Fixes

- Invalid Kerberos token DER encoding (#453) ([0ec3e687dd](https://github.com/Devolutions/sspi-rs/commit/0ec3e687dd28ff95910c79b4781d538cbffb9a80)) 

  The default behavior of serializing a KrbMessage<T> was accidentally changed.

## [[0.15.11](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.10...sspi-v0.15.11)] - 2025-06-11

### <!-- 4 -->Bug Fixes

- Negotiate attempts KDC detection even when Kerberos is disabled (#447) ([c56132c3f8](https://github.com/Devolutions/sspi-rs/commit/c56132c3f8d3b7e957e64577109158511ee3f4b8)) 

## [[0.15.10](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.9...sspi-v0.15.10)] - 2025-06-10

### <!-- 7 -->Build

- Update picky-krb to 0.10 (#448) ([b8b983d7ae](https://github.com/Devolutions/sspi-rs/commit/b8b983d7aecb8e1c84037d157c2b932668e069b1)) 

## [[0.15.9](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.8...sspi-v0.15.9)] - 2025-06-05

### <!-- 7 -->Build

- Bump windows-registry from 0.4.0 to 0.5.2 in the windows group across 1 directory (#444) ([9a349f7bdc](https://github.com/Devolutions/sspi-rs/commit/9a349f7bdcfe33658af27420af3dd38a88d773ab)) 

## [[0.15.8](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.7...sspi-v0.15.8)] - 2025-06-05

### Build

- Migrate from `winreg` to `windows-registry` crate (#441) ([8631235c8a](https://github.com/Devolutions/sspi-rs/commit/8631235c8a3f93e6f4573142101a25210adb49a5)) 



## [[0.15.7](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.6...sspi-v0.15.7)] - 2025-05-29

### <!-- 4 -->Bug Fixes

- Do not log at info-level return values (#438) ([68d02e410d](https://github.com/Devolutions/sspi-rs/commit/68d02e410dadf0278ed2a109117c71c43920ea4f)) 

## [[0.15.6](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.5...sspi-v0.15.6)] - 2025-05-27

### <!-- 4 -->Bug Fixes

- Lower info-level logs to debug-level (#436) ([665cb1e1dc](https://github.com/Devolutions/sspi-rs/commit/665cb1e1dc148683779e65f66d1408ddaa911bea)) 

## [[0.15.5](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.4...sspi-v0.15.5)] - 2025-04-25

### <!-- 1 -->Features

- Add `query_context_session_key` (#417) ([862657a57c](https://github.com/Devolutions/sspi-rs/commit/862657a57c781e348ef5ccafe540511b19148b44)) 

  This addition is an implementation for the SSP API
  `QueryContextAttributesEx(SECPKG_ATTR_SESSION_KEY)`. It is required for
  protocols such as SMB, and adding it to the `Sspi` trait, enables access
  to it across all the SSP packages implemented.
  
  This adds the option for using Kerberos and Negotiate session keys.

## [[0.15.4](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.3...sspi-v0.15.4)] - 2025-03-24

### <!-- 7 -->Build

- Update dependencies

## [[0.15.3](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.2...sspi-v0.15.3)] - 2025-03-12

### <!-- 4 -->Bug Fixes

- Set correct seq number in MIC token (#390) ([69f03c2933](https://github.com/Devolutions/sspi-rs/commit/69f03c2933c1da106b64a565a757666cd4d94bde)) 

  Fixes Kerberos LDAP auth.
  The problem was in the invalid sequence number in MIC token.

- NTLM RPC auth (#395) ([34d896c9ce](https://github.com/Devolutions/sspi-rs/commit/34d896c9cee7e0b3e0d5ee3c5002c781d9fc8fbf)) 

## [[0.15.2](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.1...sspi-v0.15.2)] - 2025-02-27

### <!-- 1 -->Features

- Support `SECBUFFER_READONLY_WITH_CHECKSUM` flag (#357) ([397fd9502d](https://github.com/Devolutions/sspi-rs/commit/397fd9502dc315e4e8e7c4700b6e789c5e7b44c3)) 

- Add `USE_DCE_STYLE` flag support (#358) ([0f78bccaea](https://github.com/Devolutions/sspi-rs/commit/0f78bccaea7ac5620f83de68d3559f212262c789)) 

### <!-- 4 -->Bug Fixes

- Kerberos authentication and encryption for RPC and RDP (#372) ([442dfc1382](https://github.com/Devolutions/sspi-rs/commit/442dfc1382033f6f81bb4cd021cca7318cce224e)) 

## [[0.15.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.0...sspi-v0.15.1)] - 2025-02-04

### <!-- 1 -->Features

- Add `make_signature` and `verify_signature` to `Sspi` trait (#343) ([040188a34d](https://github.com/Devolutions/sspi-rs/commit/040188a34d5d7b8607825b25a4eb78c25c6b57cc)) 

### <!-- 4 -->Bug Fixes

- Store session key when using server-side NTLM implementation (#354) ([41d1ca7fed](https://github.com/Devolutions/sspi-rs/commit/41d1ca7fed623759dcc9ff6f28c7558ecfa6fcbd)) 
