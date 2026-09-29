# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.1.1](https://github.com/Devolutions/sspi-rs/compare/kdc-v0.1.0...kdc-v0.1.1)] - 2026-09-29

### <!-- 4 -->Bug Fixes

- Recover from KDC clock skew during AS exchange ([#757](https://github.com/Devolutions/sspi-rs/issues/757)) ([24c9c52352](https://github.com/Devolutions/sspi-rs/commit/24c9c5235204174e8d64b685c7633794a07fcc68)) 

  - When a KDC rejects encrypted AS pre-authentication with
  `KRB_AP_ERR_SKEW`, derive a per-context time offset from the error's
  `stime`/`susec` and retry once. Propagate a second skew error or any
  other error without additional retries.
  - Apply the offset to password, keytab, and smart-card
  pre-authentication timestamps and to subsequent TGS, AP, and
  password-change authenticators. Existing public generator calls still
  use local time unless invoked through the corrected client context.
  - Fix the built-in KDC's skew check so timestamps slightly ahead of
  **or** behind its clock are accepted within `max_time_skew`.



## [[0.1.0](https://github.com/Devolutions/sspi-rs/releases/tag/kdc-v0.1.0)] - 2025-12-11

### <!-- 1 -->Features

- Add initial KDC implementation ([#541](https://github.com/Devolutions/sspi-rs/issues/541)) ([10ed474fe5](https://github.com/Devolutions/sspi-rs/commit/10ed474fe577583095305dd9ef0d5172321a643f)) 

