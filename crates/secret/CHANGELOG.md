# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.2.0](https://github.com/Devolutions/sspi-rs/compare/secret-v0.1.0...secret-v0.2.0)] - 2026-11-10

### <!-- 1 -->Features

- [**breaking**] Make `DEBUG` logging safe in production ([#792](https://github.com/Devolutions/sspi-rs/issues/792)) ([2f447436fe](https://github.com/Devolutions/sspi-rs/commit/2f447436fe6ff696aab9284bd18ab5f6410de5c1)) 

  Hi,
  
  I made it safe to enable the `DEBUG` log level in production. Logging at
  the `DEBUG` log level doesn't leak secrets, private keys, passwords, or
  PIN codes.
  
  Notable changes:
  
  * Since we use secrets all over the codebase, I moved the `sspi::Secret`
  type to a separate crate: `crates/secret`. Now `sspi`, `dpapi`,
  `winscard`, and many other crates reuse the same `Secret` type
  implementation.
  
  > [!WARNING]
  > Do not enable `TRACE` log level in production. `TRACE` log level can
  leak unencrypted data.
  
  ---------


