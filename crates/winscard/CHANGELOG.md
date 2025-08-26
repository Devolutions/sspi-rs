# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.2.2](https://github.com/Devolutions/sspi-rs/compare/winscard-v0.2.1...winscard-v0.2.2)] - 2025-08-26

### <!-- 4 -->Bug Fixes

- Incorrect `SCARD_IO_REQUEST` usage (#487) ([7e23472a7a](https://github.com/Devolutions/sspi-rs/commit/7e23472a7af347460a89379f28dc56701f7be97e)) 

  Fixes incorrect
  [`SCARD_IO_REQUEST`](https://learn.microsoft.com/en-us/windows/win32/secauthn/scard-io-request)
  usage.
  
  The `SCARD_IO_REQUEST` structure contains protocol-specific information.
  The active smart card communication protocol is negotiated during
  [`SCardConnect`](https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardconnectw)
  (see `pdwActiveProtocol` parameter).
  
  All `SCARD_IO_REQUEST`s are predefined in WinSCard/PCSC-lite and we can
  obtain handle to them using the following names
  `g_rgSCardT0Pci`/`g_rgSCardT1Pci`/`g_rgSCardRawPci`.
  
  So, when calling system provided smart card API via WinSCard/PCSC, we
  should use the predefined `SCARD_IO_REQUEST` based on the negotiated
  active protocol.


