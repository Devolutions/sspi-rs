# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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
