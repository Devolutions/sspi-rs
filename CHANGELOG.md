# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.15.3](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.2...sspi-v0.15.3)] - 2025-03-12

### <!-- 4 -->Bug Fixes

- Use Negotiate module instead of hardcoded Kerberos (#388) ([9e939730a8](https://github.com/Devolutions/sspi-rs/commit/9e939730a854f8267afef42fdf70f430143c6d15)) 

- Set correct seq number in MIC token (#390) ([69f03c2933](https://github.com/Devolutions/sspi-rs/commit/69f03c2933c1da106b64a565a757666cd4d94bde)) 

  Fixes Kerberos LDAP auth.
  The problem was in the invalid sequence number in MIC token.

- NTLM RPC auth (#395) ([34d896c9ce](https://github.com/Devolutions/sspi-rs/commit/34d896c9cee7e0b3e0d5ee3c5002c781d9fc8fbf)) 

### <!-- 7 -->Build

- Bump tokio from 1.43.0 to 1.44.0 (#394) ([e4e15b3103](https://github.com/Devolutions/sspi-rs/commit/e4e15b3103d3ba4f6dcabbeb897fef8d01ab9e1b)) 

- Bump the patch group across 1 directory with 4 updates (#393) ([bda97ded78](https://github.com/Devolutions/sspi-rs/commit/bda97ded7807e15f92ad796f881f85ef27839d96)) 

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
