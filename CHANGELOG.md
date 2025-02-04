# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [[0.15.1](https://github.com/Devolutions/sspi-rs/compare/sspi-v0.15.0...sspi-v0.15.1)] - 2025-02-04

### <!-- 0 -->Security

- Bump reqwest from 0.12.11 to 0.12.12 in the patch group across 1 directory (#341) ([a8272f7497](https://github.com/Devolutions/sspi-rs/commit/a8272f7497cff000bbed5a2a6f369b2d054adb72)) 

  Bumps the patch group with 1 update in the / directory:
  [reqwest](https://github.com/seanmonstar/reqwest).
  
  Updates `reqwest` from 0.12.11 to 0.12.12
  <details>
  <summary>Changelog</summary>
  <p><em>Sourced from <a
  href="https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md">reqwest's
  changelog</a>.</em></p>
  <blockquote>
  <h2>v0.12.12</h2>
  <ul>
  <li>(wasm) Fix compilation by not compiler <code>tokio/time</code> on
  WASM.</li>
  </ul>
  </blockquote>
  </details>
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/8b8fdd2552ad645c7e9dd494930b3e95e2aedef2"><code>8b8fdd2</code></a>
  v0.12.12</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/1ef87032c8c5666dabec1061429e67d153db4ab1"><code>1ef8703</code></a>
  (wasm) fix: remove tower as dependency for wasm32-unknown-unknown (<a
  href="https://redirect.github.com/seanmonstar/reqwest/issues/2510">#2510</a>)</li>
  <li>See full diff in <a
  href="https://github.com/seanmonstar/reqwest/compare/v0.12.11...v0.12.12">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  
  [![Dependabot compatibility
  score](https://dependabot-badges.githubapp.com/badges/compatibility_score?dependency-name=reqwest&package-manager=cargo&previous-version=0.12.11&new-version=0.12.12)](https://docs.github.com/en/github/managing-security-vulnerabilities/about-dependabot-security-updates#about-compatibility-scores)
  
  Dependabot will resolve any conflicts with this PR as long as you don't
  alter it yourself. You can also trigger a rebase manually by commenting
  `@dependabot rebase`.

- Bump rustls from 0.23.20 to 0.23.21 in the crypto group across 1 directory (#344) ([f4eecd6eea](https://github.com/Devolutions/sspi-rs/commit/f4eecd6eeafd1457d0aa6876ea86f3fe4cc07a33)) 

  Bumps the crypto group with 1 update in the / directory:
  [rustls](https://github.com/rustls/rustls).
  
  Updates `rustls` from 0.23.20 to 0.23.21
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/rustls/rustls/commit/d1bd2c86341eb491921feca3c9408061eb0262fe"><code>d1bd2c8</code></a>
  Prepare v0.23.21</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/1338caaf8ef3bfe7d604370d07da064673e6bf5a"><code>1338caa</code></a>
  Update Cargo.lock</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/12b2276ef959cf3ea4f1715a0fdfae8475e3eb7b"><code>12b2276</code></a>
  Update <code>RELEASING.md</code> with instructions about
  <code>fuzz/Cargo.lock</code></li>
  <li><a
  href="https://github.com/rustls/rustls/commit/fe6a0d12b5af4fa79c37b230c7ce8cb8ddd5bce7"><code>fe6a0d1</code></a>
  docs: update <a href="https://github.com/cpu"><code>@​cpu</code></a>
  maintainer status</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/49b5edc4314e5d1ac59b4e9617febce91000d0f5"><code>49b5edc</code></a>
  chore(deps): lock file maintenance</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/3751e24bbc1fef4f8d0bb3711a3be2a3d2a7b793"><code>3751e24</code></a>
  cleanup: use more parens when calculating ECH seed</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/dc1f92c9a896e50a24814432956a773e229215d3"><code>dc1f92c</code></a>
  chore(deps): update rust crate itertools to 0.14</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/16a0726e5585609208f30c9b35b05b809dd7ac07"><code>16a0726</code></a>
  fuzzers/server: cover post-Accepted connections</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/b873e4c46da393b35a33c4d8ec2049fdda24b9c2"><code>b873e4c</code></a>
  fuzzers/server: fix reachable unwrap</li>
  <li><a
  href="https://github.com/rustls/rustls/commit/f98484bdbd57a57bafdd459db594e21c531f1b4a"><code>f98484b</code></a>
  chore(deps): lock file maintenance</li>
  <li>Additional commits viewable in <a
  href="https://github.com/rustls/rustls/compare/v/0.23.20...v/0.23.21">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  
  [![Dependabot compatibility
  score](https://dependabot-badges.githubapp.com/badges/compatibility_score?dependency-name=rustls&package-manager=cargo&previous-version=0.23.20&new-version=0.23.21)](https://docs.github.com/en/github/managing-security-vulnerabilities/about-dependabot-security-updates#about-compatibility-scores)
  
  Dependabot will resolve any conflicts with this PR as long as you don't
  alter it yourself. You can also trigger a rebase manually by commenting
  `@dependabot rebase`.

- Bump uuid from 1.11.0 to 1.11.1 in the patch group across 1 directory (#346) ([db290a4b77](https://github.com/Devolutions/sspi-rs/commit/db290a4b77ae921b84702ccb8269ca35a9397d65)) 

  Bumps the patch group with 1 update in the / directory:
  [uuid](https://github.com/uuid-rs/uuid).
  
  Updates `uuid` from 1.11.0 to 1.11.1
  <details>
  <summary>Release notes</summary>
  <p><em>Sourced from <a
  href="https://github.com/uuid-rs/uuid/releases">uuid's
  releases</a>.</em></p>
  <blockquote>
  <h2>1.11.1</h2>
  <h2>What's Changed</h2>
  <ul>
  <li>Finish cut off docs by <a
  href="https://github.com/KodrAus"><code>@​KodrAus</code></a> in <a
  href="https://redirect.github.com/uuid-rs/uuid/pull/777">uuid-rs/uuid#777</a></li>
  <li>Fix links in CONTRIBUTING.md by <a
  href="https://github.com/jacobggman"><code>@​jacobggman</code></a> in <a
  href="https://redirect.github.com/uuid-rs/uuid/pull/778">uuid-rs/uuid#778</a></li>
  <li>Update rust toolchain before building by <a
  href="https://github.com/KodrAus"><code>@​KodrAus</code></a> in <a
  href="https://redirect.github.com/uuid-rs/uuid/pull/781">uuid-rs/uuid#781</a></li>
  <li>Prepare for 1.11.1 release by <a
  href="https://github.com/KodrAus"><code>@​KodrAus</code></a> in <a
  href="https://redirect.github.com/uuid-rs/uuid/pull/782">uuid-rs/uuid#782</a></li>
  </ul>
  <h2>New Contributors</h2>
  <ul>
  <li><a
  href="https://github.com/jacobggman"><code>@​jacobggman</code></a> made
  their first contribution in <a
  href="https://redirect.github.com/uuid-rs/uuid/pull/778">uuid-rs/uuid#778</a></li>
  </ul>
  <p><strong>Full Changelog</strong>: <a
  href="https://github.com/uuid-rs/uuid/compare/1.11.0...1.11.1">https://github.com/uuid-rs/uuid/compare/1.11.0...1.11.1</a></p>
  </blockquote>
  </details>
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/42c2d0ff4e766596cc047b6163d126bfc4854882"><code>42c2d0f</code></a>
  Merge pull request <a
  href="https://redirect.github.com/uuid-rs/uuid/issues/782">#782</a> from
  uuid-rs/cargo/1.11.1</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/7dc4122c07ee2bf4459d73c81b68cea43258b8ae"><code>7dc4122</code></a>
  prepare for 1.11.1 release</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/4cdc98107426fa17d8f22b71281bdde83430e47f"><code>4cdc981</code></a>
  Merge pull request <a
  href="https://redirect.github.com/uuid-rs/uuid/issues/781">#781</a> from
  uuid-rs/ci/rust-versions</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/1ce698c1cf6452b9ab083900eaccc33d91c71f40"><code>1ce698c</code></a>
  update rust toolchain before building</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/5cbe0ce96219182511dafc5d6a7e271b41cdaf03"><code>5cbe0ce</code></a>
  Merge pull request <a
  href="https://redirect.github.com/uuid-rs/uuid/issues/778">#778</a> from
  jacobggman/main</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/6e55348c06d1b50fe94b4ce7736556d0b9b1c933"><code>6e55348</code></a>
  Fix broken link to RFC 1574 in CONTRIBUTING.md</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/147d993034588eb0edb4ac9643b6998590107d30"><code>147d993</code></a>
  update table of contents in CONTRIBUTING.md</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/89019199989ffa616412eff4a67a5283f673659b"><code>8901919</code></a>
  Merge pull request <a
  href="https://redirect.github.com/uuid-rs/uuid/issues/777">#777</a> from
  uuid-rs/KodrAus-patch-1</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/a486f03bef05f825db6d5b07d356ae3a1abf9f05"><code>a486f03</code></a>
  try using specific node version</li>
  <li><a
  href="https://github.com/uuid-rs/uuid/commit/dcf1d81bd5b5753612b7c8167b1ca61cb31d0c66"><code>dcf1d81</code></a>
  bump msrv to 1.63.0</li>
  <li>Additional commits viewable in <a
  href="https://github.com/uuid-rs/uuid/compare/1.11.0...1.11.1">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  
  [![Dependabot compatibility
  score](https://dependabot-badges.githubapp.com/badges/compatibility_score?dependency-name=uuid&package-manager=cargo&previous-version=1.11.0&new-version=1.11.1)](https://docs.github.com/en/github/managing-security-vulnerabilities/about-dependabot-security-updates#about-compatibility-scores)
  
  Dependabot will resolve any conflicts with this PR as long as you don't
  alter it yourself. You can also trigger a rebase manually by commenting
  `@dependabot rebase`.

### <!-- 1 -->Features

- Add `make_signature` and `verify_signature` to `Sspi` trait (#343) ([040188a34d](https://github.com/Devolutions/sspi-rs/commit/040188a34d5d7b8607825b25a4eb78c25c6b57cc)) 

### <!-- 4 -->Bug Fixes

- Store session key when using server-side NTLM implementation (#354) ([41d1ca7fed](https://github.com/Devolutions/sspi-rs/commit/41d1ca7fed623759dcc9ff6f28c7558ecfa6fcbd)) 

### <!-- 7 -->Build

- Cargo update (#332) ([1ec38275cf](https://github.com/Devolutions/sspi-rs/commit/1ec38275cff42038f732be71131598cb3a688b39)) 

- Support 16 KB page sizes on Android ([cd3099109a](https://github.com/Devolutions/sspi-rs/commit/cd3099109ad5ba82403364dc4d27bb702f3117d7)) 

- Bump proptest from 1.5.0 to 1.6.0 (#337) ([7121337765](https://github.com/Devolutions/sspi-rs/commit/71213377654dd118ff175add5ada4c2d714e4f38)) 

  Bumps [proptest](https://github.com/proptest-rs/proptest) from 1.5.0 to 1.6.0.
  - [Release notes](https://github.com/proptest-rs/proptest/releases)
  - [Changelog](https://github.com/proptest-rs/proptest/blob/main/CHANGELOG.md)
  - [Commits](https://github.com/proptest-rs/proptest/commits)
  
  ---
  updated-dependencies:
  - dependency-name: proptest
    dependency-type: direct:production
    update-type: version-update:semver-minor
  ...

- Bump the patch group across 1 directory with 4 updates (#336) ([f5210a50ec](https://github.com/Devolutions/sspi-rs/commit/f5210a50ece36e2ba0e89197e38d976b3b2063ca)) 

  Bumps the patch group with 3 updates in the / directory: [serde](https://github.com/serde-rs/serde), [hickory-resolver](https://github.com/hickory-dns/hickory-dns) and [libc](https://github.com/rust-lang/libc).
  
  
  Updates `serde` from 1.0.215 to 1.0.216
  - [Release notes](https://github.com/serde-rs/serde/releases)
  - [Commits](https://github.com/serde-rs/serde/compare/v1.0.215...v1.0.216)
  
  Updates `serde_derive` from 1.0.215 to 1.0.216
  - [Release notes](https://github.com/serde-rs/serde/releases)
  - [Commits](https://github.com/serde-rs/serde/compare/v1.0.215...v1.0.216)
  
  Updates `hickory-resolver` from 0.24.1 to 0.24.2
  - [Release notes](https://github.com/hickory-dns/hickory-dns/releases)
  - [Changelog](https://github.com/hickory-dns/hickory-dns/blob/v0.24.2/CHANGELOG.md)
  - [Commits](https://github.com/hickory-dns/hickory-dns/compare/v0.24.1...v0.24.2)
  
  Updates `libc` from 0.2.167 to 0.2.168
  - [Release notes](https://github.com/rust-lang/libc/releases)
  - [Changelog](https://github.com/rust-lang/libc/blob/0.2.168/CHANGELOG.md)
  - [Commits](https://github.com/rust-lang/libc/compare/0.2.167...0.2.168)
  
  ---
  updated-dependencies:
  - dependency-name: serde
    dependency-type: direct:production
    update-type: version-update:semver-patch
    dependency-group: patch
  - dependency-name: serde_derive
    dependency-type: direct:production
    update-type: version-update:semver-patch
    dependency-group: patch
  - dependency-name: hickory-resolver
    dependency-type: direct:production
    update-type: version-update:semver-patch
    dependency-group: patch
  - dependency-name: libc
    dependency-type: direct:production
    update-type: version-update:semver-patch
    dependency-group: patch
  ...

- Bump rustls in the crypto group across 1 directory (#335) ([52568079fc](https://github.com/Devolutions/sspi-rs/commit/52568079fcac3b6c689feedab3ecc2d36031ba1a)) 

  Bumps the crypto group with 1 update in the / directory: [rustls](https://github.com/rustls/rustls).
  
  
  Updates `rustls` from 0.23.19 to 0.23.20
  - [Release notes](https://github.com/rustls/rustls/releases)
  - [Changelog](https://github.com/rustls/rustls/blob/main/CHANGELOG.md)
  - [Commits](https://github.com/rustls/rustls/compare/v/0.23.19...v/0.23.20)
  
  ---
  updated-dependencies:
  - dependency-name: rustls
    dependency-type: direct:production
    update-type: version-update:semver-patch
    dependency-group: crypto
  ...

- Bump libc in the patch group across 1 directory (#339) ([b66867da97](https://github.com/Devolutions/sspi-rs/commit/b66867da976644f91f9b6aaa5fb6aebba63d82e0)) 

  Bumps the patch group with 1 update in the / directory: [libc](https://github.com/rust-lang/libc).
  
  
  Updates `libc` from 0.2.168 to 0.2.169
  - [Release notes](https://github.com/rust-lang/libc/releases)
  - [Changelog](https://github.com/rust-lang/libc/blob/0.2.169/CHANGELOG.md)
  - [Commits](https://github.com/rust-lang/libc/compare/0.2.168...0.2.169)
  
  ---
  updated-dependencies:
  - dependency-name: libc
    dependency-type: direct:production
    update-type: version-update:semver-patch
    dependency-group: patch
  ...

- Bump the patch group across 1 directory with 3 updates (#340) ([bbb3c91330](https://github.com/Devolutions/sspi-rs/commit/bbb3c91330aad9740f2cb9db008b149c8aa60fcd)) 

  Bumps the patch group with 2 updates in the / directory:
  [serde](https://github.com/serde-rs/serde) and
  [reqwest](https://github.com/seanmonstar/reqwest).
  
  Updates `serde` from 1.0.216 to 1.0.217
  <details>
  <summary>Release notes</summary>
  <p><em>Sourced from <a
  href="https://github.com/serde-rs/serde/releases">serde's
  releases</a>.</em></p>
  <blockquote>
  <h2>v1.0.217</h2>
  <ul>
  <li>Support serializing externally tagged unit variant inside flattened
  field (<a
  href="https://redirect.github.com/serde-rs/serde/issues/2786">#2786</a>,
  thanks <a
  href="https://github.com/Mingun"><code>@​Mingun</code></a>)</li>
  </ul>
  </blockquote>
  </details>
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/serde-rs/serde/commit/930401b0dd58a809fce34da091b8aa3d6083cb33"><code>930401b</code></a>
  Release 1.0.217</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/cb6eaea151b831db36457fff17f16a195702dad4"><code>cb6eaea</code></a>
  Fix roundtrip inconsistency:</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/b6f339ca3676584e1c26028b4040c337b0105e34"><code>b6f339c</code></a>
  Resolve repr_packed_without_abi clippy lint in tests</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/2a5caea1a8abc9b6077d8eb43bd6109124db2a5f"><code>2a5caea</code></a>
  Merge pull request <a
  href="https://redirect.github.com/serde-rs/serde/issues/2872">#2872</a>
  from dtolnay/ehpersonality</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/b9f93f99aaa90760d421b60b8de6273999ca8980"><code>b9f93f9</code></a>
  Add no-std CI on stable compiler</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/eb5cd476ba7e71e22b0a856c1e78a3af1b7bbe0a"><code>eb5cd47</code></a>
  Drop #[lang = &quot;eh_personality&quot;] from no-std test</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/8478a3b7dd847753440bdaf65b828a4a535e6cef"><code>8478a3b</code></a>
  Merge pull request <a
  href="https://redirect.github.com/serde-rs/serde/issues/2871">#2871</a>
  from dtolnay/nostdstart</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/dbb909136e610b9753dcd9ffcfb8f6a3f6510060"><code>dbb9091</code></a>
  Replace #[start] with extern fn main</li>
  <li>See full diff in <a
  href="https://github.com/serde-rs/serde/compare/v1.0.216...v1.0.217">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  Updates `serde_derive` from 1.0.216 to 1.0.217
  <details>
  <summary>Release notes</summary>
  <p><em>Sourced from <a
  href="https://github.com/serde-rs/serde/releases">serde_derive's
  releases</a>.</em></p>
  <blockquote>
  <h2>v1.0.217</h2>
  <ul>
  <li>Support serializing externally tagged unit variant inside flattened
  field (<a
  href="https://redirect.github.com/serde-rs/serde/issues/2786">#2786</a>,
  thanks <a
  href="https://github.com/Mingun"><code>@​Mingun</code></a>)</li>
  </ul>
  </blockquote>
  </details>
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/serde-rs/serde/commit/930401b0dd58a809fce34da091b8aa3d6083cb33"><code>930401b</code></a>
  Release 1.0.217</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/cb6eaea151b831db36457fff17f16a195702dad4"><code>cb6eaea</code></a>
  Fix roundtrip inconsistency:</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/b6f339ca3676584e1c26028b4040c337b0105e34"><code>b6f339c</code></a>
  Resolve repr_packed_without_abi clippy lint in tests</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/2a5caea1a8abc9b6077d8eb43bd6109124db2a5f"><code>2a5caea</code></a>
  Merge pull request <a
  href="https://redirect.github.com/serde-rs/serde/issues/2872">#2872</a>
  from dtolnay/ehpersonality</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/b9f93f99aaa90760d421b60b8de6273999ca8980"><code>b9f93f9</code></a>
  Add no-std CI on stable compiler</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/eb5cd476ba7e71e22b0a856c1e78a3af1b7bbe0a"><code>eb5cd47</code></a>
  Drop #[lang = &quot;eh_personality&quot;] from no-std test</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/8478a3b7dd847753440bdaf65b828a4a535e6cef"><code>8478a3b</code></a>
  Merge pull request <a
  href="https://redirect.github.com/serde-rs/serde/issues/2871">#2871</a>
  from dtolnay/nostdstart</li>
  <li><a
  href="https://github.com/serde-rs/serde/commit/dbb909136e610b9753dcd9ffcfb8f6a3f6510060"><code>dbb9091</code></a>
  Replace #[start] with extern fn main</li>
  <li>See full diff in <a
  href="https://github.com/serde-rs/serde/compare/v1.0.216...v1.0.217">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  Updates `reqwest` from 0.12.9 to 0.12.11
  <details>
  <summary>Release notes</summary>
  <p><em>Sourced from <a
  href="https://github.com/seanmonstar/reqwest/releases">reqwest's
  releases</a>.</em></p>
  <blockquote>
  <h2>v0.12.11</h2>
  <h2>What's Changed</h2>
  <ul>
  <li>Fix decompression returning an error when HTTP/2 ends with an empty
  data frame by <a
  href="https://github.com/seanmonstar"><code>@​seanmonstar</code></a> in
  <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2508">seanmonstar/reqwest#2508</a></li>
  </ul>
  <p><strong>Full Changelog</strong>: <a
  href="https://github.com/seanmonstar/reqwest/compare/v0.12.10...v0.12.11">https://github.com/seanmonstar/reqwest/compare/v0.12.10...v0.12.11</a></p>
  <h2>v0.12.10</h2>
  <h2>What's Changed</h2>
  <ul>
  <li>Add <code>ClientBuilder::connector_layer()</code> to allow
  customizing the connector stack. by <a
  href="https://github.com/jlizen"><code>@​jlizen</code></a> in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2496">seanmonstar/reqwest#2496</a></li>
  <li>Add <code>ClientBuilder::http2_max_header_list_size()</code> option
  by <a href="https://github.com/DSharifi"><code>@​DSharifi</code></a> in
  <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2465">seanmonstar/reqwest#2465</a></li>
  <li>Fix decompression of chunked bodies so the connections can be reused
  more often by <a
  href="https://github.com/Andrey36652"><code>@​Andrey36652</code></a> in
  <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2484">seanmonstar/reqwest#2484</a></li>
  <li>Fix propagating body size hint (<code>content-length</code>)
  information when wrapping bodies by <a
  href="https://github.com/seanmonstar"><code>@​seanmonstar</code></a> in
  <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2503">seanmonstar/reqwest#2503</a></li>
  </ul>
  <h2>New Contributors</h2>
  <ul>
  <li><a href="https://github.com/DSharifi"><code>@​DSharifi</code></a>
  made their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2465">seanmonstar/reqwest#2465</a></li>
  <li><a
  href="https://github.com/gretchenfrage"><code>@​gretchenfrage</code></a>
  made their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2464">seanmonstar/reqwest#2464</a></li>
  <li><a href="https://github.com/hsivonen"><code>@​hsivonen</code></a>
  made their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2470">seanmonstar/reqwest#2470</a></li>
  <li><a href="https://github.com/ovnicraft"><code>@​ovnicraft</code></a>
  made their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2469">seanmonstar/reqwest#2469</a></li>
  <li><a href="https://github.com/Nuhvi"><code>@​Nuhvi</code></a> made
  their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2473">seanmonstar/reqwest#2473</a></li>
  <li><a href="https://github.com/caojen"><code>@​caojen</code></a> made
  their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2488">seanmonstar/reqwest#2488</a></li>
  <li><a
  href="https://github.com/Andrey36652"><code>@​Andrey36652</code></a>
  made their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2484">seanmonstar/reqwest#2484</a></li>
  <li><a href="https://github.com/jlizen"><code>@​jlizen</code></a> made
  their first contribution in <a
  href="https://redirect.github.com/seanmonstar/reqwest/pull/2499">seanmonstar/reqwest#2499</a></li>
  </ul>
  <h2>Thanks</h2>
  <ul>
  <li><a
  href="https://github.com/seanmonstar"><code>@​seanmonstar</code></a></li>
  <li><a href="https://github.com/nyurik"><code>@​nyurik</code></a></li>
  </ul>
  <p><strong>Full Changelog</strong>: <a
  href="https://github.com/seanmonstar/reqwest/compare/v0.12.9...v0.12.10">https://github.com/seanmonstar/reqwest/compare/v0.12.9...v0.12.10</a></p>
  </blockquote>
  </details>
  <details>
  <summary>Changelog</summary>
  <p><em>Sourced from <a
  href="https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md">reqwest's
  changelog</a>.</em></p>
  <blockquote>
  <h2>v0.12.11</h2>
  <ul>
  <li>Fix decompression returning an error when HTTP/2 ends with an empty
  data frame.</li>
  </ul>
  <h2>v0.12.10</h2>
  <ul>
  <li>Add <code>ClientBuilder::connector_layer()</code> to allow
  customizing the connector stack.</li>
  <li>Add <code>ClientBuilder::http2_max_header_list_size()</code>
  option.</li>
  <li>Fix propagating body size hint (<code>content-length</code>)
  information when wrapping bodies.</li>
  <li>Fix decompression of chunked bodies so the connections can be reused
  more often.</li>
  </ul>
  </blockquote>
  </details>
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/224f0b89d8cd7b653f9fadf967bafd3d082211dc"><code>224f0b8</code></a>
  v0.12.11</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/beea3320c4da59149bb46b6a118b500e6eb1ee5e"><code>beea332</code></a>
  fix decoding extra empty frame (<a
  href="https://redirect.github.com/seanmonstar/reqwest/issues/2508">#2508</a>)</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/177cc7f8d93177bd1cbe9a687237928f884f18c8"><code>177cc7f</code></a>
  cleanup: typo fix</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/409cff3cf72ceba1c63268ccba5b7ed33014abcd"><code>409cff3</code></a>
  v0.12.10</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/ea48da723c17380a7d9cdf791248cd3a196c005a"><code>ea48da7</code></a>
  docs: fix a few spelling issues (<a
  href="https://redirect.github.com/seanmonstar/reqwest/issues/2478">#2478</a>)</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/3ce98b5f2288637e22dad98e881c210246567021"><code>3ce98b5</code></a>
  fix: propagate Body::size_hint when wrapping bodies (<a
  href="https://redirect.github.com/seanmonstar/reqwest/issues/2503">#2503</a>)</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/44ca5ee864ebff81e987263de74be7002fc6b353"><code>44ca5ee</code></a>
  remove Clone from connect::Unnameable for now (<a
  href="https://redirect.github.com/seanmonstar/reqwest/issues/2502">#2502</a>)</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/2a7c1b61e0693f8b9924e2e89257aa131a30ee83"><code>2a7c1b6</code></a>
  feat: allow pluggable tower layers in connector service stack (<a
  href="https://redirect.github.com/seanmonstar/reqwest/issues/2496">#2496</a>)</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/8a2174f8a4259691b5ca0a16778427127f61373a"><code>8a2174f</code></a>
  chore: in README, update requirements to mention rustls along with
  vendored o...</li>
  <li><a
  href="https://github.com/seanmonstar/reqwest/commit/d36c0f5fd93f8190c9f39990ce4ec859c2b6d567"><code>d36c0f5</code></a>
  perf: fix decoder streams to make pooled connections reusable (<a
  href="https://redirect.github.com/seanmonstar/reqwest/issues/2484">#2484</a>)</li>
  <li>Additional commits viewable in <a
  href="https://github.com/seanmonstar/reqwest/compare/v0.12.9...v0.12.11">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  
  Dependabot will resolve any conflicts with this PR as long as you don't
  alter it yourself. You can also trigger a rebase manually by commenting
  `@dependabot rebase`.

- Bump the windows group across 1 directory with 2 updates (#345) ([a6b0f8cdf6](https://github.com/Devolutions/sspi-rs/commit/a6b0f8cdf614e78a0e5aa0ef675ae01ec8a2dc0f)) 

  Bumps the windows group with 2 updates in the / directory:
  [winreg](https://github.com/gentoo90/winreg-rs) and
  [windows](https://github.com/microsoft/windows-rs).
  
  Updates `winreg` from 0.52.0 to 0.55.0
  <details>
  <summary>Release notes</summary>
  <p><em>Sourced from <a
  href="https://github.com/gentoo90/winreg-rs/releases">winreg's
  releases</a>.</em></p>
  <blockquote>
  <h2>0.55.0 (windows-sys)</h2>
  <ul>
  <li>Breaking change: Increate MSRV to 1.60</li>
  <li>Breaking change: Upgrade <code>windows-sys</code> to version 0.59
  (<a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/77">#77</a>)</li>
  </ul>
  <h2>0.54.0 (windows-sys)</h2>
  <ul>
  <li>Breaking change: Migrate to the 2021 edition of Rust (MSRV
  1.56)</li>
  <li>Breaking change: Upgrade <code>windows-sys</code> to version 0.52
  (closes <a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/63">#63</a>,
  <a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/70">#70</a>)</li>
  </ul>
  <h2>0.53.0 (windows-sys)</h2>
  <ul>
  <li>Don't stop deserialization of <code>Any</code> due to
  <code>REG_NONE</code> (pullrequest <a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/67">#67</a>,
  fixes <a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/66">#66</a>)</li>
  <li>Implement (de)serialization of <code>Option</code> (<a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/56">#56</a>)</li>
  <li>Add <code>RegKey</code> methods for creating/opening subkeys with
  custom options (<a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/65">#65</a>)</li>
  </ul>
  </blockquote>
  </details>
  <details>
  <summary>Changelog</summary>
  <p><em>Sourced from <a
  href="https://github.com/gentoo90/winreg-rs/blob/master/CHANGELOG.md">winreg's
  changelog</a>.</em></p>
  <blockquote>
  <h2>0.55.0</h2>
  <ul>
  <li>Breaking change: Increate MSRV to 1.60</li>
  <li>Breaking change: Upgrade <code>windows-sys</code> to version 0.59
  (<a
  href="https://redirect.github.com/gentoo90/winreg-rs/pull/77">#77</a>)</li>
  </ul>
  <h2>0.54.0</h2>
  <ul>
  <li>Breaking change: Migrate to the 2021 edition of Rust (MSRV
  1.56)</li>
  <li>Breaking change: Upgrade <code>windows-sys</code> to version 0.52
  (closes <a
  href="https://redirect.github.com/gentoo90/winreg-rs/pull/63">#63</a>,
  <a
  href="https://redirect.github.com/gentoo90/winreg-rs/pull/70">#70</a>)</li>
  </ul>
  <h2>0.15.0, 0.53.0</h2>
  <ul>
  <li>Don't stop deserialization of <code>Any</code> due to
  <code>REG_NONE</code> (pullrequest <a
  href="https://redirect.github.com/gentoo90/winreg-rs/pull/67">#67</a>,
  fixes <a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/66">#66</a>)</li>
  <li>Implement (de)serialization of <code>Option</code> (<a
  href="https://redirect.github.com/gentoo90/winreg-rs/issues/56">#56</a>)</li>
  <li>Add <code>RegKey</code> methods for creating/opening subkeys with
  custom options (<a
  href="https://redirect.github.com/gentoo90/winreg-rs/pull/65">#65</a>)</li>
  </ul>
  </blockquote>
  </details>
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/9243b238493c90d3b5e8f68f33fad9c77fb9d35e"><code>9243b23</code></a>
  Bump version to 0.55.0</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/f0440749e8d000821cbc1940dcb3c69e00c9f33f"><code>f044074</code></a>
  Upgrade <code>windows-sys</code> to version 0.59 (and MSRV to 1.60)</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/4574febe779ebe502c0617e8618c14f9e8dee3ce"><code>4574feb</code></a>
  Bump version to 0.54.0</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/105ca7aee378e14b336f9aaa797144904448af84"><code>105ca7a</code></a>
  Upgrade <code>windows-sys</code> to version 0.52</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/93aefdf523812bc9d8e6295d4577b34c89cf06c1"><code>93aefdf</code></a>
  Migrate to the 2021 edition of Rust</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/c9315d07f062b766e9283920e935e988fc5bf2be"><code>c9315d0</code></a>
  Clippy: remove unnecessary typecasts</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/e62111ee60cd998680a8ecc1aad000d8b7a15ba1"><code>e62111e</code></a>
  Merge branch 'winapi'</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/049035fe943dfe12d390aef655f07c2e598e70cd"><code>049035f</code></a>
  Update the transaction example in the docs</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/5baac5d5a4d0e86706f9f2628f18f74321604079"><code>5baac5d</code></a>
  CI: upgrade actions to the latest versions</li>
  <li><a
  href="https://github.com/gentoo90/winreg-rs/commit/cbaeb4e00a35f1b00d3e43d6e1c002e2856c9215"><code>cbaeb4e</code></a>
  CI: check <code>Cargo.toml</code> formatting</li>
  <li>Additional commits viewable in <a
  href="https://github.com/gentoo90/winreg-rs/compare/v0.52.0...v0.55.0">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  Updates `windows` from 0.58.0 to 0.59.0
  <details>
  <summary>Commits</summary>
  <ul>
  <li><a
  href="https://github.com/microsoft/windows-rs/commit/308e08ec259027ebbef11b8ef838923626bf821e"><code>308e08e</code></a>
  Release 0.59.0 (<a
  href="https://redirect.github.com/microsoft/windows-rs/issues/3182">#3182</a>)</li>
  <li><a
  href="https://github.com/microsoft/windows-rs/commit/429666eb724f4a0378974d67adf38c45ce7d78d4"><code>429666e</code></a>
  Fix support for <code>no_std</code> (<a
  href="https://redirect.github.com/microsoft/windows-rs/issues/3180">#3180</a>)</li>
  <li><a
  href="https://github.com/microsoft/windows-rs/commit/02c4f29d19fbe6d59b2ae0b42262e68d00438f0f"><code>02c4f29</code></a>
  Update component sample to use static factory (<a
  href="https://redirect.github.com/microsoft/windows-rs/issues/3154">#3154</a>)</li>
  <li><a
  href="https://github.com/microsoft/windows-rs/commit/7cec74ffe7797f522501ad17953a4e3701e0c1d9"><code>7cec74f</code></a>
  Implement static COM objects (<a
  href="https://redirect.github.com/microsoft/windows-rs/issues/3144">#3144</a>)</li>
  <li><a
  href="https://github.com/microsoft/windows-rs/commit/12f4621020ab6cea11db14d06d3c1d28ca14ae54"><code>12f4621</code></a>
  Reduce boilerplate code in <code>windows-core</code> crate for
  <code>VARIANT</code> support (<a
  href="https://redirect.github.com/microsoft/windows-rs/issues/3151">#3151</a>)</li>
  <li>See full diff in <a
  href="https://github.com/microsoft/windows-rs/compare/0.58.0...0.59.0">compare
  view</a></li>
  </ul>
  </details>
  <br />
  
  
  Dependabot will resolve any conflicts with this PR as long as you don't
  alter it yourself. You can also trigger a rebase manually by commenting
  `@dependabot rebase`.

- Bump the crypto group across 1 directory with 4 updates (#351) ([f9ef383fd2](https://github.com/Devolutions/sspi-rs/commit/f9ef383fd27e9afe1c14c5f7a0ab57017e419384)) 

- Bump tokio from 1.42.0 to 1.43.0 (#353) ([1486869e0d](https://github.com/Devolutions/sspi-rs/commit/1486869e0d44f62366d54cbf46b4f1d40222e518)) 

- Bump bitflags from 2.6.0 to 2.8.0 (#352) ([a0a384b3f7](https://github.com/Devolutions/sspi-rs/commit/a0a384b3f7db9c801ba263f84003b4845982a3d7)) 

- Bump uuid from 1.11.1 to 1.12.1 (#355) ([1984ebf191](https://github.com/Devolutions/sspi-rs/commit/1984ebf1917989c4756f76656021c04706455243)) 


