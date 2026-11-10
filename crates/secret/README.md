# secret

Wrappers that keep secrets out of logs and zeroize them on drop.

`Secret<T>` prints as `Secret` in `Debug` and as `(secret)` in `Display`.
With the `picky` feature, `SecretPrivateKey` does the same for a `picky` private key.
