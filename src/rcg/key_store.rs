//! Session-bound Kerberos keys referenced by opaque handles.
//!
//! Remote Credential Guard must not disclose reusable Kerberos keys to the remote host.
//! Keys that the remote host needs to reference (for example, the forwarded TGT session key) are
//! kept here and the remote host only receives a random handle with the same length as the key.
//! Ordinary service-ticket keys returned in a protected KDC reply are also retained, so follow-up
//! service operations can authorize their exact bytes without accepting arbitrary caller-supplied keys.
//!
//! Windows has accepted the initial logon credential using such a handle as the
//! `KERB_RPC_ENCRYPTION_KEY` key value (MS-RDPEAR [2.2.1.2.8 KERB_RPC_ENCRYPTION_KEY]).
//! Successful outbound Kerberos authentication and durable bindings across reconnects remain unverified.
//! Lookups fail closed: an unknown reference is an error. TGT lookups only accept opaque handles.
//!
//! [2.2.1.2.8 KERB_RPC_ENCRYPTION_KEY]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/

use std::fmt;

use picky_krb::crypto::CipherSuite;
use rand::rngs::StdRng;
use rand_core::Rng as _;

use super::wrap::{aes_size, constant_time_eq};
use crate::{Error, ErrorKind, Secret};

/// Upper bound on keys held by one Remote Credential Guard session.
pub(crate) const MAX_KEYS: usize = 256;

/// Restricts which operations may use a stored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRole {
    /// Session key of a ticket-granting ticket.
    TicketGranting,
    /// Session key of a service ticket.
    Service,
}

pub(crate) struct StoredKey {
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) key: Secret<Vec<u8>>,
    pub(crate) role: KeyRole,
}

struct Entry {
    handle: Vec<u8>,
    key: StoredKey,
}

#[derive(Default)]
pub(crate) struct KeyStore {
    entries: Vec<Entry>,
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStore").field("len", &self.entries.len()).finish()
    }
}

impl KeyStore {
    /// Stores `key` and returns a fresh random handle for it.
    pub(crate) fn insert(
        &mut self,
        cipher_suite: CipherSuite,
        key: Secret<Vec<u8>>,
        role: KeyRole,
        rng: &mut StdRng,
    ) -> crate::Result<Vec<u8>> {
        aes_size(&cipher_suite)?;

        let key_size = cipher_suite.cipher().key_size();
        if key.as_ref().len() != key_size {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "kerberos key length does not match its encryption type",
            ));
        }

        if self.entries.len() >= MAX_KEYS {
            return Err(Error::new(
                ErrorKind::InsufficientMemory,
                "remote credential guard key store is full",
            ));
        }

        if self.entries.iter().any(|entry| {
            constant_time_eq(&entry.handle, key.as_ref())
                || (entry.key.role != role && constant_time_eq(entry.key.key.as_ref(), key.as_ref()))
        }) {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "kerberos key conflicts with a live remote credential guard reference",
            ));
        }

        // INVARIANT: handles and key bytes have disjoint namespaces.
        let handle = loop {
            let mut handle = vec![0; key_size];
            rng.fill_bytes(&mut handle);

            let conflicts = self.entries.iter().fold(false, |found, entry| {
                found | constant_time_eq(&entry.handle, &handle) | constant_time_eq(entry.key.key.as_ref(), &handle)
            });
            if !constant_time_eq(&handle, key.as_ref()) && !conflicts {
                break handle;
            }
        };

        self.entries.push(Entry {
            handle: handle.clone(),
            key: StoredKey {
                cipher_suite,
                key,
                role,
            },
        });

        Ok(handle)
    }

    /// Looks up a key by its encryption type and reference.
    ///
    /// Service operations also accept the exact key bytes retained for that service ticket. Reusable
    /// TGT keys never resolve by their raw bytes, and no unknown reference is interpreted as a key.
    ///
    /// All entries are compared so that the lookup time does not depend on the matching position.
    pub(crate) fn get(&self, etype: i32, reference: &[u8], role: KeyRole) -> crate::Result<&StoredKey> {
        let mut found = None;

        for entry in &self.entries {
            let matches_handle = constant_time_eq(&entry.handle, reference);
            let matches_service_key = role == KeyRole::Service
                && entry.key.role == KeyRole::Service
                && constant_time_eq(entry.key.key.as_ref(), reference);
            if (matches_handle | matches_service_key) && found.is_none() {
                found = Some(&entry.key);
            }
        }

        let key =
            found.ok_or_else(|| Error::new(ErrorKind::NoKerbKey, "unknown remote credential guard key reference"))?;

        if i32::from(u8::from(key.cipher_suite.clone())) != etype {
            return Err(Error::new(
                ErrorKind::AlgorithmMismatch,
                "remote credential guard key reference has a different encryption type",
            ));
        }

        if key.role != role {
            return Err(Error::new(
                ErrorKind::NoKerbKey,
                "remote credential guard key reference is not authorized for this operation",
            ));
        }

        Ok(key)
    }

    /// Returns `true` if `value` equals any live handle.
    pub(crate) fn contains_handle(&self, value: &[u8]) -> bool {
        self.entries
            .iter()
            .fold(false, |found, entry| found | constant_time_eq(&entry.handle, value))
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng as _;

    use super::*;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(1)
    }

    #[test]
    fn insert_and_lookup_by_handle() {
        let mut store = KeyStore::default();
        let mut rng = rng();
        let handle = store
            .insert(
                CipherSuite::Aes256CtsHmacSha196,
                Secret::new(vec![0x33; 32]),
                KeyRole::TicketGranting,
                &mut rng,
            )
            .unwrap();

        assert_eq!(handle.len(), 32);
        assert_ne!(handle, vec![0x33; 32]);
        assert!(store.contains_handle(&handle));

        let key = store.get(18, &handle, KeyRole::TicketGranting).unwrap();
        assert_eq!(key.key.as_ref(), &vec![0x33; 32]);
    }

    #[test]
    fn lookup_fails_closed() {
        let mut store = KeyStore::default();
        let mut rng = rng();
        let key = vec![0x44; 16];
        let handle = store
            .insert(
                CipherSuite::Aes128CtsHmacSha196,
                Secret::new(key.clone()),
                KeyRole::Service,
                &mut rng,
            )
            .unwrap();

        // Only service keys retained by this store are accepted by value.
        assert_eq!(store.get(17, &key, KeyRole::Service).unwrap().key.as_ref(), &key);
        let err = store.get(17, &[0x45; 16], KeyRole::Service).err().unwrap();
        assert_eq!(err.error_type, ErrorKind::NoKerbKey);
        let err = store.get(18, &key, KeyRole::Service).err().unwrap();
        assert_eq!(err.error_type, ErrorKind::AlgorithmMismatch);
        let err = store.get(17, &key, KeyRole::TicketGranting).err().unwrap();
        assert_eq!(err.error_type, ErrorKind::NoKerbKey);

        let err = store.get(18, &handle, KeyRole::Service).err().unwrap();
        assert_eq!(err.error_type, ErrorKind::AlgorithmMismatch);

        let err = store.get(17, &handle, KeyRole::TicketGranting).err().unwrap();
        assert_eq!(err.error_type, ErrorKind::NoKerbKey);
    }

    #[test]
    fn service_bytes_are_session_enctype_and_role_bound_but_tgt_bytes_never_resolve() {
        for suite in [CipherSuite::Aes128CtsHmacSha196, CipherSuite::Aes256CtsHmacSha196] {
            let mut store = KeyStore::default();
            let mut rng = rng();
            let etype = i32::from(u8::from(&suite));
            let service = vec![0x55; suite.cipher().key_size()];
            let tgt = vec![0x66; suite.cipher().key_size()];
            assert_eq!(store.len(), 0);
            assert_eq!(
                store.get(etype, &service, KeyRole::Service).err().unwrap().error_type,
                ErrorKind::NoKerbKey
            );
            let service_handle = store
                .insert(suite.clone(), Secret::new(service.clone()), KeyRole::Service, &mut rng)
                .unwrap();
            let tgt_handle = store
                .insert(
                    suite.clone(),
                    Secret::new(tgt.clone()),
                    KeyRole::TicketGranting,
                    &mut rng,
                )
                .unwrap();
            assert_eq!(store.len(), 2);
            assert!(!store.contains_handle(&service));
            assert!(!store.contains_handle(&tgt));
            for value in [&service_handle, &service] {
                let key = store.get(etype, value, KeyRole::Service).unwrap();
                assert_eq!(key.key.as_ref(), &service);
                assert_eq!(key.cipher_suite, suite);
                assert_eq!(key.role, KeyRole::Service);
                assert_eq!(
                    store
                        .get(etype, value, KeyRole::TicketGranting)
                        .err()
                        .unwrap()
                        .error_type,
                    ErrorKind::NoKerbKey
                );
                assert_eq!(
                    store.get(23, value, KeyRole::Service).err().unwrap().error_type,
                    ErrorKind::AlgorithmMismatch
                );
                let foreign = KeyStore::default();
                assert_eq!(
                    foreign.get(etype, value, KeyRole::Service).err().unwrap().error_type,
                    ErrorKind::NoKerbKey
                );
            }
            assert_eq!(
                store
                    .get(etype, &tgt_handle, KeyRole::TicketGranting)
                    .unwrap()
                    .key
                    .as_ref(),
                &tgt
            );
            for role in [KeyRole::Service, KeyRole::TicketGranting] {
                assert_eq!(
                    store.get(etype, &tgt, role).err().unwrap().error_type,
                    ErrorKind::NoKerbKey
                );
            }
        }
    }

    #[test]
    fn insertion_rejects_raw_keys_equal_to_live_handles_without_retention() {
        for suite in [CipherSuite::Aes128CtsHmacSha196, CipherSuite::Aes256CtsHmacSha196] {
            for existing_role in [KeyRole::TicketGranting, KeyRole::Service] {
                for new_role in [KeyRole::TicketGranting, KeyRole::Service] {
                    let mut store = KeyStore::default();
                    let mut rng = rng();
                    let etype = i32::from(u8::from(&suite));
                    let original = vec![0x31; suite.cipher().key_size()];
                    let unrelated = store
                        .insert(
                            suite.clone(),
                            Secret::new(vec![0x11; suite.cipher().key_size()]),
                            existing_role,
                            &mut rng,
                        )
                        .unwrap();
                    let handle = store
                        .insert(suite.clone(), Secret::new(original.clone()), existing_role, &mut rng)
                        .unwrap();

                    let err = store
                        .insert(suite.clone(), Secret::new(handle.clone()), new_role, &mut rng)
                        .unwrap_err();
                    assert_eq!(err.error_type, ErrorKind::InvalidParameter);
                    assert_eq!(store.len(), 2);
                    let retained = store.get(etype, &handle, existing_role).unwrap();
                    assert_eq!(retained.key.as_ref(), &original);
                    assert_eq!(retained.role, existing_role);
                    assert_eq!(
                        store.get(etype, &unrelated, existing_role).unwrap().key.as_ref(),
                        &vec![0x11; suite.cipher().key_size()]
                    );

                    let distinct = vec![0x72; suite.cipher().key_size()];
                    let next = store
                        .insert(suite.clone(), Secret::new(distinct.clone()), new_role, &mut rng)
                        .unwrap();
                    assert_eq!(store.len(), 3);
                    assert_ne!(next, handle);
                    assert_eq!(store.get(etype, &next, new_role).unwrap().key.as_ref(), &distinct);
                }
            }
        }
    }

    #[test]
    fn insertion_rejects_cross_role_raw_key_reuse_in_both_orders_without_retention() {
        for suite in [CipherSuite::Aes128CtsHmacSha196, CipherSuite::Aes256CtsHmacSha196] {
            for (existing_role, new_role) in [
                (KeyRole::TicketGranting, KeyRole::Service),
                (KeyRole::Service, KeyRole::TicketGranting),
            ] {
                let mut store = KeyStore::default();
                let mut rng = rng();
                let etype = i32::from(u8::from(&suite));
                let original = vec![0x31; suite.cipher().key_size()];
                let unrelated = store
                    .insert(
                        suite.clone(),
                        Secret::new(vec![0x11; suite.cipher().key_size()]),
                        existing_role,
                        &mut rng,
                    )
                    .unwrap();
                let handle = store
                    .insert(suite.clone(), Secret::new(original.clone()), existing_role, &mut rng)
                    .unwrap();

                let err = store
                    .insert(suite.clone(), Secret::new(original.clone()), new_role, &mut rng)
                    .unwrap_err();
                assert_eq!(err.error_type, ErrorKind::InvalidParameter);
                assert_eq!(store.len(), 2);
                assert_eq!(
                    store.get(etype, &handle, existing_role).unwrap().key.as_ref(),
                    &original
                );
                assert_eq!(
                    store.get(etype, &handle, new_role).err().unwrap().error_type,
                    ErrorKind::NoKerbKey
                );
                assert_eq!(
                    store.get(etype, &original, new_role).err().unwrap().error_type,
                    ErrorKind::NoKerbKey
                );
                assert_eq!(
                    store.get(etype, &unrelated, existing_role).unwrap().key.as_ref(),
                    &vec![0x11; suite.cipher().key_size()]
                );
                if existing_role == KeyRole::Service {
                    assert_eq!(
                        store.get(etype, &original, existing_role).unwrap().key.as_ref(),
                        &original
                    );
                }

                let distinct = vec![0x72; suite.cipher().key_size()];
                let next = store
                    .insert(suite.clone(), Secret::new(distinct.clone()), new_role, &mut rng)
                    .unwrap();
                assert_eq!(store.len(), 3);
                assert_eq!(store.get(etype, &next, new_role).unwrap().key.as_ref(), &distinct);
            }
        }
    }

    #[test]
    fn insertion_allows_same_role_duplicate_keys_with_distinct_handles() {
        for suite in [CipherSuite::Aes128CtsHmacSha196, CipherSuite::Aes256CtsHmacSha196] {
            for role in [KeyRole::TicketGranting, KeyRole::Service] {
                let mut store = KeyStore::default();
                let mut rng = rng();
                let etype = i32::from(u8::from(&suite));
                let original = vec![0x31; suite.cipher().key_size()];
                let first = store
                    .insert(suite.clone(), Secret::new(original.clone()), role, &mut rng)
                    .unwrap();
                let second = store
                    .insert(suite.clone(), Secret::new(original.clone()), role, &mut rng)
                    .unwrap();
                assert_eq!(store.len(), 2);
                assert_ne!(first, second);
                assert_ne!(first, original);
                assert_ne!(second, original);
                for handle in [&first, &second] {
                    let retained = store.get(etype, handle, role).unwrap();
                    assert_eq!(retained.key.as_ref(), &original);
                    assert_eq!(retained.role, role);
                }
                if role == KeyRole::Service {
                    assert_eq!(store.get(etype, &original, role).unwrap().key.as_ref(), &original);
                } else {
                    assert_eq!(
                        store.get(etype, &original, role).err().unwrap().error_type,
                        ErrorKind::NoKerbKey
                    );
                }
            }
        }
    }

    #[test]
    fn handle_generation_skips_live_handles_live_raw_keys_and_its_own_key() {
        for suite in [CipherSuite::Aes128CtsHmacSha196, CipherSuite::Aes256CtsHmacSha196] {
            for existing_role in [KeyRole::TicketGranting, KeyRole::Service] {
                let mut prediction = rng();
                let candidates: Vec<Vec<u8>> = (0..5)
                    .map(|_| {
                        let mut value = vec![0; suite.cipher().key_size()];
                        prediction.fill_bytes(&mut value);
                        value
                    })
                    .collect();
                for (index, candidate) in candidates.iter().enumerate() {
                    assert!(!candidates[..index].contains(candidate));
                }
                let mut store = KeyStore::default();
                let mut rng = rng();
                let etype = i32::from(u8::from(&suite));
                let unrelated = store
                    .insert(
                        suite.clone(),
                        Secret::new(vec![0x11; suite.cipher().key_size()]),
                        existing_role,
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(unrelated, candidates[0]);
                let first = store
                    .insert(
                        suite.clone(),
                        Secret::new(candidates[2].clone()),
                        existing_role,
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(first, candidates[1]);

                // Replay candidates that collide with a live handle, a live raw key, and the new key.
                rng = StdRng::seed_from_u64(1);
                let second = store
                    .insert(
                        suite.clone(),
                        Secret::new(candidates[3].clone()),
                        KeyRole::Service,
                        &mut rng,
                    )
                    .unwrap();
                assert_eq!(second, candidates[4]);
                assert_eq!(store.len(), 3);
                assert!(!store.contains_handle(&candidates[2]));
                assert!(!store.contains_handle(&candidates[3]));
                assert_eq!(
                    store.get(etype, &unrelated, existing_role).unwrap().key.as_ref(),
                    &vec![0x11; suite.cipher().key_size()]
                );
                assert_eq!(
                    store.get(etype, &first, existing_role).unwrap().key.as_ref(),
                    &candidates[2]
                );
                assert_eq!(
                    store.get(etype, &second, KeyRole::Service).unwrap().key.as_ref(),
                    &candidates[3]
                );
                assert_eq!(
                    store.get(etype, &candidates[3], KeyRole::Service).unwrap().key.as_ref(),
                    &candidates[3]
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_keys_and_bounds_size() {
        let mut store = KeyStore::default();
        let mut rng = rng();

        let err = store
            .insert(
                CipherSuite::Aes256CtsHmacSha196,
                Secret::new(vec![0; 16]),
                KeyRole::Service,
                &mut rng,
            )
            .unwrap_err();
        assert_eq!(err.error_type, ErrorKind::InvalidParameter);

        let err = store
            .insert(
                CipherSuite::Des3CbcSha1Kd,
                Secret::new(vec![0; 24]),
                KeyRole::Service,
                &mut rng,
            )
            .unwrap_err();
        assert_eq!(err.error_type, ErrorKind::AlgorithmMismatch);

        let mut last_handle = Vec::new();
        for n in 0..MAX_KEYS {
            last_handle = store
                .insert(
                    CipherSuite::Aes128CtsHmacSha196,
                    Secret::new(vec![1; 16]),
                    KeyRole::Service,
                    &mut rng,
                )
                .unwrap();
            assert_eq!(store.len(), n + 1);
        }
        assert_eq!(store.len(), MAX_KEYS);

        let err = store
            .insert(
                CipherSuite::Aes128CtsHmacSha196,
                Secret::new(vec![1; 16]),
                KeyRole::Service,
                &mut rng,
            )
            .unwrap_err();
        assert_eq!(err.error_type, ErrorKind::InsufficientMemory);
        assert_eq!(store.len(), MAX_KEYS);
        assert_eq!(
            store.get(17, &last_handle, KeyRole::Service).unwrap().key.as_ref(),
            &[1; 16]
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let mut store = KeyStore::default();
        store
            .insert(
                CipherSuite::Aes128CtsHmacSha196,
                Secret::new(vec![0x55; 16]),
                KeyRole::Service,
                &mut rng(),
            )
            .unwrap();

        assert_eq!(format!("{store:?}"), "KeyStore { len: 1 }");
    }
}
