use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use picky_asn1::wrapper::GeneralizedTimeAsn1;
use picky_krb::data_types::{Microseconds, PrincipalName};

#[derive(Debug, Clone, Eq)]
pub(super) struct AuthenticatorCacheRecord {
    pub cname: PrincipalName,
    pub sname: PrincipalName,
    pub ctime: GeneralizedTimeAsn1,
    pub microseconds: Microseconds,
}

// https://doc.rust-lang.org/std/hash/trait.Hash.html#hash-and-eq
// > When implementing both `Hash` and `Eq`, it is important that the following property holds:
// ```
// k1 == k2 -> hash(k1) == hash(k2)
// ```
// The `PrincipalName` implements the `PartialEq` trait but does not implement the `Hash` trait.
// We implement `PartialEq` manually to make sure we follow required properties.
impl PartialEq for AuthenticatorCacheRecord {
    fn eq(&self, other: &Self) -> bool {
        fn compare_principal_names(name_1: &PrincipalName, name_2: &PrincipalName) -> bool {
            if name_1.name_type.0 != name_2.name_type.0 {
                return false;
            }

            let names_1 = &name_1.name_string.0.0;
            let names_2 = &name_2.name_string.0.0;

            if names_1.len() != names_2.len() {
                return false;
            }

            for (name_1, name_2) in names_1.iter().zip(names_2.iter()) {
                if name_1.0 != name_2.0 {
                    return false;
                }
            }

            true
        }

        compare_principal_names(&self.cname, &other.cname)
            && compare_principal_names(&self.sname, &other.sname)
            && self.ctime == other.ctime
            && self.microseconds == other.microseconds
    }
}

impl Hash for AuthenticatorCacheRecord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        fn hash_principal_name<H: Hasher>(name: &PrincipalName, state: &mut H) {
            name.name_type.0.hash(state);
            for name_string in &name.name_string.0.0 {
                name_string.0.hash(state);
            }
        }

        hash_principal_name(&self.cname, state);
        hash_principal_name(&self.sname, state);
        self.ctime.hash(state);
        self.microseconds.hash(state);
    }
}

/// The authenticators the acceptor has seen within the allowed clock skew.
///
/// [Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3):
/// the acceptor must remember them to detect a replayed AP-REQ.
/// Share one cache, behind an `Arc<Mutex<_>>`, between all contexts that serve the same service.
/// A replay against a context that has another cache goes undetected.
#[derive(Debug, Default, Clone)]
pub struct AuthenticatorsCache(HashSet<AuthenticatorCacheRecord>);

impl AuthenticatorsCache {
    pub(super) fn retain(&mut self, predicate: impl FnMut(&AuthenticatorCacheRecord) -> bool) {
        self.0.retain(predicate);
    }

    /// Remembers the authenticator. Returns `false` if it has already been seen.
    pub(super) fn insert(&mut self, record: AuthenticatorCacheRecord) -> bool {
        self.0.insert(record)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
}
