use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use picky_asn1::wrapper::GeneralizedTimeAsn1;
use picky_krb::data_types::{Microseconds, PrincipalName};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthenticatorCacheRecord {
    pub cname: PrincipalName,
    pub sname: PrincipalName,
    pub ctime: GeneralizedTimeAsn1,
    pub microseconds: Microseconds,
}

impl Hash for AuthenticatorCacheRecord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        fn hash_principal_name<H: Hasher>(name: &PrincipalName, state: &mut H) {
            name.name_type.0.hash(state);
            for name_string in &name.name_string.0 .0 {
                name_string.0.hash(state);
            }
        }

        hash_principal_name(&self.cname, state);
        hash_principal_name(&self.sname, state);
        self.ctime.hash(state);
        self.microseconds.hash(state);
    }
}

pub type AuthenticatorsCache = HashSet<AuthenticatorCacheRecord>;
