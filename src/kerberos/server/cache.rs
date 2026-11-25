use std::collections::{BTreeMap, HashSet};
use std::hash::{Hash, Hasher};

use picky_asn1::wrapper::GeneralizedTimeAsn1;
use picky_krb::data_types::{Microseconds, PrincipalName};
use time::{Duration as TimeDuration, OffsetDateTime};

#[derive(Debug, Clone, Eq)]
pub(super) struct AuthenticatorCacheRecord {
    pub cname: PrincipalName,
    pub sname: PrincipalName,
    pub ctime: GeneralizedTimeAsn1,
    pub microseconds: Microseconds,
}

/// Compares the name components of a principal, ignoring the `name-type`.
///
/// [RFC 4120, section 6.2](https://www.rfc-editor.org/rfc/rfc4120#section-6.2): the name-type is a hint about how
/// to read the components, and the ticket is matched by its components only.
/// A `name-type` that is not encrypted must not make a replayed authenticator look new.
fn component_eq(name_1: &PrincipalName, name_2: &PrincipalName) -> bool {
    let names_1 = &name_1.name_string.0.0;
    let names_2 = &name_2.name_string.0.0;

    names_1.len() == names_2.len() && names_1.iter().zip(names_2.iter()).all(|(name_1, name_2)| name_1.0 == name_2.0)
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
        component_eq(&self.cname, &other.cname)
            && component_eq(&self.sname, &other.sname)
            && self.ctime == other.ctime
            && self.microseconds == other.microseconds
    }
}

impl Hash for AuthenticatorCacheRecord {
    fn hash<H: Hasher>(&self, state: &mut H) {
        fn hash_components<H: Hasher>(name: &PrincipalName, state: &mut H) {
            for name_string in &name.name_string.0.0 {
                name_string.0.hash(state);
            }
        }

        hash_components(&self.cname, state);
        hash_components(&self.sname, state);
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
pub struct AuthenticatorsCache {
    /// The authenticators by their `ctime`, so that the expired ones are removed from the front.
    by_time: BTreeMap<OffsetDateTime, HashSet<AuthenticatorCacheRecord>>,
    /// The longest clock skew of the contexts that share the cache.
    /// A record is kept for this long, so that no context forgets a record it still accepts.
    retention: TimeDuration,
}

impl AuthenticatorsCache {
    /// Remembers an authenticator, and returns `false` if it has already been remembered.
    ///
    /// The `now` must be read while the cache is locked, so that it is not older than the freshness check of the caller.
    /// The records older than the retention window are forgotten first.
    pub(super) fn insert(
        &mut self,
        record: AuthenticatorCacheRecord,
        ctime: OffsetDateTime,
        now: OffsetDateTime,
        max_time_skew: std::time::Duration,
    ) -> bool {
        let max_time_skew = TimeDuration::try_from(max_time_skew).unwrap_or(TimeDuration::MAX);
        self.retention = self.retention.max(max_time_skew);

        // INVARIANT: the cutoff is never later than `now`, so a record that a fresh authenticator may still match is kept.
        if let Some(cutoff) = now.checked_sub(self.retention) {
            self.by_time = self.by_time.split_off(&cutoff);
        }

        self.by_time.entry(ctime).or_default().insert(record)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.by_time.values().map(HashSet::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use picky_asn1::date::GeneralizedTime;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1};
    use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
    use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
    use time::{Duration as TimeDuration, OffsetDateTime};

    use super::{AuthenticatorCacheRecord, AuthenticatorsCache};

    const SKEW: Duration = Duration::from_secs(180);

    fn component(name: &str) -> KerberosStringAsn1 {
        KerberosStringAsn1::from(IA5String::from_string(name.to_owned()).unwrap())
    }

    fn principal(name_type: u8, name: &str) -> PrincipalName {
        PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![component(name)])),
        }
    }

    fn record(ctime: OffsetDateTime, sname_type: u8) -> AuthenticatorCacheRecord {
        AuthenticatorCacheRecord {
            cname: principal(NT_PRINCIPAL, "alice"),
            sname: principal(sname_type, "service"),
            ctime: GeneralizedTime::from(ctime).into(),
            microseconds: IntegerAsn1::from(vec![0]),
        }
    }

    // The name-type of the ticket is not encrypted: a changed one must not make a replay look new.
    #[test]
    fn a_changed_name_type_of_the_service_does_not_make_a_replay_new() {
        let now = OffsetDateTime::now_utc();
        let mut cache = AuthenticatorsCache::default();
        assert!(cache.insert(record(now, NT_SRV_INST), now, now, SKEW));

        let replay = cache.insert(record(now, NT_PRINCIPAL), now, now, SKEW);

        assert!(!replay);
    }

    // A context with a short skew must not forget a record that a context with a long skew still accepts.
    #[test]
    fn a_short_skew_does_not_forget_a_record_that_a_longer_skew_accepts() {
        let now = OffsetDateTime::now_utc();
        let old = now - TimeDuration::minutes(2);
        let mut cache = AuthenticatorsCache::default();
        assert!(cache.insert(record(old, NT_SRV_INST), old, old, SKEW));

        // The second context accepts a record up to 60 seconds old, so the first record stays inside its own window.
        cache.insert(record(now, NT_SRV_INST), now, now, Duration::from_secs(60));
        let replay = cache.insert(record(old, NT_SRV_INST), old, now, Duration::from_secs(60));

        assert!(!replay);
    }

    // A context whose clock is behind must not forget a record that a later context has just remembered.
    #[test]
    fn a_stale_clock_does_not_forget_a_record_of_a_later_context() {
        let later = OffsetDateTime::now_utc();
        let stale = later - TimeDuration::seconds(100);
        let future_ctime = later + TimeDuration::seconds(150);
        let mut cache = AuthenticatorsCache::default();
        assert!(cache.insert(record(future_ctime, NT_SRV_INST), future_ctime, later, SKEW));

        cache.insert(record(stale, NT_PRINCIPAL), stale, stale, SKEW);
        let replay = cache.insert(record(future_ctime, NT_SRV_INST), future_ctime, stale, SKEW);

        assert!(!replay);
    }

    #[test]
    fn records_older_than_the_skew_are_forgotten() {
        let now = OffsetDateTime::now_utc();
        let stale = now - TimeDuration::minutes(10);
        let mut cache = AuthenticatorsCache::default();
        assert!(cache.insert(record(stale, NT_SRV_INST), stale, stale, SKEW));

        cache.insert(record(now, NT_SRV_INST), now, now, SKEW);

        assert_eq!(cache.len(), 1);
    }
}
