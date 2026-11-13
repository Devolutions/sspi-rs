//! Unit tests for the request validators shared by the AS and TGS exchanges.

use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, GeneralizedTimeAsn1, IntegerAsn1};
use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
use rstest::rstest;
use time::OffsetDateTime;

use crate::{validate_request_from_and_till, validate_request_sname};

fn name(name_type: u8, names: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            names
                .iter()
                .map(|n| KerberosStringAsn1::from(IA5String::from_string((*n).to_owned()).unwrap()))
                .collect::<Vec<_>>(),
        )),
    }
}

fn at(offset_secs: i64) -> GeneralizedTimeAsn1 {
    GeneralizedTimeAsn1::from(GeneralizedTime::from(
        OffsetDateTime::now_utc() + time::Duration::seconds(offset_secs),
    ))
}

// A service name is accepted when it is an NT-SRV-INST name with exactly the expected components.
// The components are compared case-insensitively, the way Active Directory does.
#[rstest]
// oracle: mutant a service name with the expected components is rejected
#[case::exact(NT_SRV_INST, &["krbtgt", "EXAMPLE.COM"], true)]
// oracle: mutant the components are compared case-sensitively
#[case::case_insensitive(NT_SRV_INST, &["KRBTGT", "example.com"], true)]
// oracle: mutant the name type is not checked
#[case::wrong_name_type(NT_PRINCIPAL, &["krbtgt", "EXAMPLE.COM"], false)]
// oracle: mutant the first component is not checked
#[case::wrong_first_component(NT_SRV_INST, &["host", "EXAMPLE.COM"], false)]
// oracle: mutant the second component is not checked
#[case::wrong_second_component(NT_SRV_INST, &["krbtgt", "OTHER.COM"], false)]
// oracle: mutant a name with a missing component is accepted
#[case::missing_component(NT_SRV_INST, &["krbtgt"], false)]
// oracle: mutant a name with an extra component is accepted
#[case::extra_component(NT_SRV_INST, &["krbtgt", "EXAMPLE.COM", "extra"], false)]
fn sname_validation(#[case] name_type: u8, #[case] names: &[&str], #[case] valid: bool) {
    let result = validate_request_sname(&name(name_type, names), &["krbtgt", "EXAMPLE.COM"]);

    assert_eq!(result.is_ok(), valid);
}

#[test]
fn absent_start_time_means_now() {
    // oracle: spec RFC 4120 §3.1.3 - an absent starttime is set to the current time of the KDC.
    let (auth_time, _) = validate_request_from_and_till(None, &at(600), 300).unwrap();

    assert!((OffsetDateTime::now_utc() - auth_time).abs() < time::Duration::seconds(5));
}

#[test]
fn start_time_within_skew_is_treated_as_now() {
    // oracle: spec RFC 4120 §3.1.3 - a starttime inside the window of acceptable clock skew
    // is replaced with the current time of the KDC.
    let (auth_time, _) = validate_request_from_and_till(Some(&at(100)), &at(600), 300).unwrap();

    assert!((OffsetDateTime::now_utc() - auth_time).abs() < time::Duration::seconds(5));
}
