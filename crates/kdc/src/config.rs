use secret::Secret;

/// Domain user credentials.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct DomainUser {
    /// Username in FQDN format (e.g. "pw13@example.com").
    pub username: String,
    /// User password.
    pub password: Secret<String>,
    /// Salt for generating the user's key.
    ///
    /// Usually, it is equal to `{REALM}{username}` (e.g. "EXAMPLEpw13").
    pub salt: String,
}

/// Kerberos server config
///
/// This config is used to configure the Kerberos server during RDP proxying.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct KerberosServer {
    /// KDC and Kerberos Application Server realm.
    ///
    /// For example, `cd9bee03-b0aa-49dd-bad7-568b595c8024.jet`.
    pub realm: String,
    /// Users credentials inside fake KDC.
    pub users: Vec<DomainUser>,
    /// The maximum allowed time difference between client and proxy clocks.
    ///
    /// The value must be in seconds.
    pub max_time_skew: u64,
    /// krbtgt service key.
    ///
    /// This key is used to encrypt/decrypt TGT tickets.
    pub krbtgt_key: Secret<Vec<u8>>,
    /// Ticket decryption key.
    ///
    /// This key is used to decrypt the TGS ticket sent by the client. If you do not plan
    /// to use Kerberos U2U authentication, then the `ticket_decryption_key` is required.
    pub ticket_decryption_key: Option<Secret<Vec<u8>>>,
    /// The domain user credentials for the Kerberos U2U authentication.
    ///
    /// This field is needed only for Kerberos User-to-User authentication. If you do not plan
    /// to use Kerberos U2U, do not specify it.
    pub service_user: Option<DomainUser>,
}

#[cfg(test)]
mod tests {
    use super::{DomainUser, KerberosServer};

    #[test]
    fn debug_output_does_not_contain_secrets() {
        let user = DomainUser {
            username: "user@example.com".to_owned(),
            password: "p4ssw0rd-9f2c".to_owned().into(),
            salt: "EXAMPLE.COMuser".to_owned(),
        };
        let config = KerberosServer {
            realm: "EXAMPLE.COM".to_owned(),
            users: vec![user.clone()],
            max_time_skew: 300,
            krbtgt_key: vec![0xAA; 32].into(),
            ticket_decryption_key: Some(vec![0xBB; 32].into()),
            service_user: Some(user),
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("p4ssw0rd-9f2c"), "{debug}");
        // The bytes would be printed as decimal numbers.
        assert!(!debug.contains("170"), "{debug}");
        assert!(!debug.contains("187"), "{debug}");
    }
}
