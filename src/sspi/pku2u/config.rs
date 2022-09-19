use picky_asn1_x509::Certificate;

#[derive(Debug, Clone)]
pub struct Pku2uConfig {
    pub p2p_certificate: Certificate,
    pub p2p_ca_certificate: Certificate,
}

#[cfg(windows)]
impl Default for Pku2uConfig {
    fn default() -> Self {
        // Self {
        //     p2p_certificate: todo!(),
        //     p2p_ca_certificate: todo!(),
        // }
        todo!()
    }
}

#[cfg(not(windows))]
impl Default for Pku2uConfig {
    fn default() -> Self {
        Self {
            p2p_certificate: todo!(),
            p2p_ca_certificate: todo!(),
        }
    }
}
