use sspi::generator::NetworkRequest;
use sspi::network_client::NetworkClient;
use sspi::Result;

use crate::client_server::kerberos::kdc::KdcMock;

/// [NetworkClient] mock implementation.
///
/// Instead of sending Kerberos messages to the KDC service,
/// it redirects them to the KDC mock implementation.
pub struct NetworkClientMock {
    pub kdc: KdcMock,
}

impl NetworkClient for NetworkClientMock {
    fn send(&self, request: &NetworkRequest) -> Result<Vec<u8>> {
        let data = &request.data[4..];

        let response = if let Ok(as_req) = picky_asn1_der::from_bytes(data) {
            match self.kdc.as_exchange(as_req) {
                Ok(as_rep) => picky_asn1_der::to_vec(&as_rep)?,
                Err(krb_err) => picky_asn1_der::to_vec(&krb_err)?,
            }
        } else if let Ok(tgs_req) = picky_asn1_der::from_bytes(data) {
            match self.kdc.tgs_exchange(tgs_req) {
                Ok(tgs_rep) => picky_asn1_der::to_vec(&tgs_rep)?,
                Err(krb_err) => picky_asn1_der::to_vec(&krb_err)?,
            }
        } else {
            panic!("Invalid Kerberos message: {:?}", request.data);
        };

        let mut data = vec![0; 4 + response.len()];
        data[0..4].copy_from_slice(&u32::try_from(response.len()).unwrap().to_be_bytes());
        data[4..].copy_from_slice(&response);

        Ok(data)
    }
}
