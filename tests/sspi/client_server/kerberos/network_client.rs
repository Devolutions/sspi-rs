use sspi::generator::NetworkRequest;
use sspi::network_client::NetworkClient;
use sspi::{ErrorKind, Result};

use crate::client_server::kerberos::kdc::KdcMock;

/// [NetworkClient] mock implementation.
///
/// Instead of sending Kerberos messages to the KDC service,
/// it redirects them to the KDC mock implementation.
pub(crate) struct NetworkClientMock {
    pub kdc: KdcMock,
}

impl NetworkClient for NetworkClientMock {
    fn send(&self, request: &NetworkRequest) -> Result<Vec<u8>> {
        let data = &request.data[4..];

        let response = self.kdc.exchange(data)?;

        let mut data = vec![0; 4 + response.len()];
        data[0..4].copy_from_slice(&u32::try_from(response.len()).unwrap().to_be_bytes());
        data[4..].copy_from_slice(&response);

        Ok(data)
    }
}

/// [NetworkClient] that returns an error for every request.
///
/// The purpose of this specific mock is to test Kerberos to NTLM fallback in Negotiate (SPNEGO).
pub(crate) struct FailedNetworkClientMock {
    /// Error kind to return for every request.
    pub kind: ErrorKind,
}

impl NetworkClient for FailedNetworkClientMock {
    fn send(&self, _request: &NetworkRequest) -> Result<Vec<u8>> {
        Err(sspi::Error::new(self.kind, "error from mock network client"))
    }
}
