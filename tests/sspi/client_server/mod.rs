#![cfg(feature = "network_client")] // The network_client feature is required for the client_server tests.

mod credssp;
mod kerberos;
mod ntlm;

// TODO(@TheBestTvarynka): add Kerberos test when the Kerberos server-side is implemented.
