/// Emulated smart card PIN code.
pub const WINSCARD_PIN_ENV: &str = "WINSCARD_SMARTCARD_PIN";
/// Path to the user certificate to be used in emulated smart card.
pub const WINSCARD_CERT_PATH_ENV: &str = "WINSCARD_CERTIFICATE_FILE_PATH";
/// Smart card certificate data.
///
/// *Note.* The variable value should be one-line base64 string containing ASN1 DER certificate data.
pub const WINSCARD_CERT_DATA_ENV: &str = "WINSCARD_CERTIFICATE_FILE_DATA";
/// Path to the certificate private key.
pub const WINSCARD_PK_PATH_ENV: &str = "WINSCARD_PRIVATE_KEY_FILE_PATH";
/// Smart card private key data.
///
/// *Note.* The variable value should be one-line base64 string containing ASN1 DER private key.
pub const WINSCARD_PK_DATA_ENV: &str = "WINSCARD_PRIVATE_KEY_FILE_DATA";
/// Emulated smart card container name.
pub const WINSCARD_CONTAINER_NAME_ENV: &str = "WINSCARD_SMARTCARD_CONTAINER_NAME";
/// Emulated smart card reader name.
pub const WINSCARD_READER_NAME_ENV: &str = "WINSCARD_SMARTCARD_READER_NAME";
