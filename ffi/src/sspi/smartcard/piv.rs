use std::ffi::CStr;
use std::ptr::null_mut;

use sspi::{Error, ErrorKind, Result};
use winscard::tlv_tags;

use crate::winscard::pcsc_lite::initialize_pcsc_lite_api;

/// Possible PIV certificates labels and their corresponding PIV tags.
/// 
/// Certificate labels are used to determine the certificate PIV tag.
/// All values are taken from the NIST SP 800-73pt1-5 specification:
/// 4.3 Object Identifiers Table 3. Object identifiers of the PIV data objects for interoperable use.
#[rustfmt::skip]
const CERTIFICATE_LABELS: &[(&[u8], &[u8])] = &[
    // X.509 Certificate for PIV Authentication 2.16.840.1.101.3.7.2.1.1 '5FC105' M
    (b"X.509 Certificate for PIV Authentication", &[0x5f, 0xc1, 0x05]),
    // X.509 Certificate for Digital Signature 2.16.840.1.101.3.7.2.1.0 '5FC10A' C
    (b"X.509 Certificate for Digital Signature", &[0x5f, 0xc1, 0x0a]),
    // X.509 Certificate for Key Management 2.16.840.1.101.3.7.2.1.2 '5FC10B' C
    (b"X.509 Certificate for Key Management", &[0x5f, 0xc1, 0x0b]),
    // X.509 Certificate for Card Authentication 2.16.840.1.101.3.7.2.5.0 '5FC101' M
    (b"X.509 Certificate for Card Authentication", &[0x5f, 0xc1, 0x01]),
];

/// SELECT APDU command.
/// 
/// The SELECT card command sets the currently selected application. More info:
/// * NIST.SP.800-73-4, Part 2, Section 3.1.1.
/// * NIST.SP.800-73-4, Part 2, Section 2.2.
#[rustfmt::skip]
const APDU_PIV_SELECT_AID: &[u8] = &[
    0x00, // CLA
    0xa4, // INS
    0x04, // P1
    0x00, // P2
    0x09, // Lc: Length of application identifier.
    // Application identifier: AID of the PIV Card Application using the full AID.
    //
    // 2. PIV Card Application Namespaces. 2.2 PIV Card Application AID.
    // The Application IDentifier (AID) of the PIV Card Application shall be:
    0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
    0x00, // Le
];
/// GET DATA Card Command.
///
/// The GET DATA card command retrieves the data content of the single data object whose tag is given in the data field. More info:
/// * NIST.SP.800-73-4, Part 2, Section 3.1.2.
/// * NIST.SP.800-73-4, Part 2, Section 2.2.
#[rustfmt::skip]
const APDU_PIV_GET_CHUID: &[u8] = &[
    0x00, // CLA: '00' or '0C' for secure messaging.
    0xcb, // INS
    0x3f, // P1
    0xff, // P2
    0x05, // Lc: Length of data field*.
        // 3.1.2. Table 6. Data Objects in the Data Field of the GET DATA Card Command.
        // '5C' is the only one available data object for the GET DATA Card Command.
        0x5c, 0x03,
        // 4.3 Object Identifiers Table 3. Object identifiers of the PIV data objects for interoperable use.
        // Card Holder Unique Identifier 2.16.840.1.101.3.7.2.48.0 '5FC102' M.
        0x5f, 0xc1, 0x02,
    0x00 // Le
];

fn chuid_to_container_name(chuid: &[u8], tag: &[u8]) -> Result<String> {
    let chuid_len = chuid.len();

    // Check the Error Detection Code:
    if chuid[chuid_len - 2] != tlv_tags::ERROR_DETECTION_CODE || chuid[chuid_len - 1] != 0 {
        panic!("bad error detenction code");
    }

    let mut skip = 0;
    // Data tag and len
    skip += 2;
    // FASC-N tag and len
    skip += 2;
    // FASC-N data
    skip += usize::from(chuid[skip - 1]);
    // GUID tag and len
    skip += 2;

    let guid = &chuid[skip..skip + 16];

    println!("guid: {guid:?}");

    let container_name = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[3], guid[2], guid[1], guid[0],
        guid[5], guid[4],
        guid[7], guid[6],
        guid[8], guid[9],
        guid[10], guid[11],
        guid[12], tag[0], tag[1], tag[2]
    );

    Ok(container_name)
}

fn extract_piv_container_name(reader: &str, tag: &[u8]) -> Result<String> {
    println!("{reader}");

    let pcsc = initialize_pcsc_lite_api().unwrap();

    let mut context = 0;
    let result = unsafe { (pcsc.SCardEstablishContext)(0, null_mut(), null_mut(), &mut context) };
    if result != 0 {
        panic!();
    }

    let mut reader = reader.as_bytes().to_vec();
    reader.push(0);
    let reader = CStr::from_bytes_until_nul(&reader).unwrap();

    let mut card = 0;
    let mut active_protocol = 0;
    let result = unsafe {
        (pcsc.SCardConnect)(
            context,
            reader.as_ptr() as *const _,
            0x0002,
            0x0001 | 0x0002,
            &mut card,
            &mut active_protocol,
        )
    };

    if result != 0 {
        unsafe { (pcsc.SCardReleaseContext)(context) };
        panic!();
    }

    println!("Connected!");

    let send_pci = match active_protocol {
        0x0001 => pcsc.g_rgSCardT0Pci,
        0x0002 => pcsc.g_rgSCardT1Pci,
        0x0004 => pcsc.g_rgSCardRawPci,
        _ => panic!("invalid active protocol: {}", active_protocol),
    };

    let mut receive_buffer = [0; 258];
    let mut receive_buffer_len = 258;
    let result = unsafe {
        (pcsc.SCardTransmit)(
            card,
            send_pci,
            APDU_PIV_SELECT_AID.as_ptr(),
            APDU_PIV_SELECT_AID.len() as _,
            null_mut(),
            receive_buffer.as_mut_ptr(),
            &mut receive_buffer_len,
        )
    };
    println!("res: {result}, len: {receive_buffer_len}");

    let output_apdu = &receive_buffer[0..receive_buffer_len as usize];
    println!("oapdu: {output_apdu:?}");

    if result != 0 {
        unsafe { (pcsc.SCardDisconnect)(card, 0) };
        unsafe { (pcsc.SCardReleaseContext)(context) };

        panic!();
    }

    println!("t1 finished!");

    receive_buffer_len = 258;
    let result = unsafe {
        (pcsc.SCardTransmit)(
            card,
            send_pci,
            APDU_PIV_GET_CHUID.as_ptr(),
            APDU_PIV_GET_CHUID.len() as _,
            null_mut(),
            receive_buffer.as_mut_ptr(),
            &mut receive_buffer_len,
        )
    };
    println!("res: {result}, len: {receive_buffer_len}");

    let output_apdu = &receive_buffer[0..receive_buffer_len as usize];
    println!("oapdu: {output_apdu:?}");

    if result != 0 {
        unsafe { (pcsc.SCardDisconnect)(card, 0) };
        unsafe { (pcsc.SCardReleaseContext)(context) };

        panic!();
    }

    println!("t2 finished!");

    let chuid = &output_apdu[0..output_apdu.len() - 2];

    unsafe { (pcsc.SCardDisconnect)(card, 0) };
    unsafe { (pcsc.SCardReleaseContext)(context) };

    chuid_to_container_name(chuid, tag)
}

pub fn try_get_piv_container_name(reader: &str, certificate_label: &[u8]) -> Result<String> {
    for (label, tag) in CERTIFICATE_LABELS {
        if *label == certificate_label {
            return extract_piv_container_name(reader, tag);
        }
    }

    Err(Error::new(ErrorKind::NoCredentials, "certificate label not recignized"))
}

#[cfg(test)]
mod tests {
    use crate::sspi::smartcard::piv::{chuid_to_container_name, try_get_piv_container_name};

    #[test]
    fn ctname_ext() {
        let container_name =
            try_get_piv_container_name("Yubico YubiKey FIDO+CCID", b"X.509 Certificate for PIV Authentication")
                .unwrap();
        println!("{container_name}");
    }
}
