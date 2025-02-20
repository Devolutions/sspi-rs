use ffi_types::common::{Dword, LpByte, LpCByte, LpCStr, LpCUuid};

#[instrument(skip_all)]
#[no_mangle]
pub extern "system" fn DpapiProtectSecret(
    secret: LpCByte,
    secret_len: Dword,
    sid: LpCStr,
    root_key: LpCUuid,
    server: LpCStr,
    username: LpCStr,
    password: LpCStr,
    computer_name: LpCStr,
    blob: *mut LpByte,
) -> u32 {
    0
}

#[instrument(skip_all)]
#[no_mangle]
pub extern "system" fn DpapiUnprotectSecret(
    blob: LpCByte,
    server: LpCStr,
    username: LpCStr,
    password: LpCStr,
    computer_name: LpCStr,
) -> u32 {
    0
}

#[instrument(skip_all)]
#[no_mangle]
pub extern "system" fn DpapiFree(blob: *mut LpByte) -> u32 {
    0
}
