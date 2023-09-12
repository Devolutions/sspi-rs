pub mod functions;

use crate::common::{Handle, Bool, LpVoid, LpWStr, LpStr, LpCStr, LpCWStr, LpCGuid};

pub type ScardStatus = u32;

pub type ScardContext = usize;
pub type LpScardContext = *mut ScardContext;

pub type ScardHandle = usize;
pub type LpScardHandle = *mut ScardHandle;
pub type Hwnd = Handle;
pub type Hicon = Handle;
// https://docs.rs/winapi/latest/winapi/um/winscard/type.LPOCNCHKPROC.html
pub type LpOcnChkProc = Option<unsafe extern "system" fn(_: ScardContext, _: ScardHandle, _: LpVoid) -> Bool>;
// https://docs.rs/winapi/latest/winapi/um/winscard/type.LPOCNCONNPROCA.html
pub type LpOcnConnProcA = Option<unsafe extern "system" fn(_: ScardContext, _: LpStr, _: LpStr, _: LpVoid) -> ScardHandle>;
// https://docs.rs/winapi/latest/winapi/um/winscard/type.LPOCNCONNPROCW.html
pub type LpOcnConnProcW = Option<unsafe extern "system" fn(_: ScardContext, _: LpWStr, _: LpWStr, _: LpVoid) -> ScardHandle>;
// https://docs.rs/winapi/latest/winapi/um/winscard/type.LPOCNDSCPROC.html
pub type LpOcnDscProc = Option<unsafe extern "system" fn(_: ScardContext, _: ScardHandle, _: LpVoid)>;

#[repr(C)]
pub struct ScardReaderStateA {
    sz_reader: LpCStr,
    pv_user_data: LpVoid,
    dw_current_state: u32,
    dw_event_state: u32,
    cb_atr: u32,
    rgb_atr: [u8; 36],
}

pub type LpScardReaderStateA = *mut ScardReaderStateA;

#[repr(C)]
pub struct ScardReaderStateW {
    sz_reader: LpCWStr,
    pv_user_data: LpVoid,
    dw_current_state: u32,
    dw_event_state: u32,
    cb_atr: u32,
    rgb_atr: [u8; 36],
}

pub type LpScardReaderStateW = *mut ScardReaderStateW;

#[repr(C)]
pub struct ScardAtrMask {
    cb_atr: u32,
    rgb_atr: [u8; 36],
    rgb_mask: [u8; 36],
}

pub type LpScardAtrMask = *mut ScardAtrMask;

#[repr(C)]
pub struct ScardIoRequest {
    dw_protocol: u32,
    cb_pci_length: u32,
}

pub type LpScardIoRequest = *mut ScardIoRequest;

#[repr(C)]
pub struct OpenCardSearchCriteriaA {
    dw_struct_size: u32,
    lpstr_group_names: LpStr,
    n_max_group_names: u32,
    rgguid_interfaces: LpCGuid,
    cguid_interfaces: u32,
    lpstr_card_names: LpStr,
    n_max_card_names: u32,
    lpfn_check: LpOcnChkProc,
    lpfn_connect: LpOcnConnProcA,
    lpfn_disconnect: LpOcnChkProc,
    pv_user_data: LpVoid,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
}

pub type LpOpenCardSearchCriteriaA = *mut OpenCardSearchCriteriaA;

#[repr(C)]
pub struct OpenCardSearchCriteriaW {
    dw_struct_size: u32,
    lpstr_group_names: LpWStr,
    n_max_group_names: u32,
    rgguid_interfaces: LpCGuid,
    cguid_interfaces: u32,
    lpstr_card_names: LpWStr,
    n_max_card_names: u32,
    lpfn_check: LpOcnChkProc,
    lpfn_connect: LpOcnConnProcW,
    lpfn_disconnect: LpOcnChkProc,
    pv_user_data: LpVoid,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
}

pub type LpOpenCardSearchCriteriaW = *mut OpenCardSearchCriteriaW;

#[repr(C)]
pub struct OpenCardNameExA {
    dw_struct_size: u32,
    h_scard_context: ScardContext,
    hwnd_owner: Hwnd,
    dw_flags: u32,
    lpstr_title: LpCStr,
    lpstr_search_sesc: LpCStr,
    h_icon: Hicon,
    p_open_card_search_criteria: LpOpenCardSearchCriteriaA,
    lpfn_connect: LpOcnConnProcA,
    pv_user_data: LpVoid,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    lpstr_rdr: LpStr,
    n_max_rdr: u32,
    lpstr_card: LpStr,
    n_max_card: u32,
    dw_active_protocol: u32,
    h_card_handle: ScardHandle,
}

pub type LpOpenCardNameExA = *mut OpenCardNameExA;

#[repr(C)]
pub struct OpenCardNameExW {
    dw_struct_size: u32,
    h_scard_context: ScardContext,
    hwnd_owner: Hwnd,
    dw_flags: u32,
    lpstr_title: LpCWStr,
    lpstr_search_sesc: LpCWStr,
    h_icon: Hicon,
    p_open_card_search_criteria: LpOpenCardSearchCriteriaW,
    lpfn_connect: LpOcnConnProcW,
    pv_user_data: LpVoid,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    lpstr_rdr: LpStr,
    n_max_rdr: u32,
    lpstr_card: LpStr,
    n_max_card: u32,
    dw_active_protocol: u32,
    h_card_handle: ScardHandle,
}

pub type LpOpenCardNameExW = *mut OpenCardNameExW;

#[repr(C)]
pub struct OpenCardNameA {
    dw_struct_size: u32,
    hwnd_owner: Hwnd,
    h_scard_context: ScardContext,
    lpstr_group_names: LpStr,
    n_max_group_names: u32,
    lpstr_card_names: LpStr,
    n_max_card_names: u32,
    rgguid_interfaces: LpCGuid,
    cguid_interfaces: u32,
    lpstr_rdr: LpStr,
    n_max_rdr: u32,
    lpstr_card: LpStr,
    n_max_card: u32,
    lpstr_title: u32,
    dw_flags: u32,
    pv_user_data: LpVoid,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    dw_active_protocol: u32,
    lpfn_connect: LpOcnConnProcA,
    lpfn_check: LpOcnChkProc,
    lpfn_disconnect: LpOcnDscProc,
    h_card_handle: ScardHandle,
}

pub type LpOpenCardNameA = *mut OpenCardNameA;

#[repr(C)]
pub struct OpenCardNameW {
    dw_struct_size: u32,
    hwnd_owner: Hwnd,
    h_scard_context: ScardContext,
    lpstr_group_names: LpWStr,
    n_max_group_names: u32,
    lpstr_card_names: LpWStr,
    n_max_card_names: u32,
    rgguid_interfaces: LpCGuid,
    cguid_interfaces: u32,
    lpstr_rdr: LpStr,
    n_max_rdr: u32,
    lpstr_card: LpStr,
    n_max_card: u32,
    lpstr_title: u32,
    dw_flags: u32,
    pv_user_data: LpVoid,
    dw_share_mode: u32,
    dw_preferred_protocols: u32,
    dw_active_protocol: u32,
    lpfn_connect: LpOcnConnProcW,
    lpfn_check: LpOcnChkProc,
    lpfn_disconnect: LpOcnDscProc,
    h_card_handle: ScardHandle,
}

pub type LpOpenCardNameW = *mut OpenCardNameW;