use std::ffi::c_void;

pub type ScardStatus = u32;
pub type LpStr = *mut u8;
pub type LpCStr = *const u8;
pub type LpDword = *mut u32;
pub type LpWStr = *mut u16;
pub type LpCWStr = *const u16;
pub type LpCByte = *const u8;
pub type LpCVoid = *const c_void;
pub type LpVoid = *mut c_void;
pub type Handle = *mut c_void;

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u32,
    pub data3: u32,
    pub data4: [u8; 8],
}
pub type LpCGuid = *const Guid;
pub type LpGuid = *mut Guid;

pub type ScardContext = usize;
pub type LpScardContext = *mut ScardContext;

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