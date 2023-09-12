use std::ffi::c_void;

pub type LpStr = *mut u8;
pub type LpCStr = *const u8;
pub type LpDword = *mut u32;
pub type LpWStr = *mut u16;
pub type LpCWStr = *const u16;
pub type LpCByte = *const u8;
pub type LpByte = *mut u8;
pub type LpCVoid = *const c_void;
pub type LpVoid = *mut c_void;
pub type Handle = *mut c_void;
pub type Bool = i32;

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u32,
    pub data3: u32,
    pub data4: [u8; 8],
}
pub type LpCGuid = *const Guid;
pub type LpGuid = *mut Guid;
pub type Uuid = Guid;
pub type LpUuid = *mut Uuid;