use std::alloc::{alloc, Layout};
use std::slice::{from_raw_parts, from_raw_parts_mut};

use libc::c_char;
#[cfg(not(target_os = "windows"))]
use libc::c_uint;
#[cfg(target_os = "windows")]
use libc::c_ulong;
use num_traits::FromPrimitive;
use sspi::{SecurityBuffer, SecurityBufferType};

#[cfg(target_os = "windows")]
#[derive(Debug)]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: c_ulong,
    pub buffer_type: c_ulong,
    pub pv_buffer: *mut c_char,
}

#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: c_uint,
    pub buffer_type: c_uint,
    pub pv_buffer: *mut c_char,
}

pub type PSecBuffer = *mut SecBuffer;

#[derive(Debug)]
#[cfg(target_os = "windows")]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: c_ulong,
    pub c_buffers: c_ulong,
    pub p_buffers: PSecBuffer,
}

#[cfg(not(target_os = "windows"))]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: c_uint,
    pub c_buffers: c_uint,
    pub p_buffers: PSecBuffer,
}

pub type PSecBufferDesc = *mut SecBufferDesc;

#[allow(clippy::useless_conversion)]
pub(crate) unsafe fn p_sec_buffers_to_security_buffers(raw_buffers: &[SecBuffer]) -> Vec<SecurityBuffer> {
    raw_buffers
        .iter()
        .map(|raw_buffer| SecurityBuffer {
            buffer: from_raw_parts(raw_buffer.pv_buffer, raw_buffer.cb_buffer as usize)
                .iter()
                .map(|v| *v as u8)
                .collect(),
            buffer_type: SecurityBufferType::from_u32(raw_buffer.buffer_type.try_into().unwrap()).unwrap(),
        })
        .collect()
}

pub(crate) unsafe fn copy_to_c_sec_buffer(to_buffers: PSecBuffer, from_buffers: &[SecurityBuffer], allocate: bool) {
    let to_buffers = from_raw_parts_mut(to_buffers as *mut SecBuffer, from_buffers.len());
    for i in 0..from_buffers.len() {
        let buffer = &from_buffers[i];
        let buffer_size = buffer.buffer.len();
        to_buffers[i].cb_buffer = buffer_size.try_into().unwrap();
        if allocate {
            let memory_layout = Layout::from_size_align_unchecked(buffer_size as usize, 8);
            to_buffers[i].pv_buffer = alloc(memory_layout) as *mut c_char;
        }
        let to_buffer = from_raw_parts_mut(to_buffers[i].pv_buffer, buffer_size);
        to_buffer.copy_from_slice(from_raw_parts(buffer.buffer.as_ptr() as *const c_char, buffer_size));
    }
}
