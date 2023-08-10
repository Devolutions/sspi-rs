use std::slice::{from_raw_parts, from_raw_parts_mut};

use libc::c_char;
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::{SecurityBuffer, SecurityBufferType};

#[derive(Debug)]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: u32,
    pub buffer_type: u32,
    pub pv_buffer: *mut c_char,
}

pub type PSecBuffer = *mut SecBuffer;

#[derive(Debug)]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: u32,
    pub c_buffers: u32,
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
        to_buffers[i].buffer_type = buffer.buffer_type.to_u32().unwrap();
        if allocate || to_buffers[i].pv_buffer.is_null() {
            to_buffers[i].pv_buffer = libc::malloc(buffer_size) as *mut c_char;
        }
        let to_buffer = from_raw_parts_mut(to_buffers[i].pv_buffer, buffer_size);
        to_buffer.copy_from_slice(from_raw_parts(buffer.buffer.as_ptr() as *const c_char, buffer_size));
    }
}
