use std::slice::{from_raw_parts, from_raw_parts_mut};

use libc::c_char;
use sspi::{Error, ErrorKind, Result, SecurityBuffer, SecurityBufferType};

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
            buffer: if raw_buffer.pv_buffer.is_null() {
                Vec::new()
            } else {
                // SAFETY: `pv_buffer` is not null (checked above). All other guarantees must be provided by the user.
                unsafe {
                    from_raw_parts(raw_buffer.pv_buffer, raw_buffer.cb_buffer as usize)
                        .iter()
                        .map(|v| *v as u8)
                        .collect()
                }
            },
            buffer_type: SecurityBufferType::try_from(u32::try_from(raw_buffer.buffer_type).unwrap()).unwrap(),
        })
        .collect()
}

pub(crate) unsafe fn copy_to_c_sec_buffer(
    to_buffers: PSecBuffer,
    from_buffers: &[SecurityBuffer],
    allocate: bool,
) -> Result<()> {
    if to_buffers.is_null() {
        return Err(Error::new(ErrorKind::InvalidParameter, "to_buffers cannot be null"));
    }

    // SAFETY: `to_buffers` is not null. We've checked for this above.
    let to_buffers = unsafe { from_raw_parts_mut(to_buffers, from_buffers.len()) };
    for i in 0..from_buffers.len() {
        let buffer = &from_buffers[i];
        let buffer_size = buffer.buffer.len();
        to_buffers[i].cb_buffer = buffer_size.try_into().unwrap();
        to_buffers[i].buffer_type = buffer.buffer_type.into();
        if allocate || to_buffers[i].pv_buffer.is_null() {
            // SAFETY: Memory allocation should be safe. Also, we check `pv_buffer` for the null below.
            to_buffers[i].pv_buffer = unsafe { libc::malloc(buffer_size) as *mut c_char };

            if to_buffers[i].pv_buffer.is_null() {
                return Err(Error::new(
                    ErrorKind::InsufficientMemory,
                    format!("cannot allocate {buffer_size} bytes"),
                ));
            }
        }

        // SAFETY: `pv_buffer` is not null. We've checked for this above.
        let to_buffer = unsafe { from_raw_parts_mut(to_buffers[i].pv_buffer, buffer_size) };

        // SAFETY: We create a valid pointer, so it's safe to call the function.
        to_buffer.copy_from_slice(unsafe { from_raw_parts(buffer.buffer.as_ptr() as *const c_char, buffer_size) });
    }

    Ok(())
}
