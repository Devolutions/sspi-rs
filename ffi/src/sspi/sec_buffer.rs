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

/// # Safety:
///
/// * The input pointer can be null.
/// * If the input pointer is not null, then it must point to the valid [SecBufferDesc] structure. Moreover,
///   the user have to ensure that the pointer is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion).
pub unsafe fn sec_buffer_desc_to_security_buffers(p_input: PSecBufferDesc) -> Vec<SecurityBuffer> {
    // SAFETY:
    // The user must upheld the [SecBufferDesc] validity and make sure that the pointer is convertible to a reference.
    if let Some(input) = unsafe { p_input.as_ref() } {
        let p_buffers = input.p_buffers;
        let c_buffers = input.c_buffers;

        let sec_buffers = if p_buffers.is_null() {
            &[]
        } else {
            // SAFETY: We checked above that the `p_buffers` is not null.
            // The caller must ensure all other guarantees.
            unsafe { from_raw_parts(p_buffers, c_buffers as usize) }
        };

        // SAFETY: This function is safe to call because the argument is type checked.
        unsafe { p_sec_buffers_to_security_buffers(sec_buffers) }
    } else {
        Vec::new()
    }
}

#[allow(clippy::useless_conversion)]
pub(crate) unsafe fn p_sec_buffers_to_security_buffers(raw_buffers: &[SecBuffer]) -> Vec<SecurityBuffer> {
    raw_buffers
        .iter()
        .map(|raw_buffer| SecurityBuffer {
            buffer: if raw_buffer.pv_buffer.is_null() {
                Vec::new()
            } else {
                // SAFETY: `pv_buffer` is not null (checked above). All other guarantees must be provided by the user.
                unsafe { from_raw_parts(raw_buffer.pv_buffer, raw_buffer.cb_buffer as usize) }
                    .iter()
                    .map(|v| *v as u8)
                    .collect()
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
            // SAFETY: Memory allocation is safe. Also, we check `pv_buffer` for the null below.
            to_buffers[i].pv_buffer = unsafe { libc::malloc(buffer_size) } as *mut c_char;

            if to_buffers[i].pv_buffer.is_null() {
                return Err(Error::new(
                    ErrorKind::InsufficientMemory,
                    format!("coudln't allocate {buffer_size} bytes"),
                ));
            }
        }

        // SAFETY: `pv_buffer` is not null. We've checked for this above.
        // The user must ensure that the `pv_buffer` size is big enough to accommodate the data.
        unsafe { (buffer.buffer.as_ptr() as *const c_char).copy_to(to_buffers[i].pv_buffer, buffer_size) }
    }

    Ok(())
}
