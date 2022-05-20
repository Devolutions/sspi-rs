mod ntlm;
mod security_package;

use std::convert::TryFrom;
use std::str::FromStr;
use std::{io, ptr, slice};

use chrono::{NaiveDate, NaiveDateTime};
use num_traits::{FromPrimitive, ToPrimitive};
use winapi::ctypes::{c_ulong, c_void};
use winapi::shared::sspi::{
    CredHandle, FreeContextBuffer, FreeCredentialsHandle, PSecPkgInfoW, QuerySecurityPackageInfoW, SecBuffer,
    SecBufferDesc, SecPkgInfoW, TimeStamp, SECBUFFER_VERSION,
};
use winapi::um::minwinbase::SYSTEMTIME;
use winapi::um::timezoneapi::FileTimeToSystemTime;

pub use self::ntlm::Ntlm;
pub use self::security_package::SecurityPackage;
use crate::sspi::{
    self, PackageCapabilities, PackageInfo, SecurityBuffer, SecurityBufferType, SecurityPackageType, SecurityStatus,
};

const SEC_WINNT_AUTH_IDENTITY_UNICODE: c_ulong = 0x2;

/// Retrieves information about a specified security package. This information includes credentials and contexts.
///
/// # MSDN
///
/// * [QuerySecurityPackageInfoW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritypackageinfow)
pub fn query_security_package_info(package_type: SecurityPackageType) -> sspi::Result<PackageInfo> {
    let mut package_name = package_type
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut package_info_ptr = ptr::null_mut() as *mut SecPkgInfoW;

    unsafe {
        convert_winapi_status(QuerySecurityPackageInfoW(
            package_name.as_mut_ptr(),
            &mut package_info_ptr as *mut *mut SecPkgInfoW,
        ))?;
    }
    let package_info_guard = PackageInfoGuard(package_info_ptr);

    let package_info = unsafe { PackageInfo::try_from(&(*(package_info_guard.0)))? };

    Ok(package_info)
}

/// Returns an array of `PackageInfo` structures that provide information about the security packages available to the client.
///
/// # Returns
///
/// * `Vec` of `PackageInfo` structures upon success
///
/// # MSDN
///
/// * [EnumerateSecurityPackagesW function](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-enumeratesecuritypackagesw)
pub fn enumerate_security_packages() -> sspi::Result<Vec<PackageInfo>> {
    let mut size: u32 = 0;
    let mut packages = ptr::null_mut() as *mut SecPkgInfoW;

    unsafe {
        convert_winapi_status(winapi::shared::sspi::EnumerateSecurityPackagesW(
            &mut size as *mut _,
            &mut packages as *mut _,
        ))?;
    }
    let packages_guard = SecurityPackagesGuard(packages);

    let s = unsafe { std::slice::from_raw_parts(packages_guard.0, size as usize) };

    s.iter().map(PackageInfo::try_from).collect::<sspi::Result<Vec<_>>>()
}

pub struct CredentialsGuard(pub CredHandle);

impl Drop for CredentialsGuard {
    fn drop(&mut self) {
        unsafe {
            convert_winapi_status(FreeCredentialsHandle(&mut self.0 as *mut _))
                .expect("FreeCredentialsHandle for CredentialsHandle failed")
        };
    }
}

struct PackageInfoGuard(PSecPkgInfoW);

impl Drop for PackageInfoGuard {
    fn drop(&mut self) {
        unsafe {
            convert_winapi_status(FreeContextBuffer(self.0 as *mut _))
                .expect("FreeContextBuffer for PackageInfoHandle failed");
        }
    }
}

struct SecurityPackagesGuard(PSecPkgInfoW);

impl Drop for SecurityPackagesGuard {
    fn drop(&mut self) {
        unsafe {
            convert_winapi_status(FreeContextBuffer(self.0 as *mut _))
                .expect("FreeContextBuffer for SecurityPackages failed");
        }
    }
}

impl From<&mut SecurityBuffer> for SecBuffer {
    fn from(b: &mut SecurityBuffer) -> Self {
        Self {
            BufferType: b.buffer_type.to_u32().unwrap(),
            cbBuffer: b.buffer.len() as c_ulong,
            pvBuffer: b.buffer.as_mut_ptr() as *mut c_void,
        }
    }
}

impl TryFrom<&SecBuffer> for SecurityBuffer {
    type Error = sspi::Error;

    fn try_from(b: &SecBuffer) -> sspi::Result<Self> {
        let buffer = unsafe { slice::from_raw_parts(b.pvBuffer as *const _, b.cbBuffer as usize).to_vec() };
        unsafe { convert_winapi_status(FreeContextBuffer(b.pvBuffer))? };

        Ok(Self {
            buffer,
            buffer_type: SecurityBufferType::from_u32(b.BufferType).ok_or_else(|| {
                sspi::Error::new(
                    sspi::ErrorKind::InvalidToken,
                    format!("Got unexpected buffer type: {:x?}", b.BufferType),
                )
            })?,
        })
    }
}

impl TryFrom<&SecPkgInfoW> for PackageInfo {
    type Error = sspi::Error;

    fn try_from(p: &SecPkgInfoW) -> sspi::Result<Self> {
        let (name, comment) = unsafe {
            let name = wide_ptr_to_string(p.Name)?;
            let name = SecurityPackageType::from_str(name.as_str())?;

            let comment = wide_ptr_to_string(p.Comment)?;

            (name, comment)
        };

        Ok(PackageInfo {
            capabilities: PackageCapabilities::from_bits_truncate(p.fCapabilities),
            rpc_id: p.wRPCID,
            max_token_len: p.cbMaxToken,
            name,
            comment,
        })
    }
}

impl From<&PackageInfo> for SecPkgInfoW {
    fn from(p: &PackageInfo) -> Self {
        let mut name = p
            .name
            .to_string()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut comment = p
            .comment
            .to_string()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();

        SecPkgInfoW {
            fCapabilities: p.capabilities.bits(),
            wVersion: 1,
            wRPCID: p.rpc_id,
            cbMaxToken: p.max_token_len,
            Name: name.as_mut_ptr(),
            Comment: comment.as_mut_ptr(),
        }
    }
}

fn construct_buffer_desc(sec_buffers: &mut [SecBuffer]) -> SecBufferDesc {
    SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: sec_buffers.len() as c_ulong,
        pBuffers: sec_buffers.as_mut_ptr(),
    }
}

fn convert_winapi_status(status: i32) -> sspi::Result<SecurityStatus> {
    let status = status as u32;
    match SecurityStatus::from_u32(status) {
        Some(ok) => Ok(ok),
        None => Err(sspi::Error::new(
            sspi::ErrorKind::from_u32(status).unwrap_or(sspi::ErrorKind::Unknown),
            io::Error::last_os_error().to_string(),
        )),
    }
}

unsafe fn wide_ptr_to_string(ptr: *const u16) -> sspi::Result<String> {
    let mut len = 0;
    for i in 0.. {
        if *ptr.add(i) == 0 {
            len = i;
            break;
        }
    }

    let s = std::slice::from_raw_parts(ptr, len);

    String::from_utf16(s).map_err(From::from)
}

fn file_time_to_system_time(timestamp: TimeStamp) -> NaiveDateTime {
    let mut system_time = SYSTEMTIME::default();

    unsafe {
        FileTimeToSystemTime(&timestamp as *const _ as *const _, &mut system_time as *mut _);
    }

    NaiveDate::from_ymd(
        i32::from(system_time.wYear),
        u32::from(system_time.wMonth),
        u32::from(system_time.wDay),
    )
    .and_hms_micro(
        u32::from(system_time.wHour),
        u32::from(system_time.wMinute),
        u32::from(system_time.wSecond),
        u32::from(system_time.wMilliseconds),
    )
}

fn str_to_win_wstring(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>()
}
