use rustix::mm::{MprotectFlags, mlock, mprotect, munlock};
use core::ptr::NonNull;
use rustix::mm::ProtFlags;

type Error = Box<dyn core::error::Error>;
type Result<T> = std::result::Result<T, Error>;

/// Безопасный аналог safe_mlock
pub(crate) fn safe_mlock<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();

    unsafe { Ok(mlock(ptr, len)?) }
}

/// Безопасный аналог sodium_munlock
pub(crate) fn safe_munlock<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();

    unsafe { Ok(munlock(ptr, len)?) }
}

/// Безопасный аналог sodium_mprotect_noaccess
pub(crate) fn safe_mprotect_noaccess<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();

    unsafe { Ok(mprotect(ptr, len, MprotectFlags::empty())?) }
}

/// Безопасный аналог sodium_mprotect_readonly
pub(crate) fn safe_mprotect_readonly<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();

    unsafe { Ok(mprotect(ptr, len, MprotectFlags::READ)?) }
}

/// Безопасный аналог sodium_mprotect_readwrite
pub(crate) fn safe_mprotect_readwrite<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();

    unsafe {
        Ok(mprotect(
            ptr,
            len,
            MprotectFlags::READ | MprotectFlags::WRITE,
        )?)
    }
}
