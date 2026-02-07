use core::ptr::NonNull;
use nix::sys::mman::{ProtFlags, mlock, mprotect, munlock};

type Error = Box<dyn core::error::Error>;
type Result<T> = std::result::Result<T, Error>;

/// Безопасный аналог safe_mlock
pub(crate) fn safe_mlock<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();
    let non_null_ptr: Option<NonNull<std::ffi::c_void>> = NonNull::new(ptr);
    if non_null_ptr.is_none() {
        return Err("ptr is null".into());
    }

    unsafe { Ok(mlock(non_null_ptr.unwrap(), len)?) }
}

/// Безопасный аналог sodium_munlock
pub(crate) fn safe_munlock<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();
    let non_null_ptr: Option<NonNull<std::ffi::c_void>> = NonNull::new(ptr);
    if non_null_ptr.is_none() {
        return Err("ptr is null".into());
    }

    unsafe { Ok(munlock(non_null_ptr.unwrap(), len)?) }
}

/// Безопасный аналог sodium_mprotect_noaccess
pub(crate) fn safe_mprotect_noaccess<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();
    let non_null_ptr: Option<NonNull<std::ffi::c_void>> = NonNull::new(ptr);
    if non_null_ptr.is_none() {
        return Err("ptr is null".into());
    }
    unsafe { Ok(mprotect(non_null_ptr.unwrap(), len, ProtFlags::empty())?) }
}

/// Безопасный аналог sodium_mprotect_readonly
pub(crate) fn safe_mprotect_readonly<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();
    let non_null_ptr: Option<NonNull<std::ffi::c_void>> = NonNull::new(ptr);
    if non_null_ptr.is_none() {
        return Err("ptr is null".into());
    }
    unsafe { Ok(mprotect(non_null_ptr.unwrap(), len, ProtFlags::PROT_READ)?) }
}

/// Безопасный аналог sodium_mprotect_readwrite
pub(crate) fn safe_mprotect_readwrite<T>(data: &mut [T]) -> Result<()> {
    let ptr: *mut std::ffi::c_void = data.as_mut_ptr() as *mut std::ffi::c_void;
    let len: usize = data.len() * size_of::<T>();
    let non_null_ptr: Option<NonNull<std::ffi::c_void>> = NonNull::new(ptr);
    if non_null_ptr.is_none() {
        return Err("ptr is null".into());
    }
    unsafe {
        Ok(mprotect(
            non_null_ptr.unwrap(),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        )?)
    }
}
