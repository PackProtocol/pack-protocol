use std::ptr;

/// Convert a Rust value into a heap-allocated opaque pointer.
/// The caller is responsible for freeing it with the corresponding _destroy function.
pub fn box_raw<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

/// Reconstruct a Box from an opaque pointer and drop it.
/// # Safety
/// The pointer must have been created by `box_raw` and must not be used after this call.
pub unsafe fn destroy<T>(handle: *mut T) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Write a value through an output pointer, returning whether the pointer was valid.
pub fn write_out<T>(out: *mut *mut T, value: T) -> bool {
    if out.is_null() {
        return false;
    }
    unsafe {
        *out = box_raw(value);
    }
    true
}

/// Write bytes to caller-provided buffer. Returns actual length needed.
/// If buf is null or buf_len is too small, only writes the needed length.
pub fn write_bytes(
    data: &[u8],
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> bool {
    if !out_len.is_null() {
        unsafe { *out_len = data.len(); }
    }
    if buf.is_null() || buf_len < data.len() {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }
    true
}
