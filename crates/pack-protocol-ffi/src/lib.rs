// Pack Protocol C FFI
//
// Exposes pack-protocol functionality via a C-ABI using opaque handles.
// All pointers are heap-allocated and must be freed by the caller
// using the corresponding _destroy function.

mod error;
mod handles;
mod identity_ffi;
mod fingerprint_ffi;
mod group_ffi;
mod sealed_sender_ffi;
mod session_ffi;
