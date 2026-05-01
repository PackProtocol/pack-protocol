use jni::JNIEnv;
use std::any::TypeId;

struct TaggedHandle<T: 'static> {
    type_id: TypeId,
    value: T,
}

pub fn to_handle<T: 'static>(value: T) -> jni::sys::jlong {
    let tagged = TaggedHandle {
        type_id: TypeId::of::<T>(),
        value,
    };
    Box::into_raw(Box::new(tagged)) as jni::sys::jlong
}

pub unsafe fn from_handle<'a, T: 'static>(handle: jni::sys::jlong) -> Option<&'a T> {
    if handle == 0 {
        return None;
    }
    let tagged = &*(handle as *const TaggedHandle<T>);
    if tagged.type_id != TypeId::of::<T>() {
        return None;
    }
    Some(&tagged.value)
}

pub unsafe fn from_handle_mut<'a, T: 'static>(handle: jni::sys::jlong) -> Option<&'a mut T> {
    if handle == 0 {
        return None;
    }
    let tagged = &mut *(handle as *mut TaggedHandle<T>);
    if tagged.type_id != TypeId::of::<T>() {
        return None;
    }
    Some(&mut tagged.value)
}

pub unsafe fn destroy_handle<T: 'static>(handle: jni::sys::jlong) {
    if handle != 0 {
        let tagged = Box::from_raw(handle as *mut TaggedHandle<T>);
        drop(tagged);
    }
}

pub fn throw_error(env: &mut JNIEnv, message: &str) -> Result<(), jni::errors::Error> {
    env.throw_new("java/lang/RuntimeException", message)
}
