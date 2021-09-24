use mhycrypt::{mhy_xor, mhy_generate_key};

#[no_mangle]
pub extern "C" fn crypt_buffer(data: *mut char, data_size: usize, key: *mut char) {
    let data = unsafe { std::slice::from_raw_parts_mut(data as *mut u8, data_size) };
    let key = unsafe { std::slice::from_raw_parts_mut(key as *mut u8, 4096) }; // TODO: very unsafe!
    mhy_xor(data, key);
}

#[no_mangle]
pub extern "C" fn fill_key_buffer_from_uint64_old(key_buffer: *mut char, seed: u64) {
    let key = unsafe { std::slice::from_raw_parts_mut(key_buffer as *mut u8, 4096) }; // TODO: very unsafe!
    mhy_generate_key(key, seed, true);
}

#[no_mangle]
pub extern "C" fn fill_key_buffer_from_uint64(key_buffer: *mut char, seed: u64) {
    let key = unsafe { std::slice::from_raw_parts_mut(key_buffer as *mut u8, 4096) }; // TODO: very unsafe!
    mhy_generate_key(key, seed, false);
}
