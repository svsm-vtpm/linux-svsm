/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors: Vikram Narayanan <>
 *
 */

#![allow(non_camel_case_types)]

use crate::*;
use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::slice;
use core::str;

pub type c_char = u8;
pub type size_t = usize;

extern "C" {
    fn strlen(cs: *const c_char) -> size_t;
}

const ALIGN_32: usize = 32;

#[no_mangle]
pub extern "C" fn malloc(sz: usize) -> *mut u8 {
    let layout = match Layout::from_size_align(sz, ALIGN_32) {
        Ok(l) => l,
        Err(_e) => panic!("malloc: size is not 32 bytes aligned"),
    };

    let ptr: *mut u8 = unsafe { alloc(layout) };
    ptr
}

#[no_mangle]
pub extern "C" fn realloc(ptr: *mut u8, sz: usize) -> *mut u8 {
     // If ptr is null, then the call is equivalent to malloc(sz)
     if ptr == 0 as *mut u8 {
        let new_ptr: *mut u8 = malloc(sz);
        return new_ptr
    }

    let ptr_size: usize = sizeof_alloc(ptr);
    let layout = match Layout::from_size_align(ptr_size, 32) {
        Ok(l) => l,
        Err(_e) => panic!("realloc: ptr_size is not 32 aligned")
    };

    // If ptr is not null and sz is zero, then the call is equivalent to free(ptr)
    if sz == 0 {
        unsafe { dealloc(ptr, layout); }
        return 0 as *mut u8;
    }

    // If the new size is larger than the old size, the added memory will not be initialized
    // TODO: copy only the memory size requested previously rather than all the memory allocated
    let new_ptr: *mut u8 = malloc(sz);
    unsafe {
        if sz < ptr_size {
            core::ptr::copy_nonoverlapping(ptr as *const u8, new_ptr, sz)
        } else {
            core::ptr::copy_nonoverlapping(ptr as *const u8, new_ptr, ptr_size)
        }
        dealloc(ptr, layout)
    }
    new_ptr
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8) {
    let ptr_size: usize = sizeof_alloc(ptr);
    let layout = match Layout::from_size_align(ptr_size, ALIGN_32) {
        Ok(l) => l,
        Err(_e) => panic!("free: ptr_size is not 32 bytes aligned")
    };
    unsafe { dealloc(ptr, layout) }
}

#[no_mangle]
pub extern "C" fn serial_out(s: *const c_char) {
    unsafe {
        let rust_str = str::from_utf8_unchecked(slice::from_raw_parts(s, strlen(s)));
        println!("{}", rust_str);
    }
}

pub fn wrapper_init() {
    prints!("Wrappers initialized");
}
