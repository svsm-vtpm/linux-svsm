/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Dov Murik <dovmurik@linux.ibm.com>
 */

use crate::bindings::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_sha512, EVP_MD_CTX,
};

use core::ptr;

pub type Sha512Bytes = [u8; 64];

pub fn sha512(buf: &[u8]) -> Result<Sha512Bytes, i32> {
    let mut result: Sha512Bytes = [0; 64];
    let mut result_len: u32 = result.len() as u32;
    unsafe {
        let ctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
        if ctx.is_null() {
            return Err(0);
        }
        let ret: i32 = EVP_DigestInit_ex(ctx, EVP_sha512(), ptr::null_mut());
        if ret != 1 {
            EVP_MD_CTX_free(ctx);
            return Err(ret);
        }

        let ret: i32 = EVP_DigestUpdate(ctx, buf.as_ptr() as *const _, buf.len());
        if ret != 1 {
            EVP_MD_CTX_free(ctx);
            return Err(ret);
        }

        let ret: i32 = EVP_DigestFinal_ex(ctx, result.as_mut_ptr(), ptr::addr_of_mut!(result_len));
        if ret != 1 {
            EVP_MD_CTX_free(ctx);
            return Err(ret);
        }

        EVP_MD_CTX_free(ctx);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512() {
        // Expected result:
        // $ cat /dev/null | sha512sum
        // cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
        let h1: Sha512Bytes = sha512(b"").expect("sha512 should succeed");
        assert!(h1.starts_with(b"\xcf\x83\xe1\x35"));
        assert!(h1.ends_with(b"\xf9\x27\xda\x3e"));

        // Expected result:
        // $ echo -n "Hello, world!" | sha512sum
        // c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421
        let h2: Sha512Bytes = sha512(b"Hello, world!").expect("sha512 should succeed");
        assert!(h2.starts_with(b"\xc1\x52\x7c\xd8"));
        assert!(h2.ends_with(b"\x57\xf7\x94\x21"));
    }
}
