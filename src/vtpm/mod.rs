/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors: Vikram Narayanan <>
 *
 */

pub mod init;
pub mod manufacture;

pub use crate::vtpm::init::vtpm_init;
pub use crate::vtpm::manufacture::{tpm2_create_ek, KeyType};
