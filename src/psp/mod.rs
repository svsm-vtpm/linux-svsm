/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

/// SNP Guest Request Messages
pub mod guest_request;

pub use crate::psp::guest_request::send_guest_request;
