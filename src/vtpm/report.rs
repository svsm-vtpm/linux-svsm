/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use core::slice;
use crate::prints;
use crate::psp::guest_request::{
    send_guest_request,
    SNP_MSG_REPORT_REQ,
};

pub const REPORT_REQ_USER_DATA_SIZE: usize = 64;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct snp_report_req {
    pub user_data: [u8; REPORT_REQ_USER_DATA_SIZE],
    pub vmpl: u32,
    pub rsvd: [u8; 28usize],
}

impl snp_report_req {
    fn new(_vmpl: u32) -> Self {
        Self {
            user_data: [0u8; 64],
            vmpl: _vmpl,
            rsvd: [0u8; 28],
        }
    }
    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const snp_report_req as *const u8,
                core::mem::size_of::<snp_report_req>()
            )
        }
    }
}

#[repr(C)]
#[repr(align(2048))]
#[derive(Debug, Copy, Clone)]
pub struct msg_report_resp {
    pub status: u32,
    pub report_size: u32,
    pub reserved: [u8; 24usize],
    pub report: attestation_report,
}

// Converted tcb_version from enum to
// struct to make alignment simple.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct tcb_version {
    pub raw: u64,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct signature {
    pub r: [u8; 72usize],
    pub s: [u8; 72usize],
    pub reserved: [u8; 368usize],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct attestation_report {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16usize],
    pub image_id: [u8; 16usize],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub platform_version: tcb_version,
    pub platform_info: u64,
    pub flags: u32,
    pub reserved0: u32,
    pub report_data: [u8; 64usize],
    pub measurement: [u8; 48usize],
    pub host_data: [u8; 32usize],
    pub id_key_digest: [u8; 48usize],
    pub author_key_digest: [u8; 48usize],
    pub report_id: [u8; 32usize],
    pub report_id_ma: [u8; 32usize],
    pub reported_tcb: tcb_version,
    pub reserved1: [u8; 24usize],
    pub chip_id: [u8; 64usize],
    pub reserved2: [u8; 192usize],
    pub signature: signature,
}

impl attestation_report {
    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const attestation_report as *const u8,
                core::mem::size_of::<attestation_report>()
            )
        }
    }
}

// Secure Encrypted Virtualization API spec, Attestation section
pub fn get_and_save_report(data: &[u8]) {
    let data_sz: usize = data.len();
    if data_sz > REPORT_REQ_USER_DATA_SIZE {
        prints!("ERROR: Report data_size={} too big\n", data_sz);
        return;
    }
    // Create a vmpl0 request
    let mut req: snp_report_req = snp_report_req::new(0u32);
    req.user_data[..data_sz].copy_from_slice(data);

    prints!("INFO: Attestation report requested. user_data: {:02x?}\n", {req.user_data});

    let payload = send_guest_request(req.as_slice(), SNP_MSG_REPORT_REQ);
    if payload.is_none() {
        prints!("ERROR: Attestation report request failed\n");
        return;
    }
    let resp: msg_report_resp = {
            let r = payload.unwrap();
            let (head, body, _tail) = unsafe { r.align_to::<msg_report_resp>() };
            if !head.is_empty() {
                prints!("ERROR: Report response not aligned\n");
                return;
            }
            body[0]
    };
    if resp.status != 0 {
        prints!("ERROR: Bad report status={}\n", {resp.status});
        return;
    }
    const REPORT_LEN: usize = core::mem::size_of::<attestation_report>();
    if resp.report_size != REPORT_LEN as u32 {
        prints!("ERROR: Report size mismatch (size=0x{}, expected=0x{})\n",
            {resp.report_size},
            REPORT_LEN);
        return;
    }
    tpm2_write_report_nvram(resp.report.as_slice());
}
