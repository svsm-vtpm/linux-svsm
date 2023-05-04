/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::mem::{
    mem_allocate, mem_allocate_frame, pgtable_make_pages_shared, pgtable_pa_to_va,
};
use crate::{
    prints, ALIGN, ALIGNED, BIT, PAGE_COUNT, PAGE_SHIFT, PAGE_SIZE,
};

use x86_64::addr::VirtAddr;

///
/// AEAD Algo
///

#[allow(dead_code)]
/// 0
const SNP_AEAD_INVALID: u8 = 0;
/// 1
const SNP_AEAD_AES_256_GCM: u8 = 1;

///
/// SNP_GUEST_REQUEST hypervisor error codes
///

/// BIT!(32)
pub const SNP_GUEST_REQ_INVALID_LEN: u64 = BIT!(32);
/// BIT!(33)
pub const SNP_GUEST_REQ_ERR_BUSY: u64 = BIT!(33);

///
/// SNP_GUEST_MESSAGE type
///

/// 0
pub const SNP_MSG_TYPE_INVALID: u8 = 0;

/// 1
const HDR_VERSION: u8 = 1;
/// 1
const MSG_VERSION: u8 = 1;
/// 16
const AUTHTAG_SIZE: u16 = 16;
/// 12
const IV_SIZE: usize = 12;

/// 0x4000
pub const SNP_GUEST_REQ_MAX_DATA_SIZE: usize = 0x4000;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SnpGuestRequestMsgHdr {
    authtag: [u8; 32usize],
    msg_seqno: u64,
    rsvd1: [u8; 8usize],
    algo: u8,
    hdr_version: u8,
    hdr_sz: u16,
    msg_type: u8,
    msg_version: u8,
    msg_sz: u16,
    rsvd2: u32,
    msg_vmpck: u8,
    rsvd3: [u8; 35usize],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SnpGuestRequestMsg {
    hdr: SnpGuestRequestMsgHdr,
    payload: [u8; 4000usize],
}

impl SnpGuestRequestMsg {
    fn alloc() -> Result<VirtAddr, ()> {
        if let Some(pf) = mem_allocate_frame() {
            let va: VirtAddr = pgtable_pa_to_va(pf.start_address());
            return Ok(va);
        }
        prints!("ERR: Failed to allocate a guest request message\n");
        Err(())
    }
}

pub struct SnpGuestRequestCmd {
    // SNP_GUEST_REQUEST requires two unique pages: one for
    // the request and another for the response message. Both
    // of them are assigned to the hypervisor (shared).
    req_shared_page: VirtAddr,
    resp_shared_page: VirtAddr,

    // Message encryption and decryption are performed in a
    // private page to avoid data leaking.
    staging_priv_page: VirtAddr,

    // Openssl context is saved to simplify the clean-up logic in
    // the error path. We free it before use.
    ossl_ctx: VirtAddr,

    // SNP Extended Guest Request.
    data_gva: VirtAddr,
    data_npages: usize,

    initialized: bool,
}

impl SnpGuestRequestCmd {
    pub fn get_req_shared_page(&self) -> VirtAddr {
        self.req_shared_page
    }

    pub fn get_resp_shared_page(&self) -> VirtAddr {
        self.resp_shared_page
    }

    pub fn get_data_gva(&self) -> VirtAddr {
        self.data_gva
    }

    pub fn get_data_npages(&self) -> usize {
        self.data_npages
    }

    pub fn set_data_npages(&mut self, npages: &usize) {
        self.data_npages = *npages;
    }

    pub const fn new() -> Self {
        SnpGuestRequestCmd {
            req_shared_page: VirtAddr::zero(),
            resp_shared_page: VirtAddr::zero(),

            data_gva: VirtAddr::zero(),
            data_npages: 0,

            staging_priv_page: VirtAddr::zero(),
            ossl_ctx: VirtAddr::zero(),

            initialized: false,
        }
    }

    pub fn init(&mut self) -> Result<(), ()> {
        if !initialized {
            self.req_shared_page = SnpGuestRequestMsg::alloc()?;
            self.resp_shared_page = SnpGuestRequestMsg::alloc()?;
            self.staging_priv_page = SnpGuestRequestMsg::alloc()?;

            self.data_gva = mem_allocate(SNP_GUEST_REQ_MAX_DATA_SIZE)?;
            if !ALIGNED!(self.data_gva.as_u64(), PAGE_SIZE) {
                prints!("ERR: data_gva is not page aligned\n");
                return Err(());
            }
            self.data_npages = PAGE_COUNT!(SNP_GUEST_REQ_MAX_DATA_SIZE as u64) as usize;

            // The SNP ABI spec says the request, response and data pages have
            // to be shared with the hypervisor
            pgtable_make_pages_shared(self.req_shared_page, PAGE_SIZE);
            pgtable_make_pages_shared(self.resp_shared_page, PAGE_SIZE);
            pgtable_make_pages_shared(self.data_gva, SNP_GUEST_REQ_MAX_DATA_SIZE as u64);
        }

        Ok(())
    }
}
