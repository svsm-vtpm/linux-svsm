/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use alloc::boxed::Box;
use alloc::string::ToString;
use core::fmt;
use core::mem::MaybeUninit;
use crate::{
    PAGE_SIZE,
    prints,
    svsm_secrets_page,
};
use crate::bindings::{
    Aes,
    AES_BLOCK_SIZE,
    INVALID_DEVID,
    wc_AesInit,
    wc_AesGcmDecrypt,
    wc_AesGcmEncrypt,
    wc_AesGcmSetKey,
};
use crate::bios::SnpSecrets;
use crate::cpu::vc::{
    vc_terminate_svsm_enomem,
    vc_snp_guest_request,
};
use crate::mem::{
    free_page,
    mem_allocate_frame,
    pgtable_make_pages_shared,
    pgtable_make_pages_private,
    pgtable_pa_to_va,
};
use crate::util::locking::SpinLock;
use lazy_static::lazy_static;
use memoffset::offset_of;
use x86_64::{
    PhysAddr,
    VirtAddr,
};
use x86_64::structures::paging::PhysFrame;

// From Linux/include/uapi/linux/psp-sev.h
#[repr(u32)]
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
pub enum SevStatusCode {
    SEV_RET_SUCCESS = 0,
    SEV_RET_INVALID_PLATFORM_STATE,
    SEV_RET_INVALID_GUEST_STATE,
    SEV_RET_INAVLID_CONFIG,
    SEV_RET_INVALID_LEN,
    SEV_RET_ALREADY_OWNED,
    SEV_RET_INVALID_CERTIFICATE,
    SEV_RET_POLICY_FAILURE,
    SEV_RET_INACTIVE,
    SEV_RET_INVALID_ADDRESS,
    SEV_RET_BAD_SIGNATURE,
    SEV_RET_BAD_MEASUREMENT,
    SEV_RET_ASID_OWNED,
    SEV_RET_INVALID_ASID,
    SEV_RET_WBINVD_REQUIRED,
    SEV_RET_DFFLUSH_REQUIRED,
    SEV_RET_INVALID_GUEST,
    SEV_RET_INVALID_COMMAND,
    SEV_RET_ACTIVE,
    SEV_RET_HWSEV_RET_PLATFORM,
    SEV_RET_HWSEV_RET_UNSAFE,
    SEV_RET_UNSUPPORTED,
    SEV_RET_INVALID_PARAM,
    SEV_RET_RESOURCE_LIMIT,
    SEV_RET_SECURE_DATA_INVALID,
}

impl SevStatusCode {
    pub fn from_u32(value: u32) -> Option<SevStatusCode> {
        match value {
            0 => Some(SevStatusCode::SEV_RET_SUCCESS),
            1 => Some(SevStatusCode::SEV_RET_INVALID_PLATFORM_STATE),
            2 => Some(SevStatusCode::SEV_RET_INVALID_GUEST_STATE),
            3 => Some(SevStatusCode::SEV_RET_INAVLID_CONFIG),
            4 => Some(SevStatusCode::SEV_RET_INVALID_LEN),
            5 => Some(SevStatusCode::SEV_RET_ALREADY_OWNED),
            6 => Some(SevStatusCode::SEV_RET_INVALID_CERTIFICATE),
            7 => Some(SevStatusCode::SEV_RET_POLICY_FAILURE),
            8 => Some(SevStatusCode::SEV_RET_INACTIVE),
            9 => Some(SevStatusCode::SEV_RET_INVALID_ADDRESS),
            10 => Some(SevStatusCode::SEV_RET_BAD_SIGNATURE),
            11 => Some(SevStatusCode::SEV_RET_BAD_MEASUREMENT),
            12 => Some(SevStatusCode::SEV_RET_ASID_OWNED),
            13 => Some(SevStatusCode::SEV_RET_INVALID_ASID),
            14 => Some(SevStatusCode::SEV_RET_WBINVD_REQUIRED),
            15 => Some(SevStatusCode::SEV_RET_DFFLUSH_REQUIRED),
            16 => Some(SevStatusCode::SEV_RET_INVALID_GUEST),
            17 => Some(SevStatusCode::SEV_RET_INVALID_COMMAND),
            18 => Some(SevStatusCode::SEV_RET_ACTIVE),
            19 => Some(SevStatusCode::SEV_RET_HWSEV_RET_PLATFORM),
            20 => Some(SevStatusCode::SEV_RET_HWSEV_RET_UNSAFE),
            21 => Some(SevStatusCode::SEV_RET_UNSUPPORTED),
            22 => Some(SevStatusCode::SEV_RET_INVALID_PARAM),
            23 => Some(SevStatusCode::SEV_RET_RESOURCE_LIMIT),
            24 => Some(SevStatusCode::SEV_RET_SECURE_DATA_INVALID),
            _ => None,
        }
    }
}

impl fmt::Display for SevStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SevStatusCode::SEV_RET_SUCCESS => f.write_str("SEV_RET_SUCCESS"),
            SevStatusCode::SEV_RET_INVALID_PLATFORM_STATE => f.write_str("SEV_RET_INVALID_PLATFORM_STATE"),
            SevStatusCode::SEV_RET_INVALID_GUEST_STATE => f.write_str("SEV_RET_INVALID_GUEST_STATE"),
            SevStatusCode::SEV_RET_INAVLID_CONFIG => f.write_str("SEV_RET_INAVLID_CONFIG"),
            SevStatusCode::SEV_RET_INVALID_LEN => f.write_str("SEV_RET_INVALID_LEN"),
            SevStatusCode::SEV_RET_ALREADY_OWNED => f.write_str("SEV_RET_ALREADY_OWNED"),
            SevStatusCode::SEV_RET_INVALID_CERTIFICATE => f.write_str("SEV_RET_INVALID_CERTIFICATE"),
            SevStatusCode::SEV_RET_POLICY_FAILURE => f.write_str("SEV_RET_POLICY_FAILURE"),
            SevStatusCode::SEV_RET_INACTIVE => f.write_str("SEV_RET_INACTIVE"),
            SevStatusCode::SEV_RET_INVALID_ADDRESS => f.write_str("SEV_RET_INVALID_ADDRESS"),
            SevStatusCode::SEV_RET_BAD_SIGNATURE => f.write_str("SEV_RET_BAD_SIGNATURE"),
            SevStatusCode::SEV_RET_BAD_MEASUREMENT => f.write_str("SEV_RET_BAD_MEASUREMENT"),
            SevStatusCode::SEV_RET_ASID_OWNED => f.write_str("SEV_RET_ASID_OWNED"),
            SevStatusCode::SEV_RET_INVALID_ASID => f.write_str("SEV_RET_INVALID_ASID"),
            SevStatusCode::SEV_RET_WBINVD_REQUIRED => f.write_str("SEV_RET_WBINVD_REQUIRED"),
            SevStatusCode::SEV_RET_DFFLUSH_REQUIRED => f.write_str("SEV_RET_DFFLUSH_REQUIRED"),
            SevStatusCode::SEV_RET_INVALID_GUEST => f.write_str("SEV_RET_INVALID_GUEST"),
            SevStatusCode::SEV_RET_INVALID_COMMAND => f.write_str("SEV_RET_INVALID_COMMAND"),
            SevStatusCode::SEV_RET_ACTIVE => f.write_str("SEV_RET_ACTIVE"),
            SevStatusCode::SEV_RET_HWSEV_RET_PLATFORM => f.write_str("SEV_RET_HWSEV_RET_PLATFORM"),
            SevStatusCode::SEV_RET_HWSEV_RET_UNSAFE => f.write_str("SEV_RET_HWSEV_RET_UNSAFE"),
            SevStatusCode::SEV_RET_UNSUPPORTED => f.write_str("SEV_RET_UNSUPPORTED"),
            SevStatusCode::SEV_RET_INVALID_PARAM => f.write_str("SEV_RET_INVALID_PARAM"),
            SevStatusCode::SEV_RET_RESOURCE_LIMIT => f.write_str("SEV_RET_RESOURCE_LIMIT"),
            SevStatusCode::SEV_RET_SECURE_DATA_INVALID => f.write_str("SEV_RET_SECURE_DATA_INVALID"),
        }
    }
}

// AEAD Algo
#[allow(dead_code)]
const SNP_AEAD_INVALID: u8 = 0;
const SNP_AEAD_AES_256_GCM: u8 = 1;

// SNP_GUEST_MESSAGE type
pub const SNP_MSG_TYPE_INVALID: u8 = 0;
pub const SNP_MSG_CPUID_REQ: u8 = 1;
pub const SNP_MSG_CPUID_RSP: u8 = 2;
pub const SNP_MSG_KEY_REQ: u8 = 3;
pub const SNP_MSG_KEY_RSP: u8 = 4;
pub const SNP_MSG_REPORT_REQ: u8 = 5;
pub const SNP_MSG_REPORT_RSP: u8 = 6;
pub const SNP_MSG_EXPORT_REQ: u8 = 7;
pub const SNP_MSG_EXPORT_RSP: u8 = 8;
pub const SNP_MSG_IMPORT_REQ: u8 = 9;
pub const SNP_MSG_IMPORT_RSP: u8 = 10;
pub const SNP_MSG_ABSORB_REQ: u8 = 11;
pub const SNP_MSG_ABSORB_RSP: u8 = 12;
pub const SNP_MSG_VMRK_REQ: u8 = 13;
pub const SNP_MSG_VMRK_RSP: u8 = 14;
pub const SNP_MSG_ABSORB_NOMA_REQ: u8 = 15;
pub const SNP_MSG_ABSORB_NOMA_RESP: u8 = 16;
pub const SNP_MSG_TSC_INFO_REQ: u8 = 17;
pub const SNP_MSG_TSC_INFO_RSP: u8 = 18;

const HDR_VERSION: u8 = 1;
const MSG_VERSION: u8 = 1;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct snp_guest_request_msg_hdr {
    pub authtag: [u8; 32usize],
    pub msg_seqno: u64,
    pub rsvd1: [u8; 8usize],
    pub algo: u8,
    pub hdr_version: u8,
    pub hdr_sz: u16,
    pub msg_type: u8,
    pub msg_version: u8,
    pub msg_sz: u16,
    pub rsvd2: u32,
    pub msg_vmpck: u8,
    pub rsvd3: [u8; 35usize],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct snp_guest_request_msg {
    pub hdr: snp_guest_request_msg_hdr,
    pub payload: [u8; 4000usize],
}

struct SequenceNumber {
    data: u64,
}

impl SequenceNumber {
    pub const fn new() -> Self {
        SequenceNumber { data: 0 }
    }
    pub fn last_used(&self) -> u64 {
        self.data
    }
    pub fn add_two(&mut self) {
        self.data = self.data
            .checked_add(2)
            .expect("ERROR: Sequence number overflow (2)\n");
    }
}

pub struct SnpGuestRequest {
    seq_num: SequenceNumber,
}

lazy_static! {
    static ref GUEST_REQUEST: SpinLock<SnpGuestRequest> =
        SpinLock::new(SnpGuestRequest::new());
}

impl SnpGuestRequest {
    pub fn new() -> Self{
        SnpGuestRequest {
            seq_num: SequenceNumber::new(),
        }
    }
    fn send(&mut self, payload: &[u8], msg_type: u8) -> Option<Box<[u8]>> {
        // The Guest Request NAE event requires two unique pages, one page
        // for the request and one for the response messages. Both pages
        // must be assigned to the hypervisor (shared). The payload of the
        // two messages are encrypted during the communication with the
        // PSP firmware.
        let pa1: PhysFrame = match mem_allocate_frame() {
            Some(f) => f,
            None => vc_terminate_svsm_enomem(),
        };
        let pa2: PhysFrame = match mem_allocate_frame() {
            Some(f) => f,
            None => vc_terminate_svsm_enomem(),
        };
        let va1: VirtAddr = pgtable_pa_to_va(pa1.start_address());
        let va2: VirtAddr = pgtable_pa_to_va(pa2.start_address());
        pgtable_make_pages_shared(va1, PAGE_SIZE);
        pgtable_make_pages_shared(va2, PAGE_SIZE);
        let req_msg: *mut snp_guest_request_msg = va1.as_mut_ptr();
        let resp_msg: *mut snp_guest_request_msg = va2.as_mut_ptr();
        //
        // The PSP firmware adds 1 to the sequence number when
        // it receives a request successfully. Hence, we have to
        // add 2 ONLY when we receive a response successfully
        //
        let mut seq_num: u64 = self.seq_num
            .last_used()
            .checked_add(1)
            .expect("ERROR: Request sequence number overflow\n");
        //
        // Use the sequence number as IV
        //
        const IV_SIZE: usize = 12;
        const U64_SIZE: usize = core::mem::size_of::<u64>();
        let mut iv = [0u8; IV_SIZE];
        iv[..U64_SIZE].copy_from_slice(&u64::to_ne_bytes(seq_num));
        //
        // Use vmpck[0] as key
        //
        const KEY_SIZE: usize = 32;
        let svsm_secrets_va: VirtAddr = unsafe { pgtable_pa_to_va(PhysAddr::new(svsm_secrets_page)) };
        let svsm_secrets: *const SnpSecrets = svsm_secrets_va.as_ptr();
        let key = unsafe { *(&(*svsm_secrets).vmpck0 as *const _ as *const [u8; KEY_SIZE]) };
        //
        // Request message header
        //
        let req_hdr = unsafe { &mut (*req_msg).hdr };
        req_hdr.msg_seqno = seq_num;
        req_hdr.algo = SNP_AEAD_AES_256_GCM;
        req_hdr.hdr_version = HDR_VERSION;
        req_hdr.hdr_sz = core::mem::size_of::<snp_guest_request_msg_hdr>().try_into().unwrap();
        req_hdr.msg_type = msg_type;
        req_hdr.msg_version = MSG_VERSION;
        req_hdr.msg_sz = core::mem::size_of_val(payload).try_into().unwrap();
        req_hdr.msg_vmpck = 0;
        //
        // Encrypt the request payload
        //
        let aad_len: usize =
            core::mem::size_of::<snp_guest_request_msg_hdr>() -
            offset_of!(snp_guest_request_msg_hdr, algo);
        unsafe {
            let mut enc: Aes = MaybeUninit::zeroed().assume_init();
            let mut ret: i32 = wc_AesInit(&mut enc, core::ptr::null_mut(), INVALID_DEVID);
            if ret != 0 {
                prints!("ERROR: AesInit failed for encryption, ret={}\n", ret);
                return None;
            }
            ret = wc_AesGcmSetKey(
                &mut enc,
                &key as *const _ as *const u8,
                KEY_SIZE as u32
            );
            if ret != 0 {
                prints!("ERROR: AesGcmSetKey failed for encryption, ret={}\n", ret);
                return None;
            }
            ret = wc_AesGcmEncrypt(
                &mut enc,
                (*req_msg).payload.as_mut_ptr(),        // [out] cipher text
                payload.as_ptr(),                       // [in] plain text
                core::mem::size_of_val(payload) as u32, // [in] plain text size
                &mut iv as *mut _ as *mut u8,           // [in] iv
                IV_SIZE as u32,                         // [in] iv size
                (*req_msg).hdr.authtag.as_mut_ptr(),    // [out] authtag
                AES_BLOCK_SIZE as u32,                  // [in] authtag size
                &(*req_msg).hdr.algo as *const u8,      // [in] aad
                aad_len as u32                          // [in] aad size
            );
            if ret != 0 {
                prints!("ERROR: AesGcmEncrypt failed, ret={}\n", ret);
                return None;
            } else {
                prints!("INFO: SNP_GUEST_REQUEST message encrypted\n");
//              prints!("req_msg {:p} {:x?}\n", {&(*req_msg)}, {&(*req_msg)});
            }
        }
        //
        // Send the request
        //
        let rc = vc_snp_guest_request(pa1.start_address(), pa2.start_address());
        if rc != 0 {
            let status = match SevStatusCode::from_u32(rc) {
                Some(s) => s.to_string(),
                None => "Unknown".to_string(),
            };
            prints!("ERROR: SNP_GUEST_REQUEST failed, status={} {}\n", rc, status);
            return None;
        }
        self.seq_num.add_two();
        const BUF_LEN: usize = 4000;
        let mut buf: [u8; BUF_LEN] = [0u8; BUF_LEN];
        unsafe {
//          prints!("resp_msg {:p} {:x?}\n", {&(*resp_msg)}, {&(*resp_msg)});
            //
            // Check the response
            //
            seq_num = seq_num.checked_add(1)
                .expect("ERROR: Sequence number overflow\n");
            if (*resp_msg).hdr.msg_seqno != seq_num {
                prints!("ERROR: BUG: Response with invalid seq_num={}, expected={}\n",
                    {(*resp_msg).hdr.msg_seqno},
                    seq_num);
                return None;
            }
            //
            // Decrypt the response payload.
            //
            let mut dec: Aes = MaybeUninit::zeroed().assume_init();
            let mut ret: i32 = wc_AesInit(&mut dec, core::ptr::null_mut(), INVALID_DEVID);
            if ret != 0 {
                 prints!("ERROR: AesInit failed for decryption, ret={}\n", ret);
                 return None;
            }
            ret = wc_AesGcmSetKey(&mut dec, &key as *const _ as *const u8, 32);
            if ret != 0 {
                prints!("ERROR: AesGcmSetKey failed for decryption, ret={}\n", ret);
                return None;
            }
            iv[..U64_SIZE].copy_from_slice(&u64::to_ne_bytes(seq_num));
            ret = wc_AesGcmDecrypt(
                &mut dec,
                buf.as_mut_ptr(),                    // [out] plain text
                (*resp_msg).payload.as_ptr(),        // [in] cipher text
                (*resp_msg).hdr.msg_sz as u32,       // [in] plain text size
                &mut iv as *mut _ as *mut u8,        // [in] iv
                IV_SIZE as u32,                      // [in] iv size
                (*resp_msg).hdr.authtag.as_ptr(),    // [in] authtag
                AES_BLOCK_SIZE as u32,               // [in] authtag size
                &(*resp_msg).hdr.algo as *const u8,  // [in] aad
                aad_len as u32                       // [in] aad size
            );
            if ret != 0 {
                prints!("ERROR: AesGcmDecrypt failed, ret={}\n", ret);
                return None;
            } else {
                prints!("INFO: SNP_GUEST_REQUEST message decrypted\n");
            }
        }
        //
        // Free the two shared pages
        //
        pgtable_make_pages_private(va1, PAGE_SIZE);
        pgtable_make_pages_private(va2, PAGE_SIZE);
        free_page(va1);
        free_page(va2);
        Some(buf.into())
    }
}

pub fn send_guest_request(payload: &[u8], msg_type: u8) -> Option<Box<[u8]>> {
    GUEST_REQUEST.lock().send(payload, msg_type)
}
