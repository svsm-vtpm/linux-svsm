#![allow(unused)]

use crate::bindings::*;
use crate::init::send_tpm_command;
use crate::*;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::slice;

const TPM2_ST_NO_SESSIONS: u16 = 0x8001;
const TPM2_ST_SESSIONS: u16 = 0x8002;

const TPM2_CC_EVICTCONTROL: u32 = 0x00000120;
const TPM2_CC_NV_DEFINESPACE: u32 = 0x0000012a;
const TPM2_CC_PCR_ALLOCATE: u32 = 0x0000012b;
const TPM2_CC_CREATEPRIMARY: u32 = 0x00000131;
const TPM2_CC_NV_WRITE: u32 = 0x00000137;
const TPM2_CC_NV_WRITELOCK: u32 = 0x00000138;
const TPM2_CC_SHUTDOWN: u32 = 0x00000145;
const TPM2_CC_GETCAPABILITY: u32 = 0x0000017a;

const TPM2_SU_CLEAR: u16 = 0x0000;

const TPM2_RH_OWNER: u32 = 0x40000001;
const TPM2_RS_PW: u32 = 0x40000009;
const TPM2_RH_ENDORSEMENT: u32 = 0x4000000b;
const TPM2_RH_PLATFORM: u32 = 0x4000000c;

const TPM2_ALG_RSA: u16 = 0x0001;
const TPM2_ALG_SHA1: u16 = 0x0004;
const TPM2_ALG_AES: u16 = 0x0006;
const TPM2_ALG_SHA256: u16 = 0x000b;
const TPM2_ALG_SHA384: u16 = 0x000c;
const TPM2_ALG_SHA512: u16 = 0x000d;
const TPM2_ALG_SHA3_256: u16 = 0x0027;
const TPM2_ALG_SHA3_384: u16 = 0x0028;
const TPM2_ALG_SHA3_512: u16 = 0x0029;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_ALG_SM3: u16 = 0x0012;
const TPM2_ALG_ECC: u16 = 0x0023;
const TPM2_ALG_CFB: u16 = 0x0043;

const TPM2_CAP_PCRS: u32 = 0x00000005;

const TPM2_ECC_NIST_P384: u32 = 0x0004;

const TPMA_NV_PLATFORMCREATE: u32 = 0x40000000;
const TPMA_NV_AUTHREAD: u32 = 0x40000;
const TPMA_NV_NO_DA: u32 = 0x2000000;
const TPMA_NV_PPWRITE: u32 = 0x1;
const TPMA_NV_PPREAD: u32 = 0x10000;
const TPMA_NV_OWNERREAD: u32 = 0x20000;
const TPMA_NV_WRITEDEFINE: u32 = 0x2000;

const TPM2_NV_INDEX_RSA2048_EKCERT: u32 = 0x01c00002;
const TPM2_NV_INDEX_RSA2048_EKTEMPLATE: u32 = 0x01c00004;
const TPM2_NV_INDEX_RSA3072_HI_EKCERT: u32 = 0x01c0001c;
const TPM2_NV_INDEX_RSA3072_HI_EKTEMPLATE: u32 = 0x01c0001d;
// For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
// Specification Version 2.1; Revision 13; 10 December 2018
const TPM2_NV_INDEX_PLATFORMCERT: u32 = 0x01c08000;

const TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT: u32 = 0x01c00016;
const TPM2_NV_INDEX_ECC_SECP384R1_HI_EKTEMPLATE: u32 = 0x01c00017;

const TPM2_EK_RSA_HANDLE: u32 = 0x81010001;
const TPM2_EK_RSA3072_HANDLE: u32 = 0x8101001c;
const TPM2_EK_ECC_SECP384R1_HANDLE: u32 = 0x81010016;
const TPM2_SPK_HANDLE: u32 = 0x81000001;

impl tpm_req_header {
    fn new(tag: u16, size: u32, ord: u32) -> Self {
        Self {
            tag: tag.to_be(),
            size: size.to_be(),
            ordinal: ord.to_be(),
        }
    }
    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const tpm_req_header as *const u8,
                core::mem::size_of::<tpm_req_header>(),
            )
        }
    }
    fn set_size(&mut self, size: u32) {
        self.size = size.to_be();
    }
    fn size() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}

impl tpm2_authblock {
    fn new(auth: u32, foo: u16, continue_session: u8, bar: u16) -> Self {
        Self {
            auth: auth.to_be(),
            foo: foo.to_be(),
            continueSession: continue_session,
            bar: bar.to_be(),
        }
    }
    fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const tpm2_authblock as *const u8,
                core::mem::size_of::<tpm2_authblock>(),
            )
        }
    }
    fn size() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}

impl tpm2_evictcontrol_req {
    fn new(
        hdr: tpm_req_header,
        auth: u32,
        obj_handle: u32,
        authblk_len: u32,
        authblock: tpm2_authblock,
        persistent_handle: u32,
    ) -> Self {
        tpm2_evictcontrol_req {
            hdr: hdr,
            auth: auth,
            objectHandle: obj_handle,
            authblockLen: authblk_len,
            authblock: authblock,
            persistentHandle: persistent_handle,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *mut tpm2_evictcontrol_req as *mut u8,
                core::mem::size_of::<tpm2_evictcontrol_req>(),
            )
        }
    }
    fn size() -> u32 {
        core::mem::size_of::<Self>() as u32
    }
}

pub fn tpm2_create_ek_rsa2048() {
    let mut keyflags: u32 = 0;
    let symkeylen: u16 = 128;
    let authpolicy_len: u16 = 32;
    let rsa_keysize: u16 = 2048;
    let tpm2_ek_handle: u32 = TPM2_EK_RSA_HANDLE;
    let authpolicy: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa,
    ];
    // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
    // adminWithPolicy, restricted, decrypt
    keyflags |= 0x000300b2;
    // symmetric: TPM_ALG_AES, 128bit or 256bit, TPM_ALG_CFB
    let symkeydata_len = 6;
    let symkeydata: &[u8] = &[
        TPM2_ALG_AES.to_be_bytes(),
        symkeylen.to_be_bytes(),
        TPM2_ALG_CFB.to_be_bytes(),
    ]
    .concat();

    let mut hdr: tpm_req_header = tpm_req_header::new(TPM2_ST_SESSIONS, 0, TPM2_CC_CREATEPRIMARY);
    let authblock: tpm2_authblock = tpm2_authblock::new(TPM2_RS_PW, 0, 0, 0);

    let mut nonce_rsa2048: [u8; 0x102] = [0; 0x102];
    nonce_rsa2048[0..2].copy_from_slice(&0x100_u16.to_be_bytes());

    let mut public: Vec<u8> = Vec::new();
    public.extend_from_slice(&TPM2_ALG_RSA.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());
    public.extend_from_slice(&keyflags.to_be_bytes());
    public.extend_from_slice(&authpolicy_len.to_be_bytes());
    public.extend_from_slice(&authpolicy);
    public.extend_from_slice(&symkeydata);
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public.extend_from_slice(&rsa_keysize.to_be_bytes());
    public.extend_from_slice(&0_u32.to_be_bytes());
    public.extend_from_slice(&nonce_rsa2048);

    let mut create_primary_req: Vec<u8> = Vec::new();
    create_primary_req.extend_from_slice(hdr.as_slice());
    create_primary_req.extend_from_slice(&TPM2_RH_ENDORSEMENT.to_be_bytes());
    create_primary_req.extend_from_slice(&tpm2_authblock::size().to_be_bytes());
    create_primary_req.extend_from_slice(authblock.as_slice());
    create_primary_req.extend_from_slice(&4_u16.to_be_bytes());
    create_primary_req.extend_from_slice(&0_u32.to_be_bytes());
    create_primary_req.extend_from_slice(&(public.len() as u16).to_be_bytes());
    create_primary_req.extend_from_slice(public.as_slice());
    create_primary_req.extend_from_slice(&0_u32.to_be_bytes());
    create_primary_req.extend_from_slice(&0_u16.to_be_bytes());

    let final_req_len = create_primary_req.len() as u32;
    let (left_hdr, _) = create_primary_req.split_at_mut(core::mem::size_of::<tpm_req_header>());
    hdr.set_size(final_req_len);
    left_hdr.copy_from_slice(hdr.as_slice());
    let create_primary_resp = send_tpm_command(create_primary_req.as_mut_slice());

    let handle_data: &[u8] = &create_primary_resp.data[10..14];
    let curr_handle = u32::from_be_bytes([
        handle_data[0],
        handle_data[1],
        handle_data[2],
        handle_data[3],
    ]);

    tpm2_evictcontrol(curr_handle, tpm2_ek_handle);
}

fn tpm2_evictcontrol(curr_handle: u32, perm_handle: u32) {
    let mut hdr: tpm_req_header = tpm_req_header::new(
        TPM2_ST_SESSIONS,
        tpm2_evictcontrol_req::size(),
        TPM2_CC_EVICTCONTROL,
    );
    let authblock: tpm2_authblock = tpm2_authblock::new(TPM2_RS_PW, 0, 0, 0);
    let mut req: tpm2_evictcontrol_req = tpm2_evictcontrol_req::new(
        hdr,
        TPM2_RH_OWNER.to_be(),
        curr_handle.to_be(),
        tpm2_authblock::size().to_be(),
        authblock,
        perm_handle.to_be(),
    );

    send_tpm_command(req.as_mut_slice());
}

/// Get the TPM EKpub in the TSS format (marshaled TPM2B_PUBLIC structure)
/// TSS format e.g.: tpm2_createek -c 0x81000000 -G rsa -f tss -u /tmp/ekpub.tss
pub fn tpm2_get_ek_pub() -> Vec<u8> {
    // TPM2_CC_ReadPublic 0x00000173
    let mut cmd_req: &mut [u8] = &mut [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x73, 0x81, 0x01, 0x00, 0x01,
    ];
    // TPM command response buffer
    let mut response_buf: TpmResponse = send_tpm_command(&mut cmd_req);
    let mut response_size: i32 = response_buf.data.len() as i32;

    // Output parameters
    let out_parms: &[u8] = &response_buf.data[{tpm_req_header::size() as usize}..];

    const U16_SIZE: usize = core::mem::size_of::<u16>();

    // TPM2B_PUBLIC.size field
    let size: u16 = u16::from_be_bytes(out_parms[..U16_SIZE].try_into().unwrap());
    if size as usize > core::mem::size_of::<TPMT_PUBLIC>() {
        prints!("ERROR: TPM2B_PUBLIC.size={:#x} is too big\n", size);
        return Vec::new();
    }

    // TPM2B_PUBLIC structure
    let out_public: &[u8] = &out_parms[..{size as usize + U16_SIZE}];
    //prints!("out_public {:x} {:02x?}\n", {out_public.len()}, out_public);
    out_public.to_vec()
}
