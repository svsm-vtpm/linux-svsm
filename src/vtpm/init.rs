/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 IBM
 *
 * Authors: Vikram Narayanan <>
 *
 */

use crate::println;
use crate::util::locking::SpinLock;
use crate::*;
use alloc::vec::Vec;
use bindings::*;
use cty::c_void;
use lazy_static::lazy_static;
use x86_64::PhysAddr;

use tock_registers::{
    interfaces::{ReadWriteable, Writeable},
    register_bitfields, register_structs,
    registers::ReadWrite,
};

static mut IS_POWER_ON: bool = false;
const TPM_CRB_BASE: u64 = 0xFED4_0000;
const TPM_CRB_REGION_SIZE: u64 = 0x1000;

unsafe fn rpc_signal_power_on(is_reset: bool) {
    // if power is on and this is not a call to do TPM reset then return
    if IS_POWER_ON && !is_reset {
        return;
    }
    // If this is a reset but power is not on, then return
    if is_reset && !IS_POWER_ON {
        return;
    }
    // Unless this is just a reset, pass power on signal to platform
    if !is_reset {
        _plat__Signal_PowerOn();
    }
    // Power on and reset both lead to _TPM_Init()
    _plat__Signal_Reset();

    // Set state as power on
    IS_POWER_ON = true;
}

lazy_static! {
    pub static ref TPM_CRB_REGS: SpinLock<&'static mut TpmCrbRegisters> = {
        let crb_pa = PhysAddr::new(TPM_CRB_BASE);

        let crb_va = match pgtable_map_pages_private(crb_pa, TPM_CRB_REGION_SIZE) {
            Ok(v) => v,
            Err(_e) => vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_ENOMEM),
        };

        pgtable_make_pages_shared(crb_va, TPM_CRB_REGION_SIZE);

        let crb_regs = unsafe { &mut *crb_va.as_mut_ptr() as &mut TpmCrbRegisters };

        SpinLock::new(crb_regs)
    };
}

register_structs! {
    pub TpmCrbRegisters {
        (0x0000 => loc_state: ReadWrite<u32, LocState::Register>),
        (0x0004 => _reserved),
        (0x0008 => loc_ctrl: ReadWrite<u32, LocCtrl::Register>),
        (0x000c => loc_sts: ReadWrite<u32, LocSts::Register>),
        (0x0010 => _reserved1),
        (0x0030 => intf_id: ReadWrite<u32, IntfId::Register>),
        (0x0034 => intf_id2: ReadWrite<u32, IntfId2::Register>),
        (0x0038 => ctrl_ext: ReadWrite<u64>),
        (0x0040 => ctrl_req: ReadWrite<u32, CtrlReq::Register>),
        (0x0044 => ctrl_sts: ReadWrite<u32, CtrlSts::Register>),
        (0x0048 => ctrl_cancel: ReadWrite<u32>),
        (0x004c => ctrl_start: ReadWrite<u32>),
        (0x0050 => int_enable: ReadWrite<u32>),
        (0x0054 => int_status: ReadWrite<u32>),
        (0x0058 => ctrl_cmd_size: ReadWrite<u32>),
        (0x005c => ctrl_cmd_laddr: ReadWrite<u32>),
        (0x0060 => ctrl_cmd_haddr: ReadWrite<u32>),
        (0x0064 => ctrl_rsp_size: ReadWrite<u32>),
        (0x0068 => ctrl_rsp_addr: ReadWrite<u64>),
        (0x0070 => _reserved2),
        (0x0080 => cmd_buffer: [ReadWrite<u32>; 512]),
        (0x0880 => @END),
    }
}

register_bitfields! {
    u32,
    LocState [
        TpmRegValidSts          OFFSET(7) NUMBITS(1) [],
        ActiveLocality          OFFSET(2) NUMBITS(3) [],
        LocAssinged             OFFSET(1) NUMBITS(1) [],
        TpmEstablished          OFFSET(0) NUMBITS(1) [],
    ],

    LocCtrl [
        ResetEstablishmentBit   OFFSET(3) NUMBITS(1) [],
        Seize                   OFFSET(2) NUMBITS(1) [],
        Relinquish              OFFSET(1) NUMBITS(1) [],
        RequestAccess           OFFSET(0) NUMBITS(1) [],
    ],

    LocSts [
        BeenSeized              OFFSET(1) NUMBITS(1) [],
        Granted                 OFFSET(0) NUMBITS(1) [],
    ],

    IntfId [
        RID                     OFFSET(24) NUMBITS(8) [],
        IntfSelLock             OFFSET(19) NUMBITS(1) [],
        InterfaceSelector       OFFSET(17) NUMBITS(2) [
            IfSelectorCrb = 0b1,
        ],
        CapIFRes                OFFSET(15) NUMBITS(2) [],
        CapCRB                  OFFSET(14) NUMBITS(1) [
            CapCrbSupported = 0b1,
        ],
        CapFIFO                 OFFSET(13) NUMBITS(1) [
            FifoNotSupported = 0b0,
        ],
        CapDataXferSizeSupport  OFFSET(11) NUMBITS(2) [
            Transfer_4B = 0b00,
            Transfer_8B = 0b01,
            Tranfer_32B = 0b10,
            Transfer_64B = 0b11,
        ],
        CapCRBIdleBypass        OFFSET(9)  NUMBITS(1) [
            CapIdleFast = 0b0,
        ],
        CapLocality             OFFSET(8)  NUMBITS(1) [
            Locality0 = 0b0,
        ],
        InterfaceVersion        OFFSET(4)  NUMBITS(4) [
            CrbVersion = 0b0001,
        ],
        InterfaceType           OFFSET(0)  NUMBITS(4) [
            CrbActive = 0b0001,
        ],
    ],

    IntfId2 [
        DID                     OFFSET(16) NUMBITS(16) [],
        VID                     OFFSET(0)  NUMBITS(16) [
            VENDOR_SVSM = 0xABCD,
        ],
    ],

    CtrlReq [
        goIdle                  OFFSET(1) NUMBITS(1) [],
        cmdReady                OFFSET(0) NUMBITS(1) [],
    ],

    CtrlSts [
        tpmIdle                 OFFSET(1) NUMBITS(1) [],
        tpmSts                  OFFSET(0) NUMBITS(1) [],
    ],
}

fn tpm_crb_init() {
    lazy_static::initialize(&TPM_CRB_REGS);

    #[rustfmt::skip]
    {
        let crb_regs = TPM_CRB_REGS.lock();

        crb_regs.loc_state.write(LocState::TpmRegValidSts.val(1));

        crb_regs.ctrl_sts.write(CtrlSts::tpmIdle.val(1));

        crb_regs.intf_id.write(IntfId::InterfaceType::CrbActive);
        crb_regs.intf_id.modify(IntfId::InterfaceVersion::CrbVersion);
        crb_regs.intf_id.modify(IntfId::CapLocality::Locality0);
        crb_regs.intf_id.modify(IntfId::CapCRBIdleBypass::CapIdleFast);
        crb_regs.intf_id.modify(IntfId::CapDataXferSizeSupport::Transfer_64B);
        crb_regs.intf_id.modify(IntfId::CapFIFO::FifoNotSupported);
        crb_regs.intf_id.modify(IntfId::CapCRB::CapCrbSupported);
        crb_regs.intf_id.modify(IntfId::InterfaceSelector::IfSelectorCrb);
        crb_regs.intf_id.modify(IntfId::RID.val(0b0000));

        crb_regs.intf_id2.write(IntfId2::VID::VENDOR_SVSM);

        crb_regs.ctrl_cmd_size.set(TPM_CRB_REGION_SIZE as u32 - 0x80);
        crb_regs.ctrl_cmd_laddr.set(TPM_CRB_BASE as u32 + 0x80);

        crb_regs.ctrl_rsp_size.set(TPM_CRB_REGION_SIZE as u32 - 0x80);
        crb_regs.ctrl_rsp_addr.set(TPM_CRB_BASE + 0x80);
    }
    println!("TPM CRB registers initialized!");
}

pub struct TpmResponse {
    pub data: Vec<u8>,
}

pub fn send_tpm_command(request: &mut [u8]) -> TpmResponse {
    let default_vec_size: usize = 4096;

    let mut __resp_sz: u32 = default_vec_size.try_into().unwrap();
    let mut _resp_sz: *mut u32 = &mut __resp_sz;

    let mut __resp_vec: Vec<u8> = Vec::with_capacity(default_vec_size);
    let mut _resp_vec: *mut u8 = __resp_vec.as_mut_ptr();
    unsafe {
        let resp_vec: *mut *mut u8 = &mut _resp_vec as *mut *mut u8;

        ExecuteCommand(
            request.len() as u32,
            request.as_mut_ptr(),
            _resp_sz,
            resp_vec,
        );
        __resp_vec.set_len(__resp_sz as usize);
    }
    let tpm_resp: TpmResponse = TpmResponse {
        data: __resp_vec,
    };
    tpm_resp
}

pub fn vtpm_init() {
    tpm_crb_init();
    unsafe {
        _plat__NVEnable(core::ptr::null::<c_void>() as *mut c_void);

        if _plat__NVNeedsManufacture() == 1 {
            if TPM_Manufacture(1) != 0 {
                _plat__NVDisable(1);
                println!("Manufacturing failed");
            }

            // Coverage test - repeated manufacturing attempt
            if TPM_Manufacture(0) != 1 {
                println!("Manufacturing failed 1!");
            }

            // Coverage test - re-manufacturing
            TPM_TearDown();

            if TPM_Manufacture(1) != 0 {
                println!("Manufacturing failed 2!");
            }
        }

        _plat__SetNvAvail();

        rpc_signal_power_on(false);
    }
    let mut cmd1: &mut [u8] = &mut [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x00,
    ];
    let mut cmd2: &mut [u8] = &mut [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    send_tpm_command(&mut cmd1);
    send_tpm_command(&mut cmd2);
    let keytype: KeyType = KeyType::Rsa2048;
    manufacture::tpm2_create_ek(keytype);
    manufacture::tpm2_get_ek_pub();
}
