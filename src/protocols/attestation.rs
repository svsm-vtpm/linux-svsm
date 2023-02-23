/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Dov Murik <dovmurik@linux.ibm.com>
 */

use alloc::vec::Vec;
use core::mem::size_of;
use core::slice;
use uuid::Uuid;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::cpu::vmsa::Vmsa;
use crate::mem::MapGuard;
use crate::mem::{is_in_calling_area, mem_callocate};
use crate::protocols::error_codes::*;
use crate::psp::msg_report::SnpReportResponse;
use crate::psp::request::CertsBuf;
use crate::util::hash;
use crate::{psp, PAGE_SIZE};

use super::SERVICES;

/// 0
const SVSM_ATTEST_SERVICES: u32 = 0;
/// 1
const SVSM_ATTEST_SINGLE_SERVICE: u32 = 1;

/// 0x8000_1000
const SVSM_FAIL_SNP_ATTESTATION: u64 = 0x8000_1000;

#[derive(Default, Debug)]
struct AttestationResult {
    code: u64,
    services_manifest_size: u64,
    certs_size: u64,
    report_size: u64,
}

impl AttestationResult {
    pub fn from_code(code: u64) -> Self {
        Self {
            code,
            ..Default::default()
        }
    }
}

/// SVSM Spec Chapter 7 (Attestation): Table 11: Attest Services operation
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct AttestServicesRequest {
    report_gpa: u64,
    report_size: u32,
    _reserved1: [u8; 4],
    nonce_gpa: u64,
    nonce_size: u16,
    _reserved2: [u8; 6],
    services_manifest_gpa: u64,
    services_manifest_size: u32,
    _reserved3: [u8; 4],
    certs_gpa: u64,
    certs_size: u32,
    _reserved4: [u8; 4],
}

/// SVSM Spec Chapter 7 (Attestation): Table 13: Attest Single Service operation
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct AttestSingleServiceRequest {
    base: AttestServicesRequest,
    service_guid: [u8; 16],
    manifest_version: u32,
    _reserved5: [u8; 4],
}

fn add_nonce_to_buffer(
    nonce_gpa: u64,
    nonce_size: u16,
    buf: &mut Vec<u8>,
) -> Result<(), AttestationResult> {
    let nonce_gpa: PhysAddr = PhysAddr::new(nonce_gpa);
    verify_fits_in_one_page(nonce_gpa, nonce_size as usize)?;
    let map: MapGuard = MapGuard::new_private(nonce_gpa, nonce_size as u64)
        .map_err(|_| AttestationResult::from_code(SVSM_ERR_INVALID_PARAMETER))?;
    let nonce: &[u8] = map.as_bytes();
    buf.extend_from_slice(nonce);
    Ok(())
}

fn fits_in_one_page(start_gpa: PhysAddr, size: usize) -> bool {
    if size == 0 {
        return false;
    }
    let end_gpa: PhysAddr = start_gpa + size - 1usize;
    let start_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(start_gpa);
    let end_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(end_gpa);
    start_frame == end_frame
}

fn verify_fits_in_one_page(start_gpa: PhysAddr, size: usize) -> Result<(), AttestationResult> {
    if fits_in_one_page(start_gpa, size) {
        Ok(())
    } else {
        Err(AttestationResult::from_code(SVSM_ERR_INVALID_PARAMETER))
    }
}

fn verify_aligned(gpa: PhysAddr, align: u64) -> Result<(), AttestationResult> {
    if gpa.is_aligned(align) {
        Ok(())
    } else {
        Err(AttestationResult::from_code(SVSM_ERR_INVALID_PARAMETER))
    }
}

fn verify_page_aligned(gpa: PhysAddr) -> Result<(), AttestationResult> {
    if gpa.is_aligned(PAGE_SIZE) {
        Ok(())
    } else {
        Err(AttestationResult::from_code(SVSM_ERR_INVALID_ADDRESS))
    }
}

/// Map `dest_len` bytes starting at `dest_gpa` and copy the entire
/// content of `src` into that memory area. `dest_len` must be equal or
/// greater than `src.len()`
fn copy_to_caller(src: &[u8], dest_gpa: PhysAddr, dest_len: u32) -> Result<(), AttestationResult> {
    assert!(dest_len as usize >= src.len());
    let mut map: MapGuard = MapGuard::new_private(dest_gpa, dest_len as u64)
        .map_err(|_| AttestationResult::from_code(SVSM_ERR_INVALID_PARAMETER))?;
    let dest_buf: &mut [u8] = map.as_bytes_mut();
    dest_buf[..src.len()].copy_from_slice(src);
    Ok(())
}

fn get_snp_attestation_report(
    report_data: &[u8; 64],
) -> Result<(Vec<u8>, Vec<u8>), AttestationResult> {
    let mut psp_rc: u64 = 0;
    let certs_len: usize = 4 * PAGE_SIZE as usize;
    let certs_va: VirtAddr = mem_callocate(certs_len)
        .map_err(|_| AttestationResult::from_code(SVSM_ERR_INVALID_PARAMETER))?;
    let mut certs_buf: CertsBuf = CertsBuf::new(certs_va, certs_len);
    let response: SnpReportResponse =
        match psp::request::get_report(report_data, &mut psp_rc, Some(&mut certs_buf)) {
            Ok(response) => response,
            Err(_) => return Err(AttestationResult::from_code(SVSM_FAIL_SNP_ATTESTATION)),
        };
    if response.status != 0 {
        return Err(AttestationResult::from_code(SVSM_FAIL_SNP_ATTESTATION));
    }
    let report_size: usize = response.report_size as usize;
    let mut report_bytes: Vec<u8> = Vec::with_capacity(report_size);
    report_bytes.resize(report_size, 0);
    report_bytes[..].copy_from_slice(unsafe {
        slice::from_raw_parts(&response.report as *const _ as *const u8, report_size)
    });
    let mut certs_bytes: Vec<u8> = Vec::with_capacity(certs_len);
    certs_bytes.resize(certs_len, 0);
    certs_bytes[..].copy_from_slice(unsafe {
        slice::from_raw_parts(certs_va.as_ptr() as *const u8, certs_len)
    });
    Ok((report_bytes, certs_bytes))
}

fn build_services_manifest(service_guid: Option<Uuid>, manifest_version: Option<u32>) -> Vec<u8> {
    SERVICES.lock().get_manifest(service_guid, manifest_version)
}

fn attest_services(
    request: &AttestServicesRequest,
    service_guid: Option<Uuid>,
    manifest_version: Option<u32>,
) -> Result<AttestationResult, AttestationResult> {
    let report_gpa: PhysAddr = PhysAddr::new(request.report_gpa);
    verify_page_aligned(report_gpa)?;

    let services_manifest_gpa: PhysAddr = PhysAddr::new(request.services_manifest_gpa);
    verify_page_aligned(services_manifest_gpa)?;

    let certs_gpa: PhysAddr = PhysAddr::new(request.certs_gpa);
    if request.certs_size > 0 {
        verify_page_aligned(certs_gpa)?;
    }

    let services_manifest: Vec<u8> = build_services_manifest(service_guid, manifest_version);
    let services_manifest_size: u64 = services_manifest.len() as u64;
    if services_manifest.len() > request.services_manifest_size as usize {
        return Err(AttestationResult {
            code: SVSM_ERR_INVALID_PARAMETER,
            services_manifest_size,
            certs_size: 0,
            report_size: 0,
        });
    }

    let mut buffer_to_hash: Vec<u8> = Vec::new();
    add_nonce_to_buffer(request.nonce_gpa, request.nonce_size, &mut buffer_to_hash)?;
    buffer_to_hash.extend_from_slice(&services_manifest);
    let report_data: [u8; 64] = hash::sha512(&buffer_to_hash)
        .map_err(|_| AttestationResult::from_code(SVSM_ERR_INVALID_PARAMETER))?;

    let (attestation_report, certs) = get_snp_attestation_report(&report_data)?;
    let report_size: u64 = attestation_report.len() as u64;
    let certs_size: u64 = certs.len() as u64;

    if attestation_report.len() > request.report_size as usize {
        return Err(AttestationResult {
            code: SVSM_ERR_INVALID_PARAMETER,
            services_manifest_size,
            certs_size,
            report_size,
        });
    }

    copy_to_caller(&attestation_report, report_gpa, request.report_size)?;
    copy_to_caller(
        &services_manifest,
        services_manifest_gpa,
        request.services_manifest_size,
    )?;

    if request.certs_size > 0 {
        if certs_size > request.certs_size as u64 {
            return Err(AttestationResult {
                code: SVSM_ERR_INVALID_PARAMETER,
                services_manifest_size,
                certs_size,
                report_size,
            });
        }

        copy_to_caller(&certs, certs_gpa, request.certs_size)?;
    }

    Ok(AttestationResult {
        code: SVSM_SUCCESS,
        services_manifest_size,
        certs_size,
        report_size,
    })
}

fn map_request_area(
    request_gpa: PhysAddr,
    request_size: usize,
) -> Result<MapGuard, AttestationResult> {
    verify_aligned(request_gpa, 8)?;
    verify_fits_in_one_page(request_gpa, request_size)?;

    let map_res: Result<MapGuard, MapToError<_>>;
    if is_in_calling_area(request_gpa) {
        map_res = MapGuard::new_private_persistent(request_gpa, request_size as u64);
    } else {
        map_res = MapGuard::new_private(request_gpa, request_size as u64);
    }
    let request_map: MapGuard =
        map_res.map_err(|_| AttestationResult::from_code(SVSM_ERR_INVALID_PARAMETER))?;
    Ok(request_map)
}

fn handle_attest_services_request_inner(
    request_gpa: PhysAddr,
) -> Result<AttestationResult, AttestationResult> {
    let request_map: MapGuard = map_request_area(request_gpa, size_of::<AttestServicesRequest>())?;
    let request: &AttestServicesRequest = request_map.as_object();
    attest_services(request, None, None)
}

unsafe fn handle_attest_services_request(vmsa: *mut Vmsa) {
    let request_gpa: PhysAddr = PhysAddr::new((*vmsa).rcx());
    let r: AttestationResult = match handle_attest_services_request_inner(request_gpa) {
        Ok(r) => r,
        Err(r) => r,
    };
    (*vmsa).set_rax(r.code);
    (*vmsa).set_rcx(r.services_manifest_size);
    (*vmsa).set_rdx(r.certs_size);
    (*vmsa).set_r8(r.report_size);
}

fn handle_attest_single_services_request_inner(
    request_gpa: PhysAddr,
) -> Result<AttestationResult, AttestationResult> {
    let request_map: MapGuard =
        map_request_area(request_gpa, size_of::<AttestSingleServiceRequest>())?;
    let request: &AttestSingleServiceRequest = request_map.as_object();
    let base_request: &AttestServicesRequest = &request.base;
    let service_guid: Uuid = Uuid::from_bytes_le(request.service_guid);
    attest_services(
        base_request,
        Some(service_guid),
        Some(request.manifest_version),
    )
}

unsafe fn handle_attest_single_service_request(vmsa: *mut Vmsa) {
    let request_gpa: PhysAddr = PhysAddr::new((*vmsa).rcx());
    let r: AttestationResult = match handle_attest_single_services_request_inner(request_gpa) {
        Ok(r) => r,
        Err(r) => r,
    };
    (*vmsa).set_rax(r.code);
    (*vmsa).set_rcx(r.services_manifest_size);
    (*vmsa).set_rdx(r.certs_size);
    (*vmsa).set_r8(r.report_size);
}

pub unsafe fn attestation_handle_request(callid: u32, vmsa: *mut Vmsa) {
    match callid {
        SVSM_ATTEST_SERVICES => handle_attest_services_request(vmsa),
        SVSM_ATTEST_SINGLE_SERVICE => handle_attest_single_service_request(vmsa),

        _ => (*vmsa).set_rax(SVSM_ERR_UNSUPPORTED_CALLID),
    };
}
