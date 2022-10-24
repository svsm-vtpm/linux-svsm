# SVSM-Based vTPM implementation PoC

This Proof-of-Concept is made to demonstrate the ability of using AMD's SVSM (Secure VM Service Module) to implement a vTPM that cannot be tampered by any entity with access to the host or guest system, and can be used for measured boot with KeyLime. In other words, we aim at implementing a vTPM **as safe as** a physical TPM; however, we are currently limiting ourselves to a use-case scenario where the vTPM is used only for measured boot. We are not trying to implement a generic vTPM that entirely follows the TPM specifications.

## Limits of this approach

The main limit of this approach is that a new vTPM is manufactured every time the VM is booted. This means that the vTPM will not have a persistent state that will be retained after a reboot, and there is virtually no way to establish any logical connection between two instances of the same VM.

We are doing this to simplify the boot process and remove the need of direct communications between the SVSM and a client attestation service.

Any use of TPM that leverages a persistent state will not work with this implementation of vTPM

## High-level flow and security properties

### Secure VM boot

Since we are leveraging the SVSM, the Hypervisor will start the system in VMPL0, but instead of starting the firmware (namely OVMF), it will start the SVSM. In the current implementation proposed by AMD, both SVSM and OVMF will be measured and encrypted at boot using the LAUNCH_UPDATE function.

Running the vTPM code inside the SVSM makes it protected both from host access (the memory is encrypted) and from guest access (guest runs at a lower VMPL, and the SVSM can protect its pages so that any request to access them from VMPL>0 will result in an exception that can only be handled by SVSM in VMPL0).

### Initializing the vTPM

When the SVSM starts, before control is given to the firmware, we initialize the vTPM.
This initialization follows the classic TPM manufacturing process. This mainly consists in
creating an EK. We won't create EK and platform certificates, since there is no entity above the vTPM that can sign those certificates.

Manufacturing is done using randomly-generated seeds, so that there is no need to communicate the seeds to the vTPM before boot. However, this makes the manufacturing process non-repeatable, and every boot a different EK will be generated.

### Trusting the initialized vTPM

Since the vTPM is manufactured with random seeds at boot, we need a way to connect the vTPM state to the SVSM code, to make sure that:
1. We can certify that *this* is the state of the vTPM running inside the SVSM
2. We can certify that the vTPM code has not been tampered with

For 2., the code of both the SVSM and the vTPM are measured by AMD's hardware before VM boot. This means that we can request an AMD SEV attestation report after the VM is started, to verify both SVSM and vTPM code.

For 1., the attestation report has a 512-bit field called `USER_DATA`, which can be used by the entity requesting the attestation report, to add data that will then be included in the report and, like the rest of the report, signed with AMD's keys to guarantee it was not tampered with after generation.

The vTPM code running in the SVSM can ask for the generation of an attestation report *after manufacturing*, and place its EKPub in the `USER_DATA` field. The field is too small to contain a plain EKPub, but can contain a digest of EKPub. This will effectively bond the vTPM EK to the secure VM running the SVSM+vTPM.

This attestation report will then be saved in the vTPM's NVRAM at a well-known location, so that a keylime agent will be able to gather it and send it to a keylime server for authentication.

### vTPM interface

The vTPM requires an interface with the VMPL1-based guest to exchange requests and responses following a pre-defined protocol. For this PoC we decided to implement a CRB-based protocol. A vTPM device is set-up by the Hypervisor (QEMU) in a similar manner as done with swtpm (the current software-based vTPM implementation).
However, the `buffer` area is set up to point to a shared SVSM<->guest encrypted area, instead of being trapped by the Hypervisor as usually happen with swtpm.
This allows free exchange of requests and responses between the SVSM-based vTPM and the Guest O.S. driver.
Unfortunately, there is a significant synchronization problem. `CRB` is written assuming that the two communicating entities (TPM and Guest) are both active listeners to the buffers and can poll it to find new messages. Unfortunately, this is not the case in our scenario. The vCPU on the VM will keep running on VMPL1 unless there is an exception, interrupt or any event that triggers a VMEXIT. Only at that point the Hypervisor can restart the vCPU in VMPL0. Therefore, we need to apply a small change to the Linux and OVMF `CRB` drivers, to ring a bell after a message (or a group of messages if wanted) is stored inside the CRB Buffer.

This way, the vTPM appears as a normal device to the Guest O.S., which can interact with it using the (almost) standard `CRB` device driver.

### Remainder of boot process

The remainder of the boot process is very similar to the normal SVSM boot process. SVSM will change processor state to VMPL1 and start the firmware (OVMF). At this point, OVMF will see a vTPM and can start a measured boot. OVMF first, then the boot loader and finally the Linux Kernel will keep writing digests in the proper PCR registers of the vTPM.

### Gathering vTPM data and attesting it

Once the system is fully booted, we can use the keylime agent to gather all the vTPM data and send it to a keylime server for attestation/validation. This procedure is very similar to what usually happens with the keylime agent with a hardware TPM. The only difference is that the agent will also have to retrieve the attestation report saved in NVRAM and forward it, along with the measurements, to the keylime server.

On the server side, during registration, keylime usually runs a script with the EK and EK cert as arguments to confirm that the TPM is the expected one for a particular keylime agent. For our changed attestation workflow to work, we need to modify this part to allow "trust on first use" for vTPM EKs that are not predictable, but add a verification step for the EK that, instead of using a TA certificate to authenticate the EK certificate, uses the SEV attestation report to:
1. Verify that the encrypted memory of the VM contained the right version of SVSM+vTPM(+OVMF) code by checking the attestation report measurements
2. Verify that the attestation report was created in VMPL0
3. Verify that the `USER_DATA` field contains a valid digest of EKPub.


If these three conditions are verified, then the vTPM and its EK can be trusted and we can register this node. At this point, we can use PCR values to perform a normal measured boot attestation.

## Security properties of the vTPM identity

In this section we aim to prove that a vTPM identity generated this way cannot be tampered in any way.
We implicitly trust the vTPM EK key because we trust the attestation report. While the attestation report cannot be tampered after generation, an attacker could try to generate a different attestation report, containing a different EK hash in the `USER_DATA` field. Let's see why this is not possible:

1. The Guest OS cannot generate a different Attestation Report: the report contains the VMPL layer that asked for the report. Since the Guest OS is now running at VMPL>0, the Keylime Server can easily verify that the report was generated by VMPL0, i.e. SVSM+vTPM code

2. The Guest OS of a different Secure VM, running without SVSM, cannot generate a different Attestation Report: In this case, the VMPL check would pass (guest would be running at VMPL0); however, the memory measurement won't, because it won't contain the hash of the SVSM, or the BSP would be pointing to the wrong start address

3. The SVSM of a different Secure VM cannot generate a different Attestation Report: For this to happen, the SVSM would need to be malicious, or to the very least different than the ones we have implemented, so the memory measurement in the report will fail.

---

## Implementation Details

### Cargo build scripts (`build.rs`)

* We use `build.rs` that
  - builds external dependencies
  - takes care of generating the FFI headers
  for calling into the c-style libraries (`libwolfssl.a`, `libtpm.a`, and
  `libplatform.a`) using [Bindgen](https://github.com/rust-lang/rust-bindgen)

### Implementation

* vTPM implementation consists of the following (implemented in Rust with calls
  to c-wrappers for crypto and TPM stuff)
  * CRB register definitions (`tock-registers` style)
  * CRB state machine handling
  * TPM initialization
  * TPM manufacturing
    - create EK
    - install (i.e., write to NVRAM)

* Readings:
  - [AMD Secure Encrypted Virtualization (SEV)](https://developer.amd.com/sev/)
  - [TCG PC Client Platform TPM Profile (PTP) Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
  - [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
  - [Bindgen](https://rust-lang.github.io/rust-bindgen/)
  - [WolfSSL error codes](https://www.wolfssl.com/documentation/manuals/wolfssl/appendix06.html)
  - [Tock registers crate](https://crates.io/crates/tock-registers)

### External dependencies

The following external dependencies are automatically built by cargo using `build.rs`
* ms-tpm-20-ref
* wolfssl
* libcrt
* libm

### MS-TPM build
* The ms-tpm-20-ref build invokes make to trigger building only the needed
  libraries (`libtpm.a` and `libplatform.a`) to avoid dealing with the error in
  missing symbols for the `tpm2-Simulator`. To support that, a config argument
  is introduced which would enable building the simulator only when specified
  (`--enable-simulator`).

* Copies the built libraries to `external/build/lib`

* Header files are not copied

### WolfSSL build
* Wolfssl is built automatically. But there are some improvements to be done.
  - We shall switch to [wolf-sys](https://crates.io/crates/wolfssl-sys). But this crate
    supports only hardcoded options for their usecase
  - How do we do a clean build?
    ```
    pushd external/wolfssl
    make distclean
    popd
    # build.rs is triggered by cargo which should build wolfssl
    make
    ```
* Post build, the libraries (`libwolfssl.a`) are copied to `external/build/lib`
  and the headers are installed under (`external/build/include/wolfssl/`)

## Rust lint warnings
---

* You will notice a bunch of warnings from `bindings.rs` that `u128` is not
  FFI-safe. At the moment, we have to live with it as there is no solution.
  Check https://github.com/rust-lang/rust/issues/54341 for more details. But it
  has to be taken care that we do not pass `u128`'s across the FFI boundary.
```
     |         __value: u128,
     |                  ^^^^ not FFI-safe
```

## To Be Done in the PoC

* Implement attestation report request inside SVSM (currently, no attestation report is generated)
  - Post manufacturing, we need to generate an attestation report from SVSM by
    communicating with the AMD-SP. This involves creating a request, encrypting
    it and sending it off to the AMD-SP and do the reverse with the response and
    store the report in an immutable index in the NVRAM.

* Modify Keylime to handle the generated attestation report
  - Keylime has to be modified to handle how to validate the attestation report
    - On the Keylime Agent:
      - Retrieve the EK from NVRAM
      - Retrieve the attestation report from NVRAM
      - (Possibly) Extend communication protocol between Agent and Server to exchange additional information
    - On the Keylime Server:
      - Verify that the digest of EKPub matches with the one inside the attestation report
      - Apply Trust-on-first-use policy if the two EK match

* Modify OVMF to support SVSM and add a doorbell mechanism in the TPM CRB driver

* Nice to have, but not necessary for our Security model
  - Configure the stable version of wolfssl directly in `build.rs` instead of
    having to build with our changes (`amd-svsm/user_settings.h`)
  - Robust FFI handling
    - Some wolfssl wrappers need better error handling
  - Many of the wolfssl calls are written in a procedural way
    - Rustify them
  - Move from wolfssl to OpenSSL for licensing reasons
