## vTPM Rust implementation
---

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
    - create EK, EK-cert, Platform-cert
    - install (i.e., write to NVRAM)

* Readings:
  - [TCG PC Client Platform TPM Profile (PTP) Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/)
  - [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
  - [Bindgen](https://rust-lang.github.io/rust-bindgen/)
  - [WolfSSL error codes](https://www.wolfssl.com/documentation/manuals/wolfssl/appendix06.html)
  - [Tock registers crate](https://crates.io/crates/tock-registers)

### External dependencies

The following external deps are automatically built by cargo using `build.rs`
* ms-tpm-20-ref
* wolfssl

### MS-TPM wrappers
* ms-tpm-20-ref build invokes make to trigger building only the needed
  libraries (`libtpm.a` and `libplatform.a`) to avoid dealing with the error in
  missing symbols for the `tpm2-Simulator`. To support that, a config argument
  is introduced which would enable building the simulator only when specified
  (`--enable-simulator`).

* Copies the built libraries to `external/build/lib`

* Header files are not copied

### WolfSSL wrappers
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


## Future directions

* Implement attestation report request
  - Post manufacturing, we need to generate an attestation report from SVSM by
    communicating with the AMD-SP. This involves creating a request, encrypting
    it and sending it off to the AMD-SP and do the reverse (receive the
    response, decrypt) and store it in an immutable index in the NVRAM.

* Modify Keylime to handle the generated attestaion report
  - Keylime has to be modified to handle how to validate the attestation report
    - Retrieve the EK-cert from NVRAM
    - Retrieve the attestation report from SVSM
    - Verify that the digest(EK-cert) from NVRAM match with the one on the
      attestation report

* Nice to have
  - Configure the stable version of wolfssl directly in `build.rs` instead of
    having to build with our changes (`amd-svsm/user_settings.h`)
  - Robust FFI handling
    - Some wolfssl wrappers need better error handling
  - Many of the wolfssl calls are written in a procedural way
    - Rustify them

* TODO
  - Add details on what needs to rustified under wolfssl
