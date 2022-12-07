#pragma once

#include <stdint.h>
#include "Tpm.h"
#include "TpmTypes.h"
#include "ExecCommand_fp.h"
#include "wolfssl/openssl/bn.h"
#include "wolfssl/openssl/ssl.h"
#include "wolfssl/wolfcrypt/sha512.h"

#define TPM_ALG_RSA                     (ALG_RSA_VALUE)
#define TPM_RC_SUCCESS                  (0x000)

struct tpm_req_header {
    uint16_t tag;
    uint32_t size;
    uint32_t ordinal;
} __attribute__((packed));

struct tpm_resp_header {
    uint16_t tag;
    uint32_t size;
    uint32_t errcode;
} __attribute__((packed));

struct tpm2_authblock {
    uint32_t auth;
    uint16_t foo; // FIXME
    uint8_t continueSession;
    uint16_t bar; // FIMXE
} __attribute__((packed));

struct tpm2_evictcontrol_req {
    struct tpm_req_header hdr;
    uint32_t auth;
    uint32_t objectHandle;
    uint32_t authblockLen;
    struct tpm2_authblock authblock;
    uint32_t persistentHandle;
} __attribute__((packed));

struct Regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};
