#!/bin/bash

# ############################################################
# create and write a host specific root CA configuration.
# ############################################################

function rootca_config_create() {
    local root_ca_config=${1:-/tmp/TPM/tpm2_ca_csr.config.txt}
    local hostname=$(hostname -s)
    mkdir -p $(dirname ${root_ca_config})
    cat <<EOF > ${root_ca_config}
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
x509_extensions = v3_ca

[v3_ca]
subjectKeyIdentifier = hash
basicConstraints = CA:TRUE
keyUsage = critical, keyCertSign, cRLSign

[dn]
O  = IBM Self-signed TPM root CA for ${hostname}
OU = IBM Self-signed TPM root CA for ${hostname}
CN = IBM Self-signed TPM root CA for ${hostname}
EOF
}

# ############################################################
# create a root CA or fail and exit.
# inputs:
#     file name of the root CA to be created
#     file name of the private key for the root CA to be created
#     file name of the configuration for creating the root CA.
# outputs:
#     root CA
#     private key for root CA
#     (discard) configuration used to create root CA
# ############################################################

function rootca_create () {
    local root_ca_crt=${1:-/tmp/TPM/root_ca_cert.crt}
    local root_ca_privkey=${2:-/tmp/TPM/root_ca_privkey.pem}
    local root_ca_config=${3:-/tmp/TPM/tpm2_ca_csr.config.txt}
    local ecc=${4:-0}

    # password - we don't care, we'll throw away the private key anyway.
    echo "+ rootca_create: start"
    local root_ca_pass="temp4now"
    
    # create a private key for the root CA
    echo "    Creating a private key for the root CA"

    if [[ ${ecc} == 1 ]]
    then
        openssl genpkey -algorithm ec \
                -pkeyopt ec_paramgen_curve:prime256v1 \
                -pass "pass:${root_ca_pass}" > ${root_ca_privkey} 2>/dev/null
    else
        openssl genpkey -algorithm RSA -aes-256-cbc \
                -pkeyopt rsa_keygen_bits:2048 \
                -pass "pass:${root_ca_pass}" > ${root_ca_privkey} 2>/dev/null
    fi
    if [[ $? != 0 ]] ; then echo "failed" ; exit 1 ; fi

    # write configuration to file
    rootca_config_create ${root_ca_config}
    
    # make the certificate
    echo "    Creating the root CA"
    openssl req -batch -verbose -new -sha256 -x509 -days 365 \
            -key ${root_ca_privkey} -passin "pass:${root_ca_pass}" \
            -out ${root_ca_crt} -config ${root_ca_config} > /dev/null 2>&1
    if [[ $? != 0 ]] ; then echo "failed" ; exit 1 ; fi

    echo "- rootca_create: success"
    return 0
}




rootca_create root_ca_cert.crt root_ca_privkey.pem root_ca_cert.cfg 1
