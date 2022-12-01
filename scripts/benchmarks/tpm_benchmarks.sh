#!/bin/bash

# ##########################################
# ##########################################

function identify() {
    local manuf=$(tpm2_getcap properties-fixed | grep -i -A2 MANUFACTUR | grep value | awk '{ print $2 }')
    echo "===> TPM manufacturer: ${manuf}"
}

# ##########################################
# pcrread test
# ##########################################


function test_pcrread() {
    local repeats=${1:-1000}
    echo "===> pcrread test "
    echo "     repeats:               ${repeats}"
    local t0=$(date +%s%N)
    for x in `seq 1 ${repeats}`
    do
	tpm2_pcrread > /dev/null 2>&1
    done
    local t1=$(date +%s%N)
    local delta_total_ns=$((t1-t0))
    local delta_total_s=$((delta_total_ns/1000000000))
    local delta_ns=$((delta_total_ns/repeats))
    local delta_us=$((delta_ns/1000))
    echo "     test duration:         ${delta_total_s} s"
    echo "     pcrread latency:       ${delta_us} usecs"
}

# ##########################################
# pcrextend test
# ##########################################


function test_pcrextend() {
    local repeats=${1:-1000}
    echo "===> pcrextend test "
    echo "     repeats:               ${repeats}"
    local t0=$(date +%s%N)
    for x in `seq 1 ${repeats}`
    do
	tpm2_pcrextend 11:sha256=0x0000000000000000000000000000000000000000000000000000000000000001
    done
    local t1=$(date +%s%N)
    local delta_total_ns=$((t1-t0))
    local delta_total_s=$((delta_total_ns/1000000000))
    local delta_ns=$((delta_total_ns/repeats))
    local delta_us=$((delta_ns/1000))
    echo "     test duration:         ${delta_total_s} s"
    echo "     pcrextend latency:     ${delta_us} usecs"
}

# ##########################################
# createprimary test
# ##########################################

function test_quote() {
    local repeats=${1:-1000}
    local tmpdir=${2:-/tmp}
    echo "===> tpm2_quote test "
    echo "     repeats:               ${repeats}"
    (tpm2_clear && \
	 tpm2_createprimary -C e -c ${tmpdir}/primary.ctx && \
	 tpm2_create -C ${tmpdir}/primary.ctx -u ${tmpdir}/key.pub -r ${tmpdir}/key.priv && \
	 tpm2_load -C ${tmpdir}/primary.ctx -u ${tmpdir}/key.pub -r ${tmpdir}/key.priv -c ${tmpdir}/key.ctx ) > /dev/null 2>&1
    echo "     Prep exit code:        $?"

    local t0=$(date +%s%N)
    for x in `seq 1 ${repeats}`
    do
	tpm2_quote -Q -c ${tmpdir}/key.ctx -l 0x0004:16,17,18+0x000b:16,17,18
    done
    local t1=$(date +%s%N)
    rm -f ${tmpdir}/primary.ctx ${tmpdir}/key.pub ${tmpdir}/key.priv ${tmpdir}/key.ctx
    local delta_total_ns=$((t1-t0))
    local delta_total_s=$((delta_total_ns/1000000000))
    local delta_ns=$((delta_total_ns/repeats))
    local delta_us=$((delta_ns/1000))
    echo "     test duration:         ${delta_total_s} s"
    echo "     tpm2_quote latency:    ${delta_us} usecs"
}

# ##########################################
# quote test
# ##########################################

function test_createprimary() {
    local repeats=${1:-1000}
    local tmpdir=${2:-/tmp}
    echo "===> createprimary (ECC) test"
    echo "     repeats:               ${repeats}"

    local t0=$(date +%s%N)
    for x in `seq 1 ${repeats}`
    do
	tpm2_createprimary -C e -c ${tmpdir}/primary${x}.ctx -G ecc > /dev/null 2>&1
    done
    local t1=$(date +%s%N)
    rm -f ${tmpdir}/primary*.ctx
    local delta_total_ns=$((t1-t0))
    local delta_total_s=$((delta_total_ns/1000000000))
    local delta_ns=$((delta_total_ns/repeats))
    local delta_us=$((delta_ns/1000))
    echo "     test duration:         ${delta_total_s} s"
    echo "     createprimary latency: ${delta_us} usecs"
}


identify
test_pcrread 3000
test_pcrextend 3000
test_quote 1000
test_createprimary 100
