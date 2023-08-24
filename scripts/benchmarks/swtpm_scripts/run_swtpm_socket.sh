#!/bin/bash

# configuration: temporary directory this process is running in

export TMPDIR=${TPMDIR:-/tmp/qemu-vtpm-${USER}}


# Create keys
openssl req -x509 -newkey rsa:4096 -keyout ./swtpm/signkey.pem -out ./swtpm/issuercert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

# ##########################################
# provision and start swtpm
# ##########################################

export TPMSTATE=${TMPDIR}/tpmstate
export ETCDIR=${TMPDIR}/etc

if test -f ${TPMSTATE}/swtpm-pid
then
    echo "==> run_swtpm: killing previous instance pid=$(cat ${TPMSTATE}/swtpm-pid)"
    kill -9 $(cat ${TPMSTATE}/swtpm-pid)
fi

# copy all configuration files
rm -rf ${TPMSTATE} > /dev/null 2>&1
rm -rf ${ETCDIR} > /dev/null 2>&1
mkdir -p ${TPMSTATE} ${ETCDIR}
sed "s^%%etcdir%%^${ETCDIR}^g" swtpm/swtpm_setup.conf.in > ${ETCDIR}/swtpm_setup.conf
sed "s^%%etcdir%%^${ETCDIR}^g" swtpm/swtpm-localca.conf.in > ${ETCDIR}/swtpm-localca.conf
cp swtpm/swtpm-localca.options ${ETCDIR}
cp swtpm/issuercert.pem ${ETCDIR}
cp swtpm/signkey.pem ${ETCDIR}
echo ${RANDOM} > ${ETCDIR}/certserial

# ##########################################
# run TPM provisioning
# ##########################################

echo "==> run_swtpm: provisioning"
sudo chmod 777 /var/lib/swtpm-localca
if ! swtpm_setup \
    --tpmstate ${TPMSTATE} \
    --config ${ETCDIR}/swtpm_setup.conf \
    --tpm2 \
    --pcr-banks sha1,sha256,sha384 \
    --create-platform-cert \
    --create-ek-cert \
    --logfile ${TPMSTATE}/setup.log
then
    echo "==>     provisioning failed. Check ${TPMSTATE}/setup.log"
    exit 1
fi

# ##########################################
# run swtpm
# ##########################################

run_swtpm() {
echo "==> run_swtpm: starting"
swtpm socket \
      -d \
      --tpmstate dir=${TPMSTATE},mode=0600 \
      --tpm2 \
      --ctrl type=unixio,path=${TPMSTATE}/swtpm-sock \
      --pid file=${TPMSTATE}/swtpm-pid \
      --log level=20,file=${TPMSTATE}/swtpm.log
}

# ##########################################
# 
# ##########################################

echo "==> run_swtpm socket ready: ${TPMSTATE}/swtpm-sock"
