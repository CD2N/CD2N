#!/usr/bin/env bash

set -e

if [ "$SGX" -eq 1 ] && [ "$SKIP_AESMD" -eq 0 ]; then
  echo "Starting AESMD"

  if test -f "/opt/conf/aesmd.conf"; then
    echo "Found custom aesmd.conf, override the default."
    cp /opt/conf/aesmd.conf /etc/
  fi

  if test -f "/opt/conf/sgx_default_qcnl.conf"; then
    echo "Found custom sgx_default_qcnl.conf, override the default."
    cp /opt/conf/sgx_default_qcnl.conf /etc/
  fi

  /bin/mkdir -p /var/run/aesmd/
  /bin/chown -R aesmd:aesmd /var/run/aesmd/
  /bin/chmod 0755 /var/run/aesmd/
  /bin/chown -R aesmd:aesmd /var/opt/aesmd/
  /bin/chmod 0750 /var/opt/aesmd/

  LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service --no-daemon &

  if [ ! "${SLEEP_BEFORE_START:=0}" -eq 0 ]
  then
    echo "Waiting for device. Sleep ${SLEEP_BEFORE_START}s"

    sleep "${SLEEP_BEFORE_START}"
  fi
fi


WORK_DIR=$(dirname $(readlink -f "$0"))
DATA_DIR=${DATA_DIR:-"${WORK_DIR}/data"}

echo "Work dir '${WORK_DIR}'"
echo "Data dir '${DATA_DIR}'"

GRAMINE_SGX_BIN=${GRAMINE_SGX_BIN:-"${WORK_DIR}/gramine-sgx"}
GRAMINE_DIRECT_BIN=${GRAMINE_DIRECT_BIN:-"gramine-direct"}

if [ -L ${DATA_DIR} ] && [ ! -e ${DATA_DIR} ]; then
  mkdir -p $(readlink -f $DATA_DIR)
fi
mkdir -p "${DATA_DIR}/seal_data"


echo "Starting CDN TEE with extra opts '${EXTRA_OPTS}'"
if [ "$SGX" -eq 0 ]; then
  echo "DCAP test will running in software mode"
  cd $WORK_DIR && $GRAMINE_DIRECT_BIN justicar $EXTRA_OPTS
else
  echo "DCAP test will running in hardware mode"
  cd $WORK_DIR && $GRAMINE_SGX_BIN justicar $EXTRA_OPTS
fi