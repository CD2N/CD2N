SGX_SIGNER_KEY ?= ./enclave-key.pem
SGX ?= 1
RA_TYPE ?= dcap

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

CFLAGS = -Wall -Wextra

GRAMINE_LOG_LEVEL = error

USE_MUSL ?= 0

BIN_NAME = justicar

DATA_DIRS = data/protected_files \
            data/storage_files

GRAMINE_DIR ?= $(shell ./gramine-dir libs)
GRAMINE_LIBOS ?= $(shell ./gramine-dir libos)
GRAMINE_RUNTIME_DIR ?= $(shell ./gramine-dir runtime)

RUNTIME_DIR = cruntime
LIBOS_BASENAME ?= $(shell basename ${GRAMINE_LIBOS})
LIBOS ?= ${RUNTIME_DIR}/${LIBOS_BASENAME}

ifeq ($(USE_MUSL),1)
BIN_FILE = ../target/x86_64-unknown-linux-musl/release/${BIN_NAME}
CARGO_ARGS = --target x86_64-unknown-linux-musl
HOST_LIBC_DIR = /lib/x86_64-linux-musl
else
BIN_FILE = ../../target/release/${BIN_NAME}
CARGO_ARGS =
HOST_LIBC_DIR = /lib/x86_64-linux-gnu
endif

ifeq ($(V),1)
CARGO_ARGS += -vv
endif

PREFIX ?= ../bin

.PHONY: all
all: ${BIN_NAME} ${BIN_NAME}.manifest
ifeq ($(SGX),1)
all: ${BIN_NAME}.manifest.sgx ${BIN_NAME}.sig
endif

.PHONY: ${BIN_FILE}
${BIN_FILE}:
	cargo build --release ${CARGO_ARGS}

${BIN_NAME}: ${BIN_FILE}
	cp ${BIN_FILE} ${BIN_NAME}

${BIN_NAME}.manifest: ${BIN_NAME}.manifest.template ${LIBOS}
	gramine-manifest \
		-Dinstall_dir=$(INSTALL_DIR) \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Dra_type=${RA_TYPE} \
		-Dra_client_spid=${RA_CLIENT_SPID} \
		-Dra_client_linkable=${RA_CLIENT_LINKABLE} \
		-Dlibdir=${RUNTIME_DIR}/lib/ \
		-Darch_libdir=${ARCH_LIBDIR}/ \
		-Dlibos=${LIBOS} \
		$< $@

${BIN_NAME}.manifest.sgx: ${BIN_NAME}.manifest ${BIN_NAME} ${LIBOS}
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

${LIBOS}:
	mkdir -p ${RUNTIME_DIR}
	rsync -r --no-links ${GRAMINE_RUNTIME_DIR}/ ${RUNTIME_DIR}/lib
ifeq ($(USE_MUSL),0)
	cp -rfL ${HOST_LIBC_DIR}/libgcc_s.so.1 ${RUNTIME_DIR}/lib/
endif
	cp -rfL ${GRAMINE_DIR}/sgx ${RUNTIME_DIR}/
	cp -rfL ${GRAMINE_LIBOS} ${RUNTIME_DIR}/

${BIN_NAME}.sig: ${BIN_NAME}.manifest.sgx

${BIN_NAME}.token: ${BIN_NAME}.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

.PHONY: token
token: ${BIN_NAME}.token

.PHONY: dirs
dirs: ${DATA_DIRS}

${DATA_DIRS}:
	mkdir -p $@

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest ${BIN_NAME}.o ${BIN_NAME} OUTPUT
	$(RM) -rf ../target
	$(RM) -rf data
	$(RM) -rf ${RUNTIME_DIR}

.PHONY: distclean
distclean: clean

.PHONY: dist
dist: all
	gramine-sgx-sigstruct-view ${BIN_NAME}.sig
	mkdir -p ${PREFIX}/data/protected_files
	mkdir -p ${PREFIX}/data/storage_files
	cp ${BIN_NAME} ${PREFIX}/
ifeq ($(SGX),1)
	cp ${BIN_NAME}.manifest.sgx ${PREFIX}/
	cp ${BIN_NAME}.sig ${PREFIX}/
	cp -rfL ${RUNTIME_DIR} ${PREFIX}/
	cp gramine-sgx ${PREFIX}/
endif
	cp ${BIN_NAME}.manifest ${PREFIX}/

.PHONY: run
run: all token
	make dirs
ifeq ($(SGX),1)
	./gramine-sgx ${BIN_NAME}
else
	gramine-direct ${BIN_NAME}
endif