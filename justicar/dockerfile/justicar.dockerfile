FROM --platform=linux/amd64 gramine-rust:latest AS builder

WORKDIR /root
ENV HOME=/root
ARG APP_NAME="justicar"
RUN mkdir -p $HOME/${APP_NAME}
ARG SGX_SIGNER_KEY="enclave-key.pem"
ARG APP_DEPLOYMENT_DIR="/opt/justicar"

COPY crates $HOME/${APP_NAME}/crates
COPY justicar $HOME/${APP_NAME}/justicar
COPY scripts $HOME/${APP_NAME}/scripts
COPY Cargo.toml Cargo.lock rust-toolchain.toml $HOME/${APP_NAME}/

RUN cd $HOME/${APP_NAME}/justicar/gramine-build && \
    PATH="$PATH:$HOME/.cargo/bin" make dist PREFIX="${APP_DEPLOYMENT_DIR}" && \
    PATH="$PATH:$HOME/.cargo/bin" make clean

# ====

FROM --platform=linux/amd64 gramine:latest AS runtime

RUN echo "Gramine SGX Version:" && gramine-sgx --version
ARG APP_DEPLOYMENT_DIR="/opt/justicar"

COPY --from=builder ${APP_DEPLOYMENT_DIR} ${APP_DEPLOYMENT_DIR}
ADD dockerfile/start_justicar.sh ${APP_DEPLOYMENT_DIR}/start_justicar.sh
ADD dockerfile/conf /opt/conf

WORKDIR ${APP_DEPLOYMENT_DIR}

ENV SGX=1
ENV SKIP_AESMD=0
ENV SLEEP_BEFORE_START=6
ENV RUST_LOG="info"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/bash", "start_justicar.sh"]