####################################################################################################
## Builder
####################################################################################################
FROM messense/rust-musl-cross:x86_64-musl AS builder

RUN rustup target add x86_64-unknown-linux-musl
RUN sudo apt-get update && apt-get install -y ca-certificates
RUN sudo apt install -y musl-tools musl-dev
RUN sudo apt-get install -y build-essential checkinstall zlib1g-dev -y
RUN sudo apt-get install pkg-config -y
RUN sudo apt-get install libssl-dev -y

# Create appuser
ENV USER=jwt_authorizer_user
ENV GROUP=boto_services
ENV UID=10001

RUN sudo groupadd ${GROUP}
RUN sudo useradd -g ${GROUP} -ms /bin/bash ${USER}
RUN echo "User created: ${USER}"

WORKDIR /build

COPY ./ .

# ENV RUSTFLAGS='-C linker=x86_64-linux-gnu-gcc'
RUN cargo build --target x86_64-unknown-linux-musl --release

####################################################################################################
## Final image
####################################################################################################
FROM alpine:latest

USER ${USER}

# Import from builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /services

# Copy our build
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/jwt_authorizer ./

# Use an unprivileged user.
USER ${USER}:${GROUP}

CMD ["/services/jwt_authorizer"]