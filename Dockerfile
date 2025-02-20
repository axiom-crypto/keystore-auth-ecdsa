FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE=$BUILD_PROFILE

# Extra Cargo flags
ARG RUSTFLAGS=""
ENV RUSTFLAGS="$RUSTFLAGS"

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES=$FEATURES

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

# Builds a cargo-chef plan
FROM chef AS planner

COPY ./crates /app/crates

WORKDIR /app/crates

RUN cargo chef prepare --recipe-path recipe.json 

FROM chef AS builder
COPY --from=planner /app/crates/recipe.json /app/crates/recipe.json

COPY ./crates /app/crates

WORKDIR /app/crates

RUN cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Cargo chef cook creates temp Cargo.toml
COPY ./crates /app/crates

RUN cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked -p m-of-n-ecdsa-server 

RUN cp /app/crates/target/$BUILD_PROFILE/server /app/server

# Use Ubuntu as the release image
FROM ubuntu:24.04 AS runtime

COPY --from=builder /app/server /app/

EXPOSE 8000

ENTRYPOINT ["/app/server"]
