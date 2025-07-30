# ===================================================================
# Stage 1: Builder
#
# This stage uses the official Rust image to build our application.
# It contains the Rust compiler, Cargo, and all necessary build tools.
# ===================================================================
FROM rust:1.87-slim-bullseye as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install build dependencies required for crates like `openssl-sys`.
# `build-essential` provides a C compiler, and `libssl-dev` provides OpenSSL headers.
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the Cargo configuration files first. This allows Docker to cache
# the dependency layer, so dependencies are only re-downloaded if
# Cargo.toml or Cargo.lock changes.
COPY Cargo.toml Cargo.lock ./

# Create a dummy `main.rs` to build only the dependencies.
# This is another caching optimization.
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release

# Now that dependencies are cached, copy the actual source code.
COPY src ./src

# Build the application for release, which will use the cached dependencies.
# The `rm` command cleans up the dummy file we created earlier.
RUN rm -f target/release/deps/phala-zkverify* && \
    cargo build --release

# ===================================================================
# Stage 2: Runner
#
# This stage creates the final, minimal image. We use a slim Debian
# image because it's small but still gives you a shell for debugging if needed.
# For an even smaller, more secure image, you could use `gcr.io/distroless/cc-debian11`.
# ===================================================================
FROM debian:bullseye-slim as runner

WORKDIR /usr/src/app

# Copy the compiled binary from the 'builder' stage.
# The binary is located at `/usr/src/app/target/release/rust_async_proof_server`.
# Note: Replace `rust_async_proof_server` if your package name in Cargo.toml is different.
COPY --from=builder /usr/src/app/target/release/phala-zkverify .

# Expose the port the server will listen on.
EXPOSE 3000

# Set the command to run when the container starts.
CMD ["./phala-zkverify"]
