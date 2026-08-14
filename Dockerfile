# Reproducible build image for zig-stark.
#
# Pins Zig 0.16.0 (the stable release the project targets) from the official
# build, verified by SHA-256. Run:
#
#   docker build -t zig-stark .
#   docker run --rm zig-stark          # runs `zig build test`
#   docker run --rm zig-stark zig build
#   docker run --rm zig-stark zig build fmt
#
# Native target is linux-x86_64 (the codebase uses Linux clock_gettime).

FROM debian:bookworm-slim

ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/zig.tar.xz \
        "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
    && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/zig.tar.xz -C /opt \
    && mv "/opt/zig-x86_64-linux-${ZIG_VERSION}" /opt/zig \
    && ln -s /opt/zig/zig /usr/local/bin/zig \
    && rm /tmp/zig.tar.xz

WORKDIR /workspace
COPY . .

CMD ["zig", "build", "test"]
