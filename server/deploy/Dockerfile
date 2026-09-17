# drop-zone-server, built from source and run as a storage-free daemon.
#
#   docker build -t drop-zone-server -f server/deploy/Dockerfile .
#   docker run --rm -p 47654:47654 drop-zone-server
#
# The image contains the server binary and nothing else that writes. There is
# no volume to mount.

FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        g++ \
        libssl-dev \
        make \
        ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DDZ_BUILD_CLIENT=OFF \
        -DDZ_BUILD_SERVER=ON \
        -DDZ_BUILD_TESTS=OFF \
        -DDZ_NATIVE_ARCH=OFF \
    && cmake --build build \
    && cmake --install build --prefix /out

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin dropzone

COPY --from=build /out/bin/drop-zone-server /usr/local/bin/drop-zone-server

USER dropzone
EXPOSE 47654/tcp
EXPOSE 47654/udp

ENTRYPOINT ["/usr/local/bin/drop-zone-server"]
CMD ["--bind", "::", "--port", "47654"]
