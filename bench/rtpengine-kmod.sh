#!/usr/bin/env bash
# Build rtpengine's kernel forwarding module (xt_RTPENGINE) for the running
# kernel, matching the rtpengine daemon used by the benchmarks. Runs as the
# invoking user; loading the module (bench/fastpath.sh) needs root.
#
#   RTPENGINE_TAG=mr13.5.1.16                 source tag
#   RTPENGINE_VERSION=13.5.1.16+0~mr13.5.1.16 must equal the daemon's version
set -euo pipefail
cd "$(dirname "$0")"

TAG=${RTPENGINE_TAG:-mr13.5.1.16}
VERSION=${RTPENGINE_VERSION:-13.5.1.16+0~mr13.5.1.16}
mkdir -p kmod
cd kmod
if [ ! -d "rtpengine-$TAG/kernel-module" ]; then
    curl -sSfL -o src.tar.gz "https://github.com/sipwise/rtpengine/archive/refs/tags/$TAG.tar.gz"
    tar -xzf src.tar.gz "rtpengine-$TAG/kernel-module"
fi
cd "rtpengine-$TAG/kernel-module"
make clean >/dev/null 2>&1 || true
RTPENGINE_VERSION="$VERSION" make
cp xt_RTPENGINE.ko ../../xt_RTPENGINE.ko
echo "built bench/kmod/xt_RTPENGINE.ko for $(uname -r) (version $VERSION)"
