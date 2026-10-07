# Builds the linux-x64-musl binaries of @cipherstash/auth and
# @cipherstash/protect-ffi. Alpine is a musl system, so its compiler links
# musl; the Ubuntu runner's compiler links glibc, and the result does not load
# on musl.
#
# Pinned because the output is published with provenance. Dependabot moves the
# digest; nothing moves the package versions, and Alpine drops a version from
# its index when it publishes the next one, so a pin can stop resolving at any
# time. musl-build-image.yml builds this file weekly so that is a failed check,
# not a failed release. Re-pin from the FROM image with
# `apk update >/dev/null && apk search --exact <packages>`.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

# build-base is a metapackage whose compiler and linker dependencies carry no
# version, so gcc, g++, binutils, musl-dev and make are pinned beside it.
RUN apk add --no-cache \
    binutils=2.45.1-r1 \
    build-base=0.5-r4 \
    cmake=4.2.3-r0 \
    curl=8.22.0-r0 \
    g++=15.2.0-r5 \
    gcc=15.2.0-r5 \
    git=2.54.0-r0 \
    linux-headers=7.0.0-r1 \
    make=4.4.1-r4 \
    musl-dev=1.2.6-r2 \
    perl=5.42.2-r1 \
    rustup=1.29.0-r0
