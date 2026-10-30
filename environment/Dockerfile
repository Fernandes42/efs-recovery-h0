# Agent image for efs/efs-recovery-h0: toolchain + model-visible bundle.
# The bundle is the vetted calibration candidate-view (docs, fixed ABI
# headers, faulty starter, public tests, profiles, redacted world.h,
# prebuilt dev-keys lib). No reference/, no trusted sources, no grader/.
FROM ubuntu:24.04

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates curl g++ cmake ninja-build libssl-dev python3 \
  && rm -rf /var/lib/apt/lists/* \
  && { echo "g++: $(g++ -dumpversion)"; \
       echo "cmake: $(cmake --version | head -n 1)"; \
       echo "openssl: $(openssl version)"; \
       echo "python3: $(python3 --version 2>&1)"; } > /etc/efs-toolchain.txt \
  && cat /etc/efs-toolchain.txt

# Grading may run here rather than in a separate container, so
# tests/test.sh's interpreter has to exist on this side too. Same
# versions as tests/Dockerfile.
RUN curl -LsSf https://astral.sh/uv/0.9.7/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
RUN uv venv /opt/verifier-venv \
  && VIRTUAL_ENV=/opt/verifier-venv uv pip install \
       pytest==8.4.1 \
       pytest-json-ctrf==0.3.5

# Model-visible bundle only (build context: environment/).
COPY bundle/ /app/
WORKDIR /app

# Warm build validates the bundle at image-build time: the faulty
# starter must configure, compile, link the prebuilt dev-keys static
# lib, and show both BUG lines with `smoke passed`. This link+run is
# the C++ ABI validation of the dev lib IN this image (toolchain patch
# versions float with the archives, so source hashes cannot pin
# binary compatibility -- the empirical gate does). Any deviation fails
# the image build (fail closed).
# lib/libefs_trusted_dev.a ships non-PIC (absolute R_X86_64_32S
# relocations); Ubuntu 24.04 g++ defaults to PIE executables, which
# cannot link it. -no-pie selects a classic non-PIE executable, which
# links the dev lib cleanly. Bundle sources stay untouched; the flag
# lives in the image-build configuration (and hence in build/CMakeCache)
# so the agent's `cmake --build build` rebuilds keep working.
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXE_LINKER_FLAGS=-no-pie \
  && cmake --build build \
  && ./build/public_tests | tee /tmp/bundle-proof.txt \
  && grep -q "BUG REPRODUCED: committed root dangles" /tmp/bundle-proof.txt \
  && grep -q "BUG REPRODUCED: async commit used caller-mutated bytes" /tmp/bundle-proof.txt \
  && grep -q "smoke passed" /tmp/bundle-proof.txt
