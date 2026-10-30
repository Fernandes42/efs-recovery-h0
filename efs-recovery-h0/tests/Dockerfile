# Verifier image for efs/efs-recovery-h0: built with tests/ as the
# Docker build context, so COPY cannot reach environment/. Everything
# the grader needs is installed/baked here -- it does not inherit the
# agent image.
FROM ubuntu:24.04

# Everything tests/test.sh needs at grade time is installed here, so
# grading makes no network call. Toolchain patch versions float with
# the Ubuntu 24.04 archives (NOT pinned: offline pinning is impossible
# and a wrong pin breaks the build); instead the image records the
# resolved versions at build time (/etc/efs-toolchain.txt) and proves
# compatibility empirically: the harness must compile+link below, and
# every trial re-verifies the frozen source manifest at grade time.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates curl g++ cmake ninja-build libssl-dev python3 util-linux \
  && rm -rf /var/lib/apt/lists/* \
  && { echo "g++: $(g++ -dumpversion)"; \
       echo "cmake: $(cmake --version | head -n 1)"; \
       echo "openssl: $(openssl version)"; \
       echo "python3: $(python3 --version 2>&1)"; } > /etc/efs-toolchain.txt \
  && cat /etc/efs-toolchain.txt

RUN curl -LsSf https://astral.sh/uv/0.9.7/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
RUN uv venv /opt/verifier-venv \
  && VIRTUAL_ENV=/opt/verifier-venv uv pip install \
       pytest==8.4.1 \
       pytest-json-ctrf==0.3.5

# Artifact upload is a docker cp, which creates NO directories: the
# immediate parent of every artifact path must already exist here.
# Artifacts land at the same absolute paths the agent used (/app/...).
RUN mkdir -p /app /app/candidate/src

# Ground truth and grading code ship inside the image, never uploaded
# at runtime and never visible to the agent.
COPY . /tests
RUN chmod +x /tests/test.sh

# Fixed loader/runtime closure, copied into each read-only candidate root.
# No mount, namespace, Docker capability, or security-policy change is needed.
RUN mkdir -p /opt/efs-runtime \
  && cp -L --parents /lib64/ld-linux-x86-64.so.2 \
       /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
       /lib/x86_64-linux-gnu/libc.so.6 \
       /lib/x86_64-linux-gnu/libm.so.6 \
       /lib/x86_64-linux-gnu/libgcc_s.so.1 \
       /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /opt/efs-runtime \
  && g++ -std=c++20 -O2 /tests/vendor/sealed/sandbox_helper.cpp \
       -o /opt/efs-sandbox-helper \
  && chmod 0555 /opt/efs-sandbox-helper

# Build the sealed-split grade harness (links verifier-owned objects
# ONLY -- never efs_candidate -- so submitted code cannot enter the
# grading process's address space). A failed link fails the image
# build: the grade path can never run on an inconsistent tree.
# No EFS_SEALED_CXXFLAGS here: the image build uses the fixed recipe.
RUN cmake -S /tests/harness -B /tests/harness-build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
  && cmake --build /tests/harness-build \
  && test -x /tests/harness-build/efs_harness \
  && nm -C /tests/harness-build/efs_harness | grep -c "efs::candidate" | grep -q "^0$" \
  && echo "harness built, no submitted-code symbols linked"

# /tests, not /app: it keeps the agent-written tree that arrives via
# `artifacts` behind the grader's own code on sys.path.
WORKDIR /tests
