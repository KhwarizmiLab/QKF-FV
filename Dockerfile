# ─── Base ────────────────────────────────────────────────────────────────────
# Ubuntu 22.04 ships glibc 2.35 which is compatible with the bundled
# tamarin-prover and maude Linux ELF binaries already in the repo.
FROM --platform=linux/amd64 ubuntu:22.04

# Avoid interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# ─── System dependencies ─────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        m4 \
        python3 \
        python3-pydot \
        make \
        time \
        libtinfo5 \
        graphviz \
    && rm -rf /var/lib/apt/lists/*

# ─── Workspace ───────────────────────────────────────────────────────────────
WORKDIR /workspace

# Copy project files into the image
COPY . .

# Make all tool scripts executable
RUN chmod -R a+x ./tools/

# Put bundled Maude on PATH so tamarin-prover can find it at runtime
ENV PATH="/workspace/tools/maude:${PATH}"

# ─── Default command ─────────────────────────────────────────────────────────
# No default CMD – callers pass a make target or shell command at runtime,
# e.g.:  docker compose run --rm tamarin make gen_proofs
CMD ["bash"]
