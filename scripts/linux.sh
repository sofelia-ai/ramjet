#!/bin/sh
# Linux dev rig: run any command in the project's Linux container.
#   scripts/linux.sh cargo test -p ramjet-ws
#   scripts/linux.sh cargo test --workspace        # once the uring backend lands
#
# - seccomp=unconfined: Docker's default profile blocks io_uring_setup(2).
#   Dev rig only; production containers should allowlist the three
#   io_uring_* syscalls instead.
# - named volume for the target dir: keeps Linux artifacts out of the
#   macOS target/ and avoids slow bind-mount I/O.
# - Functional work and relative comparisons only — absolute benchmark
#   numbers from inside a VM are not receipts.
set -eu
cd "$(dirname "$0")/.."
# Allocate a TTY only when stdin is one, so this works both interactively
# and from scripts/agents (docker -t on a non-tty errors out).
TTY=
[ -t 0 ] && TTY=-t
exec docker run --rm -i $TTY \
  --security-opt seccomp=unconfined \
  -v "$PWD":/w -v ramjet-target:/t \
  -e CARGO_TARGET_DIR=/t -w /w \
  rust:1-bookworm "$@"
