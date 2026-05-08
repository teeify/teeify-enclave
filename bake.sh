#!/bin/bash
set -e

# Increase soft stack size limit for Nix
ulimit -s 65536 || true

echo "❄️ [Nix] Building bit-identical Enclave Image..."
# We only build the image now, not the kernel
IMAGE_PATH=$(nix-build enclave.nix -A image --no-out-link)

echo "🐳 [Docker] Loading image from Nix store..."
sudo docker load < "$IMAGE_PATH"

echo "🔨 [Nitro] Baking EIF..."
# Removed the --kernel flag. Nix fixed the Docker drift. Faketime fixes the EIF drift.
sudo /usr/local/bin/faketime "2024-05-04 00:00:00" nitro-cli build-enclave \
  --docker-uri teeify-enclave-image:latest \
  --output-file ../teeify-agent.eif

echo "✅ SUCCESS: The PCR0 below is now globally deterministic."