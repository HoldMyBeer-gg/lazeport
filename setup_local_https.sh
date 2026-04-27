#!/bin/bash
# Set up locally-trusted HTTPS for development using mkcert

set -e

echo "🔐 Setting up local HTTPS with mkcert..."

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "❌ mkcert is not installed."
    echo ""
    echo "Install mkcert:"
    echo "  macOS:   brew install mkcert nss"
    echo "  Linux:   See https://github.com/FiloSottile/mkcert#installation"
    echo ""
    echo "After installing, run this script again."
    exit 1
fi

# Create certs directory
mkdir -p certs

# Install local CA
echo "📜 Installing local Certificate Authority..."
mkcert -install

# Generate certificate for localhost
echo "🔑 Generating certificate for localhost..."
cd certs
mkcert localhost 127.0.0.1 ::1
cd ..

# Rename to expected names
mv certs/localhost+2.pem certs/localhost.pem
mv certs/localhost+2-key.pem certs/localhost-key.pem

echo "✅ Local HTTPS certificates generated!"
echo ""
echo "Certificates are in ./certs/"
echo "  - localhost.pem (certificate)"
echo "  - localhost-key.pem (private key)"
echo ""
echo "To use:"
echo "  1. Update Caddyfile to use these certificates"
echo "  2. Run: ./run_with_caddy.sh"
echo "  3. Visit: https://localhost:8000 (no warnings!)"
