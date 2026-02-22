#!/bin/bash
# Generate self-signed CA and TSA certificates for offline timestamping with osslsigncode
# Usage: ./generate_tsa_certs.sh [output_directory]
# If output_directory is not specified, certificates will be created in the current directory.

set -e

OUTDIR="${1:-.}"
mkdir -p "$OUTDIR"

echo "Generating self-signed CA and TSA certificates in $OUTDIR"

# Generate self-signed Root CA
echo "1. Generating self-signed Root CA private key and certificate..."
openssl genrsa -out "$OUTDIR/ca.key" 2048
openssl req -new -x509 -days 3650 -key "$OUTDIR/ca.key" -out "$OUTDIR/ca.crt" \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Timestamping Authority/CN=My TSA Root CA"

# Generate TSA private key
echo "2. Generating TSA private key..."
openssl genrsa -out "$OUTDIR/tsa.key" 2048

# Generate TSA certificate signing request
echo "3. Generating TSA certificate signing request..."
openssl req -new -key "$OUTDIR/tsa.key" -out "$OUTDIR/tsa.csr" \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Timestamping Authority/CN=My TSA"

# Create extensions configuration file for TSA certificate
echo "4. Creating TSA certificate extensions configuration..."
cat > "$OUTDIR/tsa.ext" <<EOF
basicConstraints = critical,CA:FALSE
extendedKeyUsage = critical,timeStamping
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

# Sign TSA certificate with Root CA
echo "5. Signing TSA certificate with Root CA..."
openssl x509 -req -days 3650 -in "$OUTDIR/tsa.csr" -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" \
  -CAcreateserial -out "$OUTDIR/tsa.crt" -extfile "$OUTDIR/tsa.ext"

# Create certificate chain file (TSA certificate + CA certificate)
echo "6. Creating certificate chain file..."
cat "$OUTDIR/tsa.crt" "$OUTDIR/ca.crt" > "$OUTDIR/tsa-chain.pem"

# Clean up temporary files
echo "7. Cleaning up temporary files..."
rm -f "$OUTDIR/tsa.csr" "$OUTDIR/tsa.ext" "$OUTDIR/ca.srl"

echo "Done!"
echo ""
echo "Generated files:"
echo "  - ca.key:       Root CA private key (keep secure!)"
echo "  - ca.crt:       Root CA certificate"
echo "  - tsa.key:      TSA private key (for signing timestamps)"
echo "  - tsa.crt:      TSA certificate (for timestamp verification)"
echo "  - tsa-chain.pem: Certificate chain (TSA + CA)"
echo ""
echo "Usage with osslsigncode:"
echo "  osslsigncode sign -certs your_cert.pem -key your_key.pem \\"
echo "    -TSA-certs tsa.crt -TSA-key tsa.key \\"
echo "    -in file.exe -out file_signed.exe"
echo ""
echo "Verification (requires CA certificate):"
echo "  osslsigncode verify -TSA-CAfile ca.crt file_signed.exe"