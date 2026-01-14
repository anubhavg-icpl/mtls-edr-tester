# mtls-edr-tester

RFC-compliant mutual TLS (mTLS) testing tool for EDR systems on macOS.

## RFC Standards Compliance

This tool is designed with strict adherence to IETF RFC standards for security and interoperability.

| RFC | Standard | Implementation Details |
|-----|----------|----------------------|
| [RFC 8446](https://tools.ietf.org/html/rfc8446) | **TLS 1.3** | Default minimum TLS version; enforces modern cryptographic algorithms; supports 0-RTT when available |
| [RFC 5280](https://tools.ietf.org/html/rfc5280) | **X.509 PKI** | Certificate path validation; proper chain verification; CRL/OCSP support via Security.framework |
| [RFC 6125](https://tools.ietf.org/html/rfc6125) | **Server Identity** | Hostname verification per TLS best practices |
| [RFC 7468](https://tools.ietf.org/html/rfc7468) | **PEM Encoding** | Support for PEM-encoded certificates and keys |
| [RFC 7292](https://tools.ietf.org/html/rfc7292) | **PKCS #12** | Import/export of certificate bundles with private keys |
| [RFC 6749](https://tools.ietf.org/html/rfc6749) | **OAuth 2.0** | Token-based enrollment workflows |
| [RFC 8705](https://tools.ietf.org/html/rfc8705) | **mTLS for OAuth** | Client certificate-bound access tokens support |

## Overview

A Swift command-line tool for testing mTLS connections between EDR agents and management servers. Designed to verify certificate-based authentication flows for endpoint detection and response (EDR) systems.

### Key Features

- **TLS 1.3 by Default** - Enforces RFC 8446 compliant connections
- **X.509 Certificate Handling** - RFC 5280 compliant path validation
- **macOS Keychain Integration** - Native access to MDM-provisioned certificates
- **MDM Verification** - Detect and use certificates from Jamf, Intune, Mosyle, Kandji, etc.
- **PKCS#12 Support** - Import `.p12` files for development testing (RFC 7292)
- **Enrollment Simulation** - Test device enrollment workflows

## Installation

### Build from Source

```bash
git clone https://github.com/anubhavg-icpl/mtls-edr-tester.git
cd mtls-edr-tester
swift build -c release
sudo cp .build/release/registration /usr/local/bin/edr-tester
```

### Requirements

- macOS 13.0+ (Ventura or later)
- Swift 5.9+
- Xcode Command Line Tools

## Commands

### `list-identities` - List Available Certificates

List all certificate identities with private keys in the macOS Keychain.

```bash
edr-tester list-identities
```

Output:
```
Available Certificate Identities in Keychain:
──────────────────────────────────────────────

[1] Developer ID Application: Your Company (TEAMID)
    Subject: Developer ID Application: Your Company (TEAMID)
    Serial: 2A:C7:6C:D7:67:47:8D:15

──────────────────────────────────────────────
Total: 1 identit(y|ies)
```

### `info` - Certificate Details

Display detailed information about a specific certificate identity (RFC 5280 compliant).

```bash
edr-tester info --identity "Your Certificate Name"
```

Output:
```
Certificate Identity Information
────────────────────────────────

Label: Your Certificate Name
Subject: Your Certificate Name
Serial Number: 2A:C7:6C:D7:67:47:8D:15
Key Size: 2048 bits
Key Type: RSA

OK: Identity is valid and ready for mTLS
```

### `test` - Test mTLS Connection

Test TLS/mTLS connections with RFC 8446 (TLS 1.3) enforcement.

```bash
# Basic TLS 1.3 test (no client cert)
edr-tester test --url https://your-edr-server:8443

# mTLS with client certificate from Keychain
edr-tester test --url https://your-edr-server:8443 \
    --identity "Your Certificate Name" \
    --verbose

# mTLS with .p12 file (development/testing)
edr-tester test --url https://your-edr-server:8443 \
    --p12-path ./client.p12 \
    --p12-password "secret"

# Allow self-signed certificates (dev only)
edr-tester test --url https://localhost:8443 \
    --allow-self-signed \
    --tls-version tls12

# POST request with JSON body
edr-tester test --url https://api.example.com/data \
    --method POST \
    --body '{"key": "value"}' \
    --verbose
```

### `enroll` - Device Enrollment

Simulate device enrollment with an EDR server.

```bash
edr-tester enroll --url https://edr-server/enroll \
    --token "enrollment-token-123" \
    --device-id "DEVICE-001" \
    --verbose
```

### `mdm-verify` - MDM Enrollment Verification

Verify MDM enrollment status and discover MDM-provisioned certificates.

```bash
sudo edr-tester mdm-verify
```

Output:
```
MDM Enrollment Verification
════════════════════════════

1. MDM Enrollment Status
────────────────────────
✓ Device is enrolled in MDM
   Organization: Your Company
   Server URL: https://mdm.yourcompany.com

2. Installed Configuration Profiles
───────────────────────────────────
   [1] Company Security Profile
       ID: com.yourcompany.security
       Org: Your Company

3. MDM-Provisioned Certificates
───────────────────────────────
✓ [1] Your Company Device Certificate
       Serial: 1A:2B:3C:4D:5E:6F
       Has Private Key: Yes
       Keychain Label: com.yourcompany.device

════════════════════════════
Use 'edr-tester mdm-connect --url <server>' to test connection
```

### `mdm-connect` - Auto mTLS with MDM Certificate

Automatically discover and use MDM-provisioned certificates for mTLS connections.

```bash
sudo edr-tester mdm-connect --url https://your-edr-server:8443 --verbose
```

This command:
1. Checks MDM enrollment status
2. Discovers MDM-provisioned certificates
3. Automatically selects the appropriate certificate
4. Establishes an mTLS connection

## Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version |
| `-h, --help` | Show help |
| `-v, --verbose` | Enable verbose output |
| `--no-color` | Disable colored output |

### `test` Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | EDR server URL (required) | - |
| `-i, --identity` | Keychain identity label | - |
| `--p12-path` | Path to PKCS#12 file | - |
| `--p12-password` | PKCS#12 password | - |
| `--method` | HTTP method (GET, POST) | GET |
| `--body` | Request body for POST | - |
| `--tls-version` | Minimum TLS version (tls12, tls13) | tls13 |
| `--timeout` | Connection timeout (seconds) | 30 |
| `--allow-self-signed` | Accept self-signed certs | false |

### `enroll` Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Enrollment server URL (required) | - |
| `--token` | Enrollment token | - |
| `--device-id` | Device identifier | auto-generated |

### `mdm-connect` Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | EDR server URL (required) | - |
| `--method` | HTTP method (GET, POST) | GET |
| `--body` | Request body for POST | - |
| `--tls-version` | Minimum TLS version | tls13 |
| `--timeout` | Connection timeout (seconds) | 30 |
| `--allow-self-signed` | Accept self-signed certs | false |

## Architecture

```
Sources/
├── main.swift              # CLI entry point with ArgumentParser
├── KeychainManager.swift   # X.509 identity handling (RFC 5280, RFC 7292)
├── TLSSessionManager.swift # mTLS session management (RFC 8446)
├── MDMVerifier.swift       # MDM enrollment & certificate discovery
└── Logger.swift            # Colored CLI output utility
```

## RFC Implementation Details

### RFC 8446 - TLS 1.3

The tool enforces TLS 1.3 by default via `tlsMinimumSupportedProtocolVersion = .TLSv13`:

```swift
// From TLSSessionManager.swift
if configuration.minimumTLSVersion == .tls13 {
    urlSessionConfig.tlsMinimumSupportedProtocolVersion = .TLSv13
} else {
    urlSessionConfig.tlsMinimumSupportedProtocolVersion = .TLSv12
}
```

TLS 1.3 provides:
- Reduced handshake latency (1-RTT, 0-RTT)
- Forward secrecy by default
- Simplified cipher suite negotiation
- Encrypted handshake messages

### RFC 5280 - X.509 PKI

Certificate validation uses macOS Security.framework with full RFC 5280 compliance:

```swift
// Certificate path validation
var trust: SecTrust?
let policy = SecPolicyCreateSSL(true, hostname as CFString)
SecTrustCreateWithCertificates(certificates, policy, &trust)
SecTrustEvaluateWithError(trust, &error)
```

Validation includes:
- Certificate chain building
- Signature verification
- Validity period checking
- Key usage validation
- Basic constraints enforcement

### RFC 7292 - PKCS#12

Support for importing `.p12` bundles containing certificates and private keys:

```swift
// PKCS#12 import
let options = [kSecImportExportPassphrase: password]
SecPKCS12Import(p12Data, options as CFDictionary, &items)
```

### RFC 8705 - mTLS for OAuth

The tool supports client certificate-bound tokens for OAuth 2.0 mTLS flows, enabling:
- Certificate-bound access tokens
- Mutual authentication in OAuth flows
- Enhanced security for API access

## Security Considerations

1. **Never commit certificates** - `.gitignore` excludes `.p12`, `.pem`, `.key` files
2. **Use MDM-provisioned certificates** - Production deployments should use certificates installed via MDM configuration profiles
3. **TLS 1.3 default** - Legacy TLS 1.2 requires explicit `--tls-version tls12`
4. **Self-signed warning** - `--allow-self-signed` displays a warning; use only for development
5. **Keychain access** - The tool requests Keychain access for private key operations; approve only for trusted uses

## Supported MDM Solutions

The MDM verifier recognizes certificates from:

- Jamf Pro
- Microsoft Intune
- Mosyle
- Kandji
- VMware Workspace ONE (AirWatch)
- MobileIron
- Cisco Meraki Systems Manager
- SOTI MobiControl
- Hexnode
- Generic SCEP-provisioned certificates

## Use Cases

1. **EDR Agent Testing** - Verify agent can authenticate to management server
2. **Certificate Validation** - Check if MDM-provisioned certs are correctly installed
3. **Enrollment Testing** - Simulate device enrollment workflows
4. **TLS Debugging** - Troubleshoot TLS handshake issues with `--verbose`
5. **Compliance Verification** - Ensure mTLS is properly configured before deployment

## Troubleshooting

### No identities found
```bash
# Check Keychain Access for installed certificates
security find-identity -v -p ssl

# Import a .p12 manually
security import client.p12 -k ~/Library/Keychains/login.keychain-db
```

### MDM certificates not detected
```bash
# Run as root for full profile access
sudo edr-tester mdm-verify

# Check profiles manually
profiles list
profiles status -type enrollment
```

### TLS handshake failures
```bash
# Enable verbose logging
edr-tester test --url https://server:8443 --verbose

# Try TLS 1.2 if server doesn't support 1.3
edr-tester test --url https://server:8443 --tls-version tls12
```

## License

MIT License - See [LICENSE](LICENSE) file

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Author

Anubhav Gain
