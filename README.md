# mTLS EDR Tester

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://developer.apple.com/macos/)
[![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)](https://swift.org/)

A command-line tool for testing mutual TLS (mTLS) connections between EDR agents and management servers on macOS. Built with strict adherence to IETF RFC standards.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [RFC Standards Compliance](#rfc-standards-compliance)
- [Supported MDM Solutions](#supported-mdm-solutions)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Features

- **TLS 1.3 Enforcement** - RFC 8446 compliant with fallback to TLS 1.2
- **X.509 Certificate Validation** - RFC 5280 compliant path verification
- **macOS Keychain Integration** - Native access to system and user certificates
- **MDM Certificate Discovery** - Auto-detect certificates from enterprise MDM solutions
- **PKCS#12 Import** - Support for `.p12` bundles (RFC 7292)
- **Enrollment Simulation** - Test device onboarding workflows

## Requirements

| Component | Version |
|-----------|---------|
| macOS | 13.0+ (Ventura) |
| Swift | 5.9+ |
| Xcode CLI Tools | Latest |

## Installation

### From Source

```bash
git clone https://github.com/anubhavg-icpl/mtls-edr-tester.git
cd mtls-edr-tester
swift build -c release
```

### Install Globally

```bash
sudo cp .build/release/registration /usr/local/bin/edr-tester
```

### Verify Installation

```bash
edr-tester --version
```

## Quick Start

```bash
# List available certificates
edr-tester list-identities

# Test TLS 1.3 connection
edr-tester test --url https://api.github.com

# Test mTLS with client certificate
edr-tester test --url https://your-server:8443 --identity "Your Cert Name"

# Auto-detect MDM certificate and connect
sudo edr-tester mdm-connect --url https://your-edr-server:8443
```

## Commands

### `list-identities`

List all certificate identities (certificate + private key pairs) in the macOS Keychain.

```bash
edr-tester list-identities
```

**Output:**
```
Available Certificate Identities in Keychain:
──────────────────────────────────────────────

[1] Developer ID Application: Company Name (TEAM123)
    Subject: Developer ID Application: Company Name (TEAM123)
    Serial: 2A:C7:6C:D7:67:47:8D:15

──────────────────────────────────────────────
Total: 1 identity
```

---

### `info`

Display detailed certificate information including key type and size.

```bash
edr-tester info --identity "Certificate Name"
```

| Option | Description | Required |
|--------|-------------|----------|
| `-i, --identity` | Certificate label in Keychain | Yes |

---

### `test`

Test TLS/mTLS connections to a server.

```bash
# Basic TLS test
edr-tester test --url https://example.com

# mTLS with Keychain identity
edr-tester test --url https://server:8443 --identity "Client Cert" --verbose

# mTLS with PKCS#12 file
edr-tester test --url https://server:8443 --p12-path ./client.p12 --p12-password "pass"

# POST request with body
edr-tester test --url https://api.example.com --method POST --body '{"key":"value"}'

# Allow self-signed (development only)
edr-tester test --url https://localhost:8443 --allow-self-signed
```

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Server URL | Required |
| `-i, --identity` | Keychain certificate label | - |
| `--p12-path` | Path to PKCS#12 file | - |
| `--p12-password` | PKCS#12 password | - |
| `--method` | HTTP method (GET, POST) | GET |
| `--body` | Request body | - |
| `--tls-version` | Minimum TLS (tls12, tls13) | tls13 |
| `--timeout` | Timeout in seconds | 30 |
| `--allow-self-signed` | Accept self-signed certs | false |
| `-v, --verbose` | Verbose output | false |

---

### `enroll`

Simulate device enrollment with an EDR server.

```bash
edr-tester enroll --url https://edr-server/api/enroll \
    --token "enrollment-token" \
    --device-id "DEVICE-001"
```

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Enrollment endpoint | Required |
| `--token` | Enrollment token | - |
| `--device-id` | Device identifier | Auto-generated |

---

### `mdm-verify`

Check MDM enrollment status and discover provisioned certificates.

```bash
sudo edr-tester mdm-verify
```

**Output:**
```
MDM Enrollment Verification
════════════════════════════

1. MDM Enrollment Status
────────────────────────
✓ Device is enrolled in MDM
   Organization: Your Company
   Server URL: https://mdm.company.com

2. Installed Configuration Profiles
───────────────────────────────────
   [1] Security Policy
       ID: com.company.security
       Org: Your Company

3. MDM-Provisioned Certificates
───────────────────────────────
✓ [1] Device Identity Certificate
       Serial: 1A:2B:3C:4D
       Has Private Key: Yes

════════════════════════════
```

---

### `mdm-connect`

Automatically discover and use MDM certificate for mTLS connection.

```bash
sudo edr-tester mdm-connect --url https://edr-server:8443 --verbose
```

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Server URL | Required |
| `--method` | HTTP method | GET |
| `--body` | Request body | - |
| `--tls-version` | Minimum TLS version | tls13 |
| `--timeout` | Timeout in seconds | 30 |
| `--allow-self-signed` | Accept self-signed | false |

---

## RFC Standards Compliance

This tool implements the following IETF standards:

| RFC | Standard | Description |
|-----|----------|-------------|
| [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) | TLS 1.3 | Transport Layer Security protocol with modern cipher suites, forward secrecy, and 1-RTT handshakes |
| [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) | X.509 PKI | Certificate format, path validation, revocation checking, and trust anchor management |
| [RFC 6125](https://datatracker.ietf.org/doc/html/rfc6125) | Service Identity | Server hostname verification and certificate subject matching |
| [RFC 7292](https://datatracker.ietf.org/doc/html/rfc7292) | PKCS #12 | Certificate and private key bundle format for import/export |
| [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) | PEM Encoding | Text encoding for cryptographic objects |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 | Authorization framework for token-based enrollment |
| [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) | OAuth 2.0 mTLS | Certificate-bound access tokens for mutual authentication |

### Implementation Details

**TLS 1.3 (RFC 8446)**
```swift
urlSessionConfig.tlsMinimumSupportedProtocolVersion = .TLSv13
```
- Enforced as default minimum version
- Supports 0-RTT early data when available
- Forward secrecy via ephemeral key exchange

**X.509 Validation (RFC 5280)**
```swift
let policy = SecPolicyCreateSSL(true, hostname as CFString)
SecTrustCreateWithCertificates(certificates, policy, &trust)
SecTrustEvaluateWithError(trust, &error)
```
- Full certificate chain validation
- Signature and validity period verification
- Key usage and basic constraints enforcement

**PKCS#12 Import (RFC 7292)**
```swift
let options = [kSecImportExportPassphrase: password]
SecPKCS12Import(p12Data, options as CFDictionary, &items)
```

## Supported MDM Solutions

The tool recognizes certificates provisioned by:

| MDM Solution | Detection Method |
|--------------|------------------|
| Jamf Pro | Profile identifier, certificate label |
| Microsoft Intune | Certificate issuer, label patterns |
| Mosyle | Profile and certificate metadata |
| Kandji | Certificate attributes |
| VMware Workspace ONE | AirWatch identifiers |
| Cisco Meraki | Systems Manager profiles |
| MobileIron | Certificate labels |
| SOTI MobiControl | Profile identifiers |
| Hexnode | Certificate metadata |
| SCEP Certificates | Generic SCEP-provisioned certs |

## Security Considerations

| Consideration | Recommendation |
|---------------|----------------|
| Certificate Storage | Use MDM-provisioned certificates; avoid manual `.p12` files in production |
| TLS Version | Keep TLS 1.3 default; use TLS 1.2 only for legacy compatibility |
| Self-Signed Certs | Use `--allow-self-signed` only in development environments |
| Keychain Access | Approve Keychain prompts only for trusted tool invocations |
| Credential Files | Never commit `.p12`, `.pem`, `.key` files to version control |

## Troubleshooting

### No Certificates Found

```bash
# List SSL-capable identities
security find-identity -v -p ssl

# Import a .p12 file
security import client.p12 -k ~/Library/Keychains/login.keychain-db
```

### MDM Not Detected

```bash
# Requires root for full profile access
sudo edr-tester mdm-verify

# Check enrollment manually
profiles status -type enrollment
profiles list
```

### TLS Handshake Failures

```bash
# Enable debug output
edr-tester test --url https://server:8443 --verbose

# Fallback to TLS 1.2
edr-tester test --url https://server:8443 --tls-version tls12
```

### Certificate Trust Issues

```bash
# Check certificate chain
openssl s_client -connect server:8443 -showcerts

# Verify certificate dates
openssl x509 -in cert.pem -noout -dates
```

## Architecture

```
Sources/
├── main.swift               # CLI entry point (ArgumentParser)
├── KeychainManager.swift    # Keychain operations (RFC 5280, RFC 7292)
├── TLSSessionManager.swift  # TLS session handling (RFC 8446)
├── MDMVerifier.swift        # MDM enrollment verification
└── Logger.swift             # Colored terminal output
```

### Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| `KeychainManager` | Load identities, import PKCS#12, extract certificates/keys |
| `TLSSessionManager` | Configure URLSession, handle mTLS authentication, manage connections |
| `MDMVerifier` | Query profiles, detect MDM enrollment, discover provisioned certs |
| `Logger` | Formatted console output with color support |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -m 'feat: add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Anubhav Gain**

---

<p align="center">
  <sub>Built for secure endpoint management</sub>
</p>
