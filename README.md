# mtls-edr-tester

RFC 8446 (TLS 1.3) compliant mutual TLS testing tool for EDR systems on macOS.

## Overview

A Swift command-line tool for testing mTLS connections between EDR agents and management servers. Designed to verify certificate-based authentication flows per RFC standards.

## Features

- **RFC 8446 Compliant** - TLS 1.3 enforcement by default
- **RFC 5280 X.509** - Proper certificate validation and path checking
- **macOS Keychain Integration** - Load client certificates installed via MDM/configuration profiles
- **PKCS#12 Support** - Import `.p12` files for development testing
- **Enrollment Simulation** - Test device enrollment workflows

## Installation

### Build from Source

```bash
git clone https://github.com/yourusername/mtls-edr-tester.git
cd mtls-edr-tester
swift build -c release
sudo cp .build/release/registration /usr/local/bin/edr-tester
```

### Requirements

- macOS 13.0+
- Swift 5.9+
- Xcode Command Line Tools

## Usage

### List Available Certificates

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
```

### Test mTLS Connection

```bash
# Basic TLS 1.3 test
edr-tester test --url https://your-edr-server:8443

# With client certificate from Keychain
edr-tester test --url https://your-edr-server:8443 \
    --identity "Your Certificate Name" \
    --verbose

# With .p12 file (development)
edr-tester test --url https://your-edr-server:8443 \
    --p12-path ./client.p12 \
    --p12-password "secret"

# Allow self-signed certificates (dev only)
edr-tester test --url https://localhost:8443 \
    --allow-self-signed \
    --tls-version tls12
```

### Certificate Info

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

### Device Enrollment

```bash
edr-tester enroll --url https://edr-server/enroll \
    --token "enrollment-token-123" \
    --device-id "DEVICE-001" \
    --verbose
```

## Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version |
| `-h, --help` | Show help |

### `test` Command

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
| `-v, --verbose` | Enable verbose logging | false |
| `--no-color` | Disable colored output | false |

### `enroll` Command

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Enrollment server URL (required) | - |
| `--token` | Enrollment token | - |
| `--device-id` | Device identifier | auto-generated |

## Architecture

```
Sources/
├── main.swift              # CLI entry point with ArgumentParser
├── KeychainManager.swift   # X.509 identity loading (RFC 5280)
├── TLSSessionManager.swift # mTLS session handling (RFC 8446)
└── Logger.swift            # Colored logging utility
```

## RFC Compliance

| RFC | Description | Implementation |
|-----|-------------|----------------|
| [RFC 8446](https://tools.ietf.org/html/rfc8446) | TLS 1.3 | `tlsMinimumSupportedProtocolVersion = .TLSv13` |
| [RFC 5280](https://tools.ietf.org/html/rfc5280) | X.509 PKI | SecTrust certificate path validation |
| [RFC 6749](https://tools.ietf.org/html/rfc6749) | OAuth 2.0 | Token-based enrollment support |

## Security Considerations

- **Never commit certificates** - `.gitignore` excludes `.p12`, `.pem`, `.key` files
- **Use Keychain** - Production deployments should use MDM-provisioned certificates
- **TLS 1.3 Default** - Legacy TLS 1.2 requires explicit `--tls-version tls12`
- **Self-Signed Warning** - `--allow-self-signed` shows warning in logs

## Use Cases

1. **EDR Agent Testing** - Verify agent can authenticate to management server
2. **Certificate Validation** - Check if MDM-provisioned certs are correctly installed
3. **Enrollment Testing** - Simulate device enrollment workflows
4. **TLS Debugging** - Troubleshoot TLS handshake issues with `--verbose`

## License

MIT License - See [LICENSE](LICENSE) file

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Author

Anubhav Gain
