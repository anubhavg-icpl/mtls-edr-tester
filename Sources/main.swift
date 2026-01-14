//
//  main.swift
//  registration - EDR mTLS Client Tool
//
//  RFC 8446 (TLS 1.3) compliant mutual TLS testing CLI
//  For testing EDR agent ↔ server communication
//
//  Created by Anubhav Gain on 14/01/26.
//

import Foundation
import ArgumentParser

// MARK: - Main Command

@main
struct EDRTester: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "edr-tester",
        abstract: "RFC 8446 compliant mTLS testing tool for EDR systems",
        discussion: """
            A command-line tool for testing mutual TLS (mTLS) connections
            between EDR agents and management servers.
            
            Supports:
            - TLS 1.3 enforcement per RFC 8446
            - X.509 certificate handling per RFC 5280
            - Client certificate authentication via macOS Keychain
            - PKCS#12 (.p12) file import for development
            
            Examples:
              edr-tester test --url https://edr.example.com:8443 --identity "EDR Client"
              edr-tester list-identities
              edr-tester info --identity "EDR Client"
            """,
        version: "1.1.0",
        subcommands: [
            TestCommand.self,
            ListIdentitiesCommand.self,
            IdentityInfoCommand.self,
            EnrollCommand.self,
            MDMVerifyCommand.self,
            MDMConnectCommand.self
        ],
        defaultSubcommand: TestCommand.self
    )
}

// MARK: - Common Options

struct CommonOptions: ParsableArguments {
    @Flag(name: .shortAndLong, help: "Enable verbose output")
    var verbose: Bool = false
    
    @Flag(name: .long, help: "Disable colored output")
    var noColor: Bool = false
}

struct TLSOptions: ParsableArguments {
    @Option(name: .long, help: "Minimum TLS version (tls12 or tls13)")
    var tlsVersion: String = "tls13"
    
    @Option(name: .long, help: "Connection timeout in seconds")
    var timeout: Int = 30
    
    @Flag(name: .long, help: "Allow self-signed certificates (development only)")
    var allowSelfSigned: Bool = false
    
    var minimumTLSVersion: TLSVersion {
        tlsVersion.lowercased() == "tls12" ? .tls12 : .tls13
    }
}

// MARK: - Test Command

struct TestCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "test",
        abstract: "Test mTLS connection to an EDR server"
    )
    
    @Option(name: .shortAndLong, help: "URL of the EDR server (e.g., https://edr.local:8443)")
    var url: String
    
    @Option(name: .shortAndLong, help: "Keychain identity label (Common Name)")
    var identity: String?
    
    @Option(name: .long, help: "Path to PKCS#12 (.p12) file")
    var p12Path: String?
    
    @Option(name: .long, help: "Password for PKCS#12 file")
    var p12Password: String?
    
    @Option(name: .long, help: "HTTP method (GET, POST)")
    var method: String = "GET"
    
    @Option(name: .long, help: "Request body for POST")
    var body: String?
    
    @OptionGroup var common: CommonOptions
    @OptionGroup var tls: TLSOptions
    
    func run() async throws {
        let logger = Logger.shared
        if common.verbose {
            logger.setLevel(.debug)
        }
        if common.noColor {
            logger.setColors(false)
        }
        
        logger.info("EDR mTLS Tester v1.0.0")
        logger.info("RFC 8446 (TLS 1.3) Compliant")
        
        // Load client identity
        var clientIdentity: SecIdentity?
        
        if let identityLabel = identity {
            logger.info("Loading identity from Keychain: \(identityLabel)")
            do {
                clientIdentity = try KeychainManager.shared.findIdentity(byLabel: identityLabel)
                let cert = try KeychainManager.shared.extractCertificate(from: clientIdentity!)
                let info = KeychainManager.shared.getCertificateInfo(cert)
                logger.success("Loaded identity: \(info["Subject"] ?? identityLabel)")
            } catch {
                logger.failure("Failed to load identity: \(error.localizedDescription)")
                throw ExitCode.failure
            }
        } else if let p12 = p12Path {
            let password = p12Password ?? ""
            logger.info("Loading identity from PKCS#12: \(p12)")
            do {
                clientIdentity = try KeychainManager.shared.importIdentity(fromP12: p12, password: password)
                logger.success("Loaded identity from .p12 file")
            } catch {
                logger.failure("Failed to load .p12: \(error.localizedDescription)")
                throw ExitCode.failure
            }
        }
        
        // Configure mTLS session
        let config = MTLSConfiguration(
            minimumTLSVersion: tls.minimumTLSVersion,
            clientIdentity: clientIdentity,
            allowSelfSigned: tls.allowSelfSigned,
            timeoutInterval: TimeInterval(tls.timeout),
            verboseLogging: common.verbose
        )
        
        let sessionManager = TLSSessionManager(configuration: config, logger: logger)
        
        logger.info("Testing connection to: \(url)")
        logger.info("TLS Version: \(tls.minimumTLSVersion.rawValue)+")
        
        do {
            let response: MTLSResponse
            
            if method.uppercased() == "POST" {
                let bodyData = body?.data(using: .utf8)
                response = try await sessionManager.post(url: url, body: bodyData)
            } else {
                response = try await sessionManager.get(url: url)
            }
            
            logger.plain("")
            logger.success("Connection successful!")
            logger.plain("────────────────────────────────────────")
            logger.plain("Status Code: \(response.statusCode)")
            logger.plain("TLS Version: \(response.tlsVersion ?? "Unknown")")
            
            if common.verbose {
                logger.plain("")
                logger.plain("Headers:")
                for (key, value) in response.headers {
                    logger.plain("  \(key): \(value)")
                }
            }
            
            if let bodyStr = response.bodyString, !bodyStr.isEmpty {
                logger.plain("")
                logger.plain("Response Body:")
                logger.plain(bodyStr.prefix(1000).description)
                if bodyStr.count > 1000 {
                    logger.plain("... (truncated)")
                }
            }
            
            // Print server certificate info
            if let serverCert = response.serverCertificate {
                let serverInfo = KeychainManager.shared.getCertificateInfo(serverCert)
                logger.plain("")
                logger.plain("Server Certificate:")
                logger.plain("  Subject: \(serverInfo["Subject"] ?? "Unknown")")
                if let serial = serverInfo["Serial"] {
                    logger.plain("  Serial: \(serial)")
                }
            }
            
            logger.plain("────────────────────────────────────────")
            
        } catch {
            logger.failure("Connection failed: \(error.localizedDescription)")
            throw ExitCode.failure
        }
        
        sessionManager.invalidate()
    }
}

// MARK: - List Identities Command

struct ListIdentitiesCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list-identities",
        abstract: "List available certificate identities in Keychain"
    )
    
    @OptionGroup var common: CommonOptions
    
    func run() async throws {
        let logger = Logger.shared
        if common.noColor {
            logger.setColors(false)
        }
        
        logger.plain("Available Certificate Identities in Keychain:")
        logger.plain("──────────────────────────────────────────────")
        
        do {
            let identities = try KeychainManager.shared.listIdentities()
            
            if identities.isEmpty {
                logger.warning("No certificate identities found.")
                logger.plain("")
                logger.plain("To add identities:")
                logger.plain("  1. Install a configuration profile via MDM")
                logger.plain("  2. Import a .p12 file using Keychain Access")
                logger.plain("  3. Use: security import cert.p12 -k ~/Library/Keychains/login.keychain-db")
                return
            }
            
            for (index, item) in identities.enumerated() {
                let cert = try KeychainManager.shared.extractCertificate(from: item.identity)
                let info = KeychainManager.shared.getCertificateInfo(cert)
                
                logger.plain("")
                logger.plain("[\(index + 1)] \(item.label)")
                logger.plain("    Subject: \(info["Subject"] ?? "Unknown")")
                if let serial = info["Serial"] {
                    logger.plain("    Serial: \(serial)")
                }
            }
            
            logger.plain("")
            logger.plain("──────────────────────────────────────────────")
            logger.plain("Total: \(identities.count) identit(y|ies)")
            
        } catch {
            logger.failure("Failed to list identities: \(error.localizedDescription)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Identity Info Command

struct IdentityInfoCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "info",
        abstract: "Show detailed information about a certificate identity"
    )
    
    @Option(name: .shortAndLong, help: "Keychain identity label")
    var identity: String
    
    @OptionGroup var common: CommonOptions
    
    func run() async throws {
        let logger = Logger.shared
        if common.noColor {
            logger.setColors(false)
        }
        
        do {
            let secIdentity = try KeychainManager.shared.findIdentity(byLabel: identity)
            let certificate = try KeychainManager.shared.extractCertificate(from: secIdentity)
            let privateKey = try KeychainManager.shared.extractPrivateKey(from: secIdentity)
            
            let info = KeychainManager.shared.getCertificateInfo(certificate)
            
            logger.plain("Certificate Identity Information")
            logger.plain("────────────────────────────────")
            logger.plain("")
            logger.plain("Label: \(identity)")
            logger.plain("Subject: \(info["Subject"] ?? "Unknown")")
            logger.plain("Serial Number: \(info["Serial"] ?? "Unknown")")
            
            // Private key info
            if let keyAttrs = SecKeyCopyAttributes(privateKey) as? [String: Any] {
                if let keySize = keyAttrs[kSecAttrKeySizeInBits as String] as? Int {
                    logger.plain("Key Size: \(keySize) bits")
                }
                if let keyType = keyAttrs[kSecAttrKeyType as String] as? String {
                    let typeStr: String
                    let rsaType = kSecAttrKeyTypeRSA as String
                    let ecType = kSecAttrKeyTypeECSECPrimeRandom as String
                    if keyType == rsaType {
                        typeStr = "RSA"
                    } else if keyType == ecType {
                        typeStr = "ECDSA"
                    } else {
                        typeStr = keyType
                    }
                    logger.plain("Key Type: \(typeStr)")
                }
            }
            
            logger.plain("")
            logger.success("Identity is valid and ready for mTLS")
            
        } catch {
            logger.failure("Failed to get identity info: \(error.localizedDescription)")
            throw ExitCode.failure
        }
    }
}

// MARK: - Enroll Command

struct EnrollCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "enroll",
        abstract: "Enroll this device with an EDR server"
    )
    
    @Option(name: .shortAndLong, help: "EDR enrollment server URL")
    var url: String
    
    @Option(name: .long, help: "Enrollment token/password")
    var token: String?
    
    @Option(name: .long, help: "Device identifier")
    var deviceId: String?
    
    @OptionGroup var common: CommonOptions
    @OptionGroup var tls: TLSOptions
    
    func run() async throws {
        let logger = Logger.shared
        if common.verbose {
            logger.setLevel(.debug)
        }
        if common.noColor {
            logger.setColors(false)
        }
        
        logger.info("EDR Agent Enrollment")
        logger.info("────────────────────")
        
        let hostname = Host.current().localizedName ?? "Unknown"
        let deviceIdentifier = deviceId ?? UUID().uuidString
        
        logger.plain("Hostname: \(hostname)")
        logger.plain("Device ID: \(deviceIdentifier)")
        logger.plain("Enrollment URL: \(url)")
        
        // Build enrollment request
        var enrollmentData: [String: Any] = [
            "hostname": hostname,
            "device_id": deviceIdentifier,
            "platform": "macOS",
            "os_version": ProcessInfo.processInfo.operatingSystemVersionString,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        
        if let enrollToken = token {
            enrollmentData["enrollment_token"] = enrollToken
        }
        
        guard let jsonData = try? JSONSerialization.data(withJSONObject: enrollmentData) else {
            logger.failure("Failed to serialize enrollment data")
            throw ExitCode.failure
        }
        
        // Configure session (no client cert yet for enrollment)
        let config = MTLSConfiguration(
            minimumTLSVersion: tls.minimumTLSVersion,
            clientIdentity: nil,
            allowSelfSigned: tls.allowSelfSigned,
            timeoutInterval: TimeInterval(tls.timeout),
            verboseLogging: common.verbose
        )
        
        let sessionManager = TLSSessionManager(configuration: config, logger: logger)
        
        logger.info("Sending enrollment request...")
        
        do {
            let response = try await sessionManager.post(url: url, body: jsonData)
            
            if response.statusCode >= 200 && response.statusCode < 300 {
                logger.success("Enrollment successful!")
                
                if let bodyStr = response.bodyString {
                    logger.plain("")
                    logger.plain("Server Response:")
                    logger.plain(bodyStr)
                }
                
                logger.plain("")
                logger.info("Next steps:")
                logger.plain("  1. A configuration profile may be pushed to this device via MDM")
                logger.plain("  2. The profile will contain your client certificate")
                logger.plain("  3. Use 'edr-tester list-identities' to verify installation")
            } else {
                logger.failure("Enrollment failed with status: \(response.statusCode)")
                if let body = response.bodyString {
                    logger.plain("Response: \(body)")
                }
                throw ExitCode.failure
            }
            
        } catch let error as MTLSError {
            logger.failure("Enrollment failed: \(error.localizedDescription)")
            throw ExitCode.failure
        }
        
        sessionManager.invalidate()
    }
}

// MARK: - MDM Verify Command

struct MDMVerifyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mdm-verify",
        abstract: "Verify MDM enrollment and available certificates"
    )
    
    @OptionGroup var common: CommonOptions
    
    func run() async throws {
        let logger = Logger.shared
        if common.verbose {
            logger.setLevel(.debug)
        }
        if common.noColor {
            logger.setColors(false)
        }
        
        logger.plain("MDM Enrollment Verification")
        logger.plain("════════════════════════════")
        logger.plain("")
        
        let mdmVerifier = MDMVerifier.shared
        
        // Check MDM enrollment
        logger.plain("1. MDM Enrollment Status")
        logger.plain("────────────────────────")
        
        if mdmVerifier.isDeviceEnrolled() {
            logger.success("Device is enrolled in MDM")
            
            if let mdmInfo = mdmVerifier.getMDMServerInfo() {
                if let org = mdmInfo.organization, !org.isEmpty {
                    logger.plain("   Organization: \(org)")
                }
                if let url = mdmInfo.serverURL, !url.isEmpty {
                    logger.plain("   Server URL: \(url)")
                }
            }
        } else {
            logger.warning("Device is NOT enrolled in MDM")
            logger.plain("   Tip: Contact your IT admin to enroll this device")
        }
        
        logger.plain("")
        
        // Check installed profiles
        logger.plain("2. Installed Configuration Profiles")
        logger.plain("───────────────────────────────────")
        
        do {
            let profiles = try mdmVerifier.listInstalledProfiles()
            
            if profiles.isEmpty {
                logger.warning("No configuration profiles installed")
            } else {
                for (index, profile) in profiles.enumerated() {
                    logger.plain("   [\(index + 1)] \(profile.displayName)")
                    logger.plain("       ID: \(profile.identifier)")
                    if let org = profile.organization {
                        logger.plain("       Org: \(org)")
                    }
                }
            }
        } catch {
            logger.warning("Could not query profiles: \(error.localizedDescription)")
        }
        
        logger.plain("")
        
        // Check MDM certificates
        logger.plain("3. MDM-Provisioned Certificates")
        logger.plain("───────────────────────────────")
        
        do {
            let mdmCerts = try mdmVerifier.findMDMCertificates()
            
            if mdmCerts.isEmpty {
                logger.warning("No MDM certificates found in Keychain")
                logger.plain("   Checking all available identities...")
                
                let allIdentities = try KeychainManager.shared.listIdentities()
                if allIdentities.isEmpty {
                    logger.failure("No certificate identities available")
                } else {
                    logger.plain("")
                    logger.plain("   Available identities (non-MDM):")
                    for (index, item) in allIdentities.enumerated() {
                        logger.plain("   [\(index + 1)] \(item.label)")
                    }
                }
            } else {
                for (index, cert) in mdmCerts.enumerated() {
                    logger.success("[\(index + 1)] \(cert.commonName)")
                    logger.plain("       Serial: \(cert.serialNumber)")
                    if let issuer = cert.issuer {
                        logger.plain("       Issuer: \(issuer)")
                    }
                    logger.plain("       Has Private Key: \(cert.hasPrivateKey ? "Yes" : "No")")
                    if let label = cert.keychainLabel {
                        logger.plain("       Keychain Label: \(label)")
                    }
                }
            }
        } catch {
            logger.failure("Error checking certificates: \(error.localizedDescription)")
        }
        
        logger.plain("")
        logger.plain("════════════════════════════")
        logger.plain("Use 'edr-tester mdm-connect --url <server>' to test connection with MDM certificate")
    }
}

// MARK: - MDM Connect Command

struct MDMConnectCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mdm-connect",
        abstract: "Automatically use MDM certificate for mTLS connection"
    )
    
    @Option(name: .shortAndLong, help: "URL of the EDR server")
    var url: String
    
    @Option(name: .long, help: "HTTP method (GET, POST)")
    var method: String = "GET"
    
    @Option(name: .long, help: "Request body for POST")
    var body: String?
    
    @OptionGroup var common: CommonOptions
    @OptionGroup var tls: TLSOptions
    
    func run() async throws {
        let logger = Logger.shared
        if common.verbose {
            logger.setLevel(.debug)
        }
        if common.noColor {
            logger.setColors(false)
        }
        
        logger.info("EDR mTLS Connection (Auto MDM)")
        logger.info("RFC 8446 (TLS 1.3) Compliant")
        logger.plain("")
        
        // Verify MDM and get identity
        let mdmVerifier = MDMVerifier.shared
        var clientIdentity: SecIdentity?
        
        do {
            clientIdentity = try mdmVerifier.verifyAndGetIdentity()
            
            // Show certificate info
            let cert = try KeychainManager.shared.extractCertificate(from: clientIdentity!)
            let info = KeychainManager.shared.getCertificateInfo(cert)
            logger.success("Using certificate: \(info["Subject"] ?? "Unknown")")
            
        } catch {
            logger.failure("MDM verification failed: \(error.localizedDescription)")
            logger.plain("")
            logger.info("Troubleshooting:")
            logger.plain("  1. Ensure device is enrolled in MDM")
            logger.plain("  2. Check if MDM has pushed a client certificate profile")
            logger.plain("  3. Run 'edr-tester mdm-verify' for detailed status")
            logger.plain("  4. Use 'edr-tester test --identity <name>' for manual selection")
            throw ExitCode.failure
        }
        
        // Configure mTLS session
        let config = MTLSConfiguration(
            minimumTLSVersion: tls.minimumTLSVersion,
            clientIdentity: clientIdentity,
            allowSelfSigned: tls.allowSelfSigned,
            timeoutInterval: TimeInterval(tls.timeout),
            verboseLogging: common.verbose
        )
        
        let sessionManager = TLSSessionManager(configuration: config, logger: logger)
        
        logger.info("Connecting to: \(url)")
        logger.info("TLS Version: \(tls.minimumTLSVersion.rawValue)+")
        
        do {
            let response: MTLSResponse
            
            if method.uppercased() == "POST" {
                let bodyData = body?.data(using: .utf8)
                response = try await sessionManager.post(url: url, body: bodyData)
            } else {
                response = try await sessionManager.get(url: url)
            }
            
            logger.plain("")
            logger.success("mTLS Connection successful!")
            logger.plain("────────────────────────────────────────")
            logger.plain("Status Code: \(response.statusCode)")
            logger.plain("TLS Version: \(response.tlsVersion ?? "Unknown")")
            
            if common.verbose {
                logger.plain("")
                logger.plain("Headers:")
                for (key, value) in response.headers {
                    logger.plain("  \(key): \(value)")
                }
            }
            
            if let bodyStr = response.bodyString, !bodyStr.isEmpty {
                logger.plain("")
                logger.plain("Response Body:")
                logger.plain(bodyStr.prefix(1000).description)
                if bodyStr.count > 1000 {
                    logger.plain("... (truncated)")
                }
            }
            
            if let serverCert = response.serverCertificate {
                let serverInfo = KeychainManager.shared.getCertificateInfo(serverCert)
                logger.plain("")
                logger.plain("Server Certificate:")
                logger.plain("  Subject: \(serverInfo["Subject"] ?? "Unknown")")
            }
            
            logger.plain("────────────────────────────────────────")
            
        } catch {
            logger.failure("Connection failed: \(error.localizedDescription)")
            throw ExitCode.failure
        }
        
        sessionManager.invalidate()
    }
}
