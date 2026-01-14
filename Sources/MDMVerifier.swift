//
//  MDMVerifier.swift
//  mtls-edr-tester
//
//  Verifies MDM-installed configuration profiles and certificates
//  Supports Jamf, Intune, Mosyle, Kandji, and other MDM solutions
//
//  Created by Anubhav Gain on 14/01/26.
//

import Foundation
import Security

/// MDM profile information
public struct MDMProfile: Sendable {
    public let identifier: String
    public let displayName: String
    public let organization: String?
    public let installDate: Date?
    public let isManaged: Bool
    public let certificates: [CertificateInfo]
}

/// Certificate information extracted from MDM profiles
public struct CertificateInfo: Sendable {
    public let commonName: String
    public let serialNumber: String
    public let issuer: String?
    public let expirationDate: Date?
    public let hasPrivateKey: Bool
    public let keychainLabel: String?
}

/// Errors specific to MDM verification
public enum MDMError: LocalizedError {
    case noProfilesInstalled
    case noCertificatesFound
    case profileCommandFailed(String)
    case identityNotUsable(String)
    case mdmNotEnrolled
    
    public var errorDescription: String? {
        switch self {
        case .noProfilesInstalled:
            return "No MDM configuration profiles installed on this device."
        case .noCertificatesFound:
            return "No client certificates found in MDM profiles."
        case .profileCommandFailed(let reason):
            return "Failed to query profiles: \(reason)"
        case .identityNotUsable(let reason):
            return "Certificate identity not usable for mTLS: \(reason)"
        case .mdmNotEnrolled:
            return "Device is not enrolled in MDM."
        }
    }
}

/// Verifies MDM-installed profiles and certificates
public final class MDMVerifier: @unchecked Sendable {
    
    public static let shared = MDMVerifier()
    private let logger = Logger.shared
    
    private init() {}
    
    // MARK: - MDM Enrollment Check
    
    /// Checks if device is enrolled in MDM
    public func isDeviceEnrolled() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/profiles")
        task.arguments = ["status", "-type", "enrollment"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            // Check for MDM enrollment indicators
            return output.contains("MDM enrollment") || 
                   output.contains("Yes") ||
                   output.contains("Enrolled")
        } catch {
            return false
        }
    }
    
    /// Gets MDM server information if enrolled
    public func getMDMServerInfo() -> (serverURL: String?, organization: String?)? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/profiles")
        task.arguments = ["status", "-type", "enrollment"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            // Parse MDM server URL and org from output
            var serverURL: String?
            var organization: String?
            
            for line in output.components(separatedBy: "\n") {
                if line.contains("MDM server") || line.contains("ServerURL") {
                    serverURL = line.components(separatedBy: ":").dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespaces)
                }
                if line.contains("Organization") {
                    organization = line.components(separatedBy: ":").dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespaces)
                }
            }
            
            return (serverURL, organization)
        } catch {
            return nil
        }
    }
    
    // MARK: - Profile Discovery
    
    /// Lists all installed configuration profiles
    public func listInstalledProfiles() throws -> [MDMProfile] {
        var profiles: [MDMProfile] = []
        
        // Query user profiles
        let userProfiles = try queryProfiles(scope: "user")
        profiles.append(contentsOf: userProfiles)
        
        // Query system profiles (may need sudo)
        let systemProfiles = try queryProfiles(scope: "system")
        profiles.append(contentsOf: systemProfiles)
        
        return profiles
    }
    
    private func queryProfiles(scope: String) throws -> [MDMProfile] {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/profiles")
        task.arguments = ["list", "-output", "stdout-xml"]
        
        let pipe = Pipe()
        let errorPipe = Pipe()
        task.standardOutput = pipe
        task.standardError = errorPipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            
            if data.isEmpty {
                return []
            }
            
            // Parse plist output
            guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                return []
            }
            
            return parseProfilesPlist(plist)
        } catch {
            throw MDMError.profileCommandFailed(error.localizedDescription)
        }
    }
    
    private func parseProfilesPlist(_ plist: [String: Any]) -> [MDMProfile] {
        var profiles: [MDMProfile] = []
        
        // Handle different profile list formats
        let profilesArray: [[String: Any]]
        if let items = plist["_computerlevel"] as? [[String: Any]] {
            profilesArray = items
        } else if let items = plist["profiles"] as? [[String: Any]] {
            profilesArray = items
        } else {
            return []
        }
        
        for item in profilesArray {
            let identifier = item["ProfileIdentifier"] as? String ?? item["profileIdentifier"] as? String ?? "Unknown"
            let displayName = item["ProfileDisplayName"] as? String ?? item["profileDisplayName"] as? String ?? identifier
            let organization = item["ProfileOrganization"] as? String ?? item["profileOrganization"] as? String
            let installDate = item["ProfileInstallDate"] as? Date
            
            let profile = MDMProfile(
                identifier: identifier,
                displayName: displayName,
                organization: organization,
                installDate: installDate,
                isManaged: true,
                certificates: []
            )
            profiles.append(profile)
        }
        
        return profiles
    }
    
    // MARK: - Certificate Discovery
    
    /// Finds all client certificates that could be from MDM
    /// These are typically marked with specific labels or issuers
    public func findMDMCertificates() throws -> [CertificateInfo] {
        var certificates: [CertificateInfo] = []
        
        // Query identities (cert + private key pairs)
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            if status == errSecItemNotFound {
                return []
            }
            throw KeychainError.unexpectedError(status)
        }
        
        for item in items {
            guard let identityRef = item[kSecValueRef as String] else {
                continue
            }
            
            let identity = unsafeBitCast(identityRef as AnyObject, to: SecIdentity.self)
            
            // Extract certificate info
            var certRef: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certRef) == errSecSuccess,
                  let cert = certRef else {
                continue
            }
            
            let label = item[kSecAttrLabel as String] as? String ?? "Unknown"
            let info = KeychainManager.shared.getCertificateInfo(cert)
            
            // Check if this looks like an MDM-provisioned cert
            let isMDMCert = isMDMProvisionedCertificate(label: label, info: info)
            
            if isMDMCert {
                let certInfo = CertificateInfo(
                    commonName: info["Subject"] ?? label,
                    serialNumber: info["Serial"] ?? "Unknown",
                    issuer: extractIssuer(from: cert),
                    expirationDate: extractExpirationDate(from: cert),
                    hasPrivateKey: true,
                    keychainLabel: label
                )
                certificates.append(certInfo)
            }
        }
        
        return certificates
    }
    
    /// Heuristic to detect MDM-provisioned certificates
    private func isMDMProvisionedCertificate(label: String, info: [String: String]) -> Bool {
        let mdmIndicators = [
            "MDM", "Jamf", "Intune", "Mosyle", "Kandji", "Workspace ONE",
            "AirWatch", "MobileIron", "Meraki", "SOTI", "Hexnode",
            "Device Identity", "Client Certificate", "SCEP",
            "com.apple.mdm", "Microsoft Intune", "Corporate"
        ]
        
        let subject = info["Subject"] ?? ""
        let combinedText = "\(label) \(subject)".lowercased()
        
        for indicator in mdmIndicators {
            if combinedText.contains(indicator.lowercased()) {
                return true
            }
        }
        
        // Also include any non-Apple developer certificates
        // as they might be MDM-provisioned
        let developerPrefixes = ["Apple Development", "Developer ID", "iPhone Distribution"]
        for prefix in developerPrefixes {
            if subject.hasPrefix(prefix) {
                return false // Skip Apple dev certs
            }
        }
        
        return false
    }
    
    private func extractIssuer(from certificate: SecCertificate) -> String? {
        // Use Security framework to get issuer
        // This is a simplified version
        if let summary = SecCertificateCopySubjectSummary(certificate) as String? {
            return summary
        }
        return nil
    }
    
    private func extractExpirationDate(from certificate: SecCertificate) -> Date? {
        // Would need to parse the certificate data for expiration
        // Simplified for now
        return nil
    }
    
    // MARK: - Verification
    
    /// Verifies that an MDM certificate is valid and usable for mTLS
    public func verifyCertificateForMTLS(label: String) throws -> SecIdentity {
        // Find the identity
        let identity = try KeychainManager.shared.findIdentity(byLabel: label)
        
        // Verify we can extract the certificate
        let cert = try KeychainManager.shared.extractCertificate(from: identity)
        
        // Verify we can access the private key
        let _ = try KeychainManager.shared.extractPrivateKey(from: identity)
        
        // Create a trust object and evaluate
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        
        guard SecTrustCreateWithCertificates(cert, policy, &trust) == errSecSuccess,
              let trustRef = trust else {
            throw MDMError.identityNotUsable("Failed to create trust object")
        }
        
        // Evaluate trust (checks expiration, etc.)
        var error: CFError?
        if !SecTrustEvaluateWithError(trustRef, &error) {
            let errorDesc = error.map { CFErrorCopyDescription($0) as String? ?? "Unknown" } ?? "Unknown"
            throw MDMError.identityNotUsable(errorDesc)
        }
        
        return identity
    }
    
    // MARK: - Full MDM Check and Connect
    
    /// Performs full MDM verification and returns usable identity
    public func verifyAndGetIdentity() throws -> SecIdentity {
        logger.info("Checking MDM enrollment status...")
        
        // Check if device is MDM enrolled
        if isDeviceEnrolled() {
            logger.success("Device is MDM enrolled")
            
            if let mdmInfo = getMDMServerInfo() {
                if let org = mdmInfo.organization {
                    logger.info("MDM Organization: \(org)")
                }
                if let url = mdmInfo.serverURL {
                    logger.info("MDM Server: \(url)")
                }
            }
        } else {
            logger.warning("Device is not MDM enrolled, checking for manually installed profiles...")
        }
        
        // Find MDM certificates
        logger.info("Searching for MDM-provisioned certificates...")
        let mdmCerts = try findMDMCertificates()
        
        if mdmCerts.isEmpty {
            // Fall back to all available identities
            logger.warning("No MDM certificates found, checking all available identities...")
            let allIdentities = try KeychainManager.shared.listIdentities()
            
            if allIdentities.isEmpty {
                throw MDMError.noCertificatesFound
            }
            
            // Use first available identity
            let first = allIdentities[0]
            logger.info("Using available identity: \(first.label)")
            return try verifyCertificateForMTLS(label: first.label)
        }
        
        // Use first MDM certificate
        let firstCert = mdmCerts[0]
        logger.success("Found MDM certificate: \(firstCert.commonName)")
        
        guard let label = firstCert.keychainLabel else {
            throw MDMError.noCertificatesFound
        }
        
        return try verifyCertificateForMTLS(label: label)
    }
}
