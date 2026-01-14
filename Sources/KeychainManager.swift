//
//  KeychainManager.swift
//  registration - EDR mTLS Client Tool
//
//  Manages X.509 certificate identities from macOS Keychain
//  Implements RFC 5280 certificate handling for mTLS authentication
//
//  Created by Anubhav Gain on 14/01/26.
//

import Foundation
import Security

/// Errors that can occur during Keychain operations
public enum KeychainError: LocalizedError {
    case identityNotFound(label: String)
    case certificateNotFound
    case privateKeyNotFound
    case accessDenied
    case invalidData
    case unexpectedError(OSStatus)
    case p12ImportFailed(OSStatus)
    case noIdentitiesInP12
    
    public var errorDescription: String? {
        switch self {
        case .identityNotFound(let label):
            return "Identity '\(label)' not found in Keychain. Ensure the certificate is installed via MDM profile."
        case .certificateNotFound:
            return "Certificate not found in identity."
        case .privateKeyNotFound:
            return "Private key not found in identity."
        case .accessDenied:
            return "Access to Keychain was denied. Check your permissions."
        case .invalidData:
            return "Invalid data returned from Keychain."
        case .unexpectedError(let status):
            return "Keychain error: \(status) - \(SecCopyErrorMessageString(status, nil) as String? ?? "Unknown")"
        case .p12ImportFailed(let status):
            return "Failed to import PKCS#12: \(status) - \(SecCopyErrorMessageString(status, nil) as String? ?? "Unknown")"
        case .noIdentitiesInP12:
            return "No identities found in PKCS#12 file."
        }
    }
}

/// Manages loading and handling of X.509 identities from macOS Keychain
/// Compliant with RFC 5280 for certificate profiles
public final class KeychainManager: @unchecked Sendable {
    
    public static let shared = KeychainManager()
    
    private init() {}
    
    // MARK: - Identity Loading from Keychain
    
    /// Finds an identity in the Keychain by its label (Common Name)
    /// - Parameter label: The label/common name of the certificate to find
    /// - Returns: The SecIdentity containing the certificate and private key
    /// - Throws: KeychainError if identity cannot be found or accessed
    public func findIdentity(byLabel label: String) throws -> SecIdentity {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        switch status {
        case errSecSuccess:
            guard let ref = result else {
                throw KeychainError.invalidData
            }
            // SecIdentity is toll-free bridged, use unsafeBitCast for CF types
            let identity = unsafeBitCast(ref, to: SecIdentity.self)
            return identity
        case errSecItemNotFound:
            throw KeychainError.identityNotFound(label: label)
        case errSecAuthFailed, errSecInteractionNotAllowed:
            throw KeychainError.accessDenied
        default:
            throw KeychainError.unexpectedError(status)
        }
    }
    
    /// Lists all available identities in the Keychain
    /// - Returns: Array of tuples containing label and SecIdentity
    public func listIdentities() throws -> [(label: String, identity: SecIdentity)] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return []
            }
            throw KeychainError.unexpectedError(status)
        }
        
        guard let items = result as? [[String: Any]] else {
            throw KeychainError.invalidData
        }
        
        return items.compactMap { item in
            guard let ref = item[kSecValueRef as String],
                  let label = item[kSecAttrLabel as String] as? String else {
                return nil
            }
            let identity = unsafeBitCast(ref as AnyObject, to: SecIdentity.self)
            return (label, identity)
        }
    }
    
    // MARK: - PKCS#12 Import (for development/testing)
    
    /// Imports an identity from a PKCS#12 (.p12) file
    /// - Parameters:
    ///   - path: Path to the .p12 file
    ///   - password: Password to decrypt the .p12 file
    /// - Returns: The imported SecIdentity
    public func importIdentity(fromP12 path: String, password: String) throws -> SecIdentity {
        let p12Data = try Data(contentsOf: URL(fileURLWithPath: path))
        
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: password
        ]
        
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        
        guard status == errSecSuccess else {
            throw KeychainError.p12ImportFailed(status)
        }
        
        guard let itemsArray = items as? [[String: Any]],
              let firstItem = itemsArray.first,
              let identityRef = firstItem[kSecImportItemIdentity as String] else {
            throw KeychainError.noIdentitiesInP12
        }
        
        let identity = unsafeBitCast(identityRef as AnyObject, to: SecIdentity.self)
        return identity
    }
    
    // MARK: - Certificate Extraction
    
    /// Extracts the certificate from an identity
    /// - Parameter identity: The SecIdentity to extract from
    /// - Returns: The certificate as SecCertificate
    public func extractCertificate(from identity: SecIdentity) throws -> SecCertificate {
        var certificate: SecCertificate?
        let status = SecIdentityCopyCertificate(identity, &certificate)
        
        guard status == errSecSuccess, let cert = certificate else {
            throw KeychainError.certificateNotFound
        }
        
        return cert
    }
    
    /// Extracts the private key from an identity
    /// - Parameter identity: The SecIdentity to extract from
    /// - Returns: The private key as SecKey
    public func extractPrivateKey(from identity: SecIdentity) throws -> SecKey {
        var privateKey: SecKey?
        let status = SecIdentityCopyPrivateKey(identity, &privateKey)
        
        guard status == errSecSuccess, let key = privateKey else {
            throw KeychainError.privateKeyNotFound
        }
        
        return key
    }
    
    // MARK: - Certificate Information
    
    /// Gets human-readable information about a certificate
    /// - Parameter certificate: The certificate to inspect
    /// - Returns: Dictionary of certificate properties
    public func getCertificateInfo(_ certificate: SecCertificate) -> [String: String] {
        var info: [String: String] = [:]
        
        // Get subject summary (Common Name)
        if let summary = SecCertificateCopySubjectSummary(certificate) as String? {
            info["Subject"] = summary
        }
        
        // Get serial number
        if let serialData = SecCertificateCopySerialNumberData(certificate, nil) as Data? {
            info["Serial"] = serialData.map { String(format: "%02X", $0) }.joined(separator: ":")
        }
        
        return info
    }
    
    /// Creates URLCredential from an identity for use with URLSession
    /// - Parameter identity: The SecIdentity to create credential from
    /// - Returns: URLCredential for client certificate authentication
    public func createCredential(from identity: SecIdentity) throws -> URLCredential {
        let certificate = try extractCertificate(from: identity)
        return URLCredential(
            identity: identity,
            certificates: [certificate],
            persistence: .forSession
        )
    }
}
