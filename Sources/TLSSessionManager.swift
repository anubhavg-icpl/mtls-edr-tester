//
//  TLSSessionManager.swift
//  registration - EDR mTLS Client Tool
//
//  RFC 8446 (TLS 1.3) compliant session manager for mutual TLS
//  Implements client certificate authentication per RFC 5280
//
//  Created by Anubhav Gain on 14/01/26.
//

import Foundation
import Security

/// TLS protocol version enforcement per RFC 8446
public enum TLSVersion: String, CaseIterable {
    case tls12 = "TLS 1.2"
    case tls13 = "TLS 1.3"
    
    var protocolVersion: tls_protocol_version_t {
        switch self {
        case .tls12:
            return .TLSv12
        case .tls13:
            return .TLSv13
        }
    }
}

/// Configuration for mTLS connections following RFC standards
public struct MTLSConfiguration {
    /// Minimum TLS version (RFC 8446 recommends TLS 1.3)
    public let minimumTLSVersion: TLSVersion
    
    /// Client identity for mutual authentication
    public let clientIdentity: SecIdentity?
    
    /// Trusted root CA certificates for server verification
    public let trustedCertificates: [SecCertificate]
    
    /// Whether to allow self-signed certificates (dev only)
    public let allowSelfSigned: Bool
    
    /// Connection timeout in seconds
    public let timeoutInterval: TimeInterval
    
    /// Enable verbose TLS logging
    public let verboseLogging: Bool
    
    public init(
        minimumTLSVersion: TLSVersion = .tls13,
        clientIdentity: SecIdentity? = nil,
        trustedCertificates: [SecCertificate] = [],
        allowSelfSigned: Bool = false,
        timeoutInterval: TimeInterval = 30,
        verboseLogging: Bool = false
    ) {
        self.minimumTLSVersion = minimumTLSVersion
        self.clientIdentity = clientIdentity
        self.trustedCertificates = trustedCertificates
        self.allowSelfSigned = allowSelfSigned
        self.timeoutInterval = timeoutInterval
        self.verboseLogging = verboseLogging
    }
}

/// Result of an mTLS request
public struct MTLSResponse {
    public let statusCode: Int
    public let headers: [String: String]
    public let body: Data?
    public let tlsVersion: String?
    public let serverCertificate: SecCertificate?
    
    public var bodyString: String? {
        guard let data = body else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

/// Errors specific to mTLS operations
public enum MTLSError: LocalizedError {
    case noClientIdentity
    case tlsHandshakeFailed(String)
    case serverCertificateRejected(String)
    case connectionFailed(String)
    case invalidURL
    case noResponse
    case httpError(statusCode: Int, message: String?)
    
    public var errorDescription: String? {
        switch self {
        case .noClientIdentity:
            return "No client identity configured for mTLS. Provide a certificate via Keychain or .p12 file."
        case .tlsHandshakeFailed(let reason):
            return "TLS handshake failed: \(reason)"
        case .serverCertificateRejected(let reason):
            return "Server certificate rejected: \(reason)"
        case .connectionFailed(let reason):
            return "Connection failed: \(reason)"
        case .invalidURL:
            return "Invalid URL provided."
        case .noResponse:
            return "No response received from server."
        case .httpError(let code, let message):
            return "HTTP \(code): \(message ?? "Unknown error")"
        }
    }
}

/// Delegate for handling mTLS authentication challenges
/// Implements RFC 8446 client authentication flow
public final class MTLSSessionDelegate: NSObject, URLSessionDelegate {
    
    private let configuration: MTLSConfiguration
    private let logger: Logger
    private var serverCertificate: SecCertificate?
    
    public init(configuration: MTLSConfiguration, logger: Logger = .shared) {
        self.configuration = configuration
        self.logger = logger
        super.init()
    }
    
    /// Handles authentication challenges per RFC 8446 Section 4.4
    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let authMethod = challenge.protectionSpace.authenticationMethod
        
        if configuration.verboseLogging {
            logger.debug("Received authentication challenge: \(authMethod)")
        }
        
        switch authMethod {
        case NSURLAuthenticationMethodClientCertificate:
            handleClientCertificateChallenge(challenge, completionHandler: completionHandler)
            
        case NSURLAuthenticationMethodServerTrust:
            handleServerTrustChallenge(challenge, completionHandler: completionHandler)
            
        default:
            if configuration.verboseLogging {
                logger.debug("Using default handling for: \(authMethod)")
            }
            completionHandler(.performDefaultHandling, nil)
        }
    }
    
    /// Handles client certificate authentication (RFC 8446 Section 4.4.2)
    /// Client sends Certificate + CertificateVerify messages
    private func handleClientCertificateChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let identity = configuration.clientIdentity else {
            logger.error("Client certificate requested but no identity configured")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        do {
            let credential = try KeychainManager.shared.createCredential(from: identity)
            
            if configuration.verboseLogging {
                let cert = try KeychainManager.shared.extractCertificate(from: identity)
                let info = KeychainManager.shared.getCertificateInfo(cert)
                logger.info("Presenting client certificate: \(info["Subject"] ?? "Unknown")")
            }
            
            completionHandler(.useCredential, credential)
        } catch {
            logger.error("Failed to create credential: \(error.localizedDescription)")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    /// Handles server certificate verification (RFC 5280 path validation)
    private func handleServerTrustChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            logger.error("No server trust information available")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Store server certificate for later inspection
        if let certChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
           let leafCert = certChain.first {
            self.serverCertificate = leafCert
            
            if configuration.verboseLogging {
                let info = KeychainManager.shared.getCertificateInfo(leafCert)
                logger.info("Server certificate: \(info["Subject"] ?? "Unknown")")
            }
        }
        
        // Add custom trusted certificates if provided
        if !configuration.trustedCertificates.isEmpty {
            SecTrustSetAnchorCertificates(serverTrust, configuration.trustedCertificates as CFArray)
            SecTrustSetAnchorCertificatesOnly(serverTrust, false)
        }
        
        // Evaluate server certificate per RFC 5280
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &error)
        
        if isValid {
            if configuration.verboseLogging {
                logger.info("Server certificate validation successful")
            }
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else if configuration.allowSelfSigned {
            logger.warning("Accepting self-signed certificate (development mode)")
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            let errorMessage = error.map { CFErrorCopyDescription($0) as String? ?? "Unknown" } ?? "Unknown"
            logger.error("Server certificate validation failed: \(errorMessage)")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    public func getServerCertificate() -> SecCertificate? {
        return serverCertificate
    }
}

/// Main session manager for mTLS connections
public final class TLSSessionManager: @unchecked Sendable {
    
    private let configuration: MTLSConfiguration
    private let logger: Logger
    private var session: URLSession?
    private var delegate: MTLSSessionDelegate?
    
    public init(configuration: MTLSConfiguration, logger: Logger = .shared) {
        self.configuration = configuration
        self.logger = logger
        setupSession()
    }
    
    private func setupSession() {
        delegate = MTLSSessionDelegate(configuration: configuration, logger: logger)
        
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = configuration.timeoutInterval
        sessionConfig.timeoutIntervalForResource = configuration.timeoutInterval * 2
        
        // RFC 8446: Enforce minimum TLS version
        sessionConfig.tlsMinimumSupportedProtocolVersion = 
            configuration.minimumTLSVersion == .tls13 ? .TLSv13 : .TLSv12
        
        // Prefer TLS 1.3
        sessionConfig.tlsMaximumSupportedProtocolVersion = .TLSv13
        
        session = URLSession(
            configuration: sessionConfig,
            delegate: delegate,
            delegateQueue: nil
        )
        
        if configuration.verboseLogging {
            logger.info("TLS Session configured with minimum: \(configuration.minimumTLSVersion.rawValue)")
        }
    }
    
    /// Performs an mTLS GET request
    public func get(url: String) async throws -> MTLSResponse {
        guard let requestURL = URL(string: url) else {
            throw MTLSError.invalidURL
        }
        
        var request = URLRequest(url: requestURL)
        request.httpMethod = "GET"
        
        return try await performRequest(request)
    }
    
    /// Performs an mTLS POST request
    public func post(url: String, body: Data?, contentType: String = "application/json") async throws -> MTLSResponse {
        guard let requestURL = URL(string: url) else {
            throw MTLSError.invalidURL
        }
        
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        
        return try await performRequest(request)
    }
    
    /// Performs an mTLS request with the given URLRequest
    public func performRequest(_ request: URLRequest) async throws -> MTLSResponse {
        guard let session = session else {
            throw MTLSError.connectionFailed("Session not initialized")
        }
        
        if configuration.verboseLogging {
            logger.info("Initiating mTLS request to: \(request.url?.absoluteString ?? "unknown")")
        }
        
        do {
            let (data, response) = try await session.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                throw MTLSError.noResponse
            }
            
            // Extract headers
            var headers: [String: String] = [:]
            for (key, value) in httpResponse.allHeaderFields {
                if let keyStr = key as? String, let valStr = value as? String {
                    headers[keyStr] = valStr
                }
            }
            
            if configuration.verboseLogging {
                logger.info("Response: HTTP \(httpResponse.statusCode)")
            }
            
            return MTLSResponse(
                statusCode: httpResponse.statusCode,
                headers: headers,
                body: data,
                tlsVersion: configuration.minimumTLSVersion.rawValue,
                serverCertificate: delegate?.getServerCertificate()
            )
        } catch let error as URLError {
            throw MTLSError.connectionFailed(error.localizedDescription)
        }
    }
    
    /// Invalidates the session
    public func invalidate() {
        session?.invalidateAndCancel()
    }
}
