//
//  Logger.swift
//  registration - EDR mTLS Client Tool
//
//  Simple logging utility for mTLS operations
//
//  Created by Anubhav Gain on 14/01/26.
//

import Foundation

/// Log levels for controlling output verbosity
public enum LogLevel: Int, Comparable {
    case debug = 0
    case info = 1
    case warning = 2
    case error = 3
    case silent = 4
    
    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
    
    var prefix: String {
        switch self {
        case .debug:   return "[DEBUG]"
        case .info:    return "[INFO]"
        case .warning: return "[WARN]"
        case .error:   return "[ERROR]"
        case .silent:  return ""
        }
    }
    
    var colorCode: String {
        switch self {
        case .debug:   return "\u{001B}[36m"  // Cyan
        case .info:    return "\u{001B}[32m"  // Green
        case .warning: return "\u{001B}[33m"  // Yellow
        case .error:   return "\u{001B}[31m"  // Red
        case .silent:  return ""
        }
    }
}

/// Thread-safe logger for CLI output
public final class Logger: @unchecked Sendable {
    
    public static let shared = Logger()
    
    private var minimumLevel: LogLevel = .info
    private var useColors: Bool = true
    private let resetCode = "\u{001B}[0m"
    private let queue = DispatchQueue(label: "com.edr.logger", qos: .utility)
    
    private init() {
        // Detect if running in a terminal that supports colors
        useColors = isatty(STDOUT_FILENO) != 0
    }
    
    /// Sets the minimum log level
    public func setLevel(_ level: LogLevel) {
        queue.sync { minimumLevel = level }
    }
    
    /// Enables or disables colored output
    public func setColors(_ enabled: Bool) {
        queue.sync { useColors = enabled }
    }
    
    /// Logs a debug message
    public func debug(_ message: String) {
        log(level: .debug, message: message)
    }
    
    /// Logs an info message
    public func info(_ message: String) {
        log(level: .info, message: message)
    }
    
    /// Logs a warning message
    public func warning(_ message: String) {
        log(level: .warning, message: message)
    }
    
    /// Logs an error message
    public func error(_ message: String) {
        log(level: .error, message: message)
    }
    
    /// Logs a message at the specified level
    private func log(level: LogLevel, message: String) {
        queue.async { [self] in
            guard level >= minimumLevel else { return }
            
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let output: String
            
            if useColors {
                output = "\(level.colorCode)\(level.prefix)\(resetCode) \(timestamp) \(message)"
            } else {
                output = "\(level.prefix) \(timestamp) \(message)"
            }
            
            if level == .error {
                FileHandle.standardError.write(Data((output + "\n").utf8))
            } else {
                print(output)
            }
        }
    }
    
    /// Prints a plain message without formatting (for CLI output)
    public func plain(_ message: String) {
        print(message)
    }
    
    /// Prints a success message
    public func success(_ message: String) {
        if useColors {
            print("\u{001B}[32m✓\u{001B}[0m \(message)")
        } else {
            print("OK: \(message)")
        }
    }
    
    /// Prints a failure message
    public func failure(_ message: String) {
        if useColors {
            FileHandle.standardError.write(Data("\u{001B}[31m✗\u{001B}[0m \(message)\n".utf8))
        } else {
            FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        }
    }
}
