// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.
//
//  Package.swift
//  registration - EDR mTLS Client Tool
//
//  RFC 8446 (TLS 1.3) compliant mutual TLS testing tool
//  RFC 5280 (X.509) certificate handling via macOS Keychain
//
//  Created by Anubhav Gain on 14/01/26.
//

import PackageDescription

let package = Package(
    name: "registration",
    platforms: [
        .macOS(.v13)  // Requires macOS 13+ for modern TLS APIs
    ],
    dependencies: [
        // Swift ArgumentParser for CLI argument handling
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        .executableTarget(
            name: "registration",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources",
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"])
            ]
        ),
    ]
)
