// swift-tools-version: 6.2

import CompilerPluginSupport
import PackageDescription

let package = Package(
    name: "Rigging",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(name: "Rigging", targets: ["Rigging"]),
        .library(name: "RiggingCore", targets: ["RiggingCore"]),
        .library(name: "RiggingOnePassword", targets: ["RiggingOnePassword"]),
        .library(name: "RiggingKeychain", targets: ["RiggingKeychain"]),
        .library(name: "RiggingBitwarden", targets: ["RiggingBitwarden"]),
        .library(name: "RiggingUnixPass", targets: ["RiggingUnixPass"]),
        .library(name: "RiggingArgumentParser", targets: ["RiggingArgumentParser"]),
        .library(name: "RiggingSwiftConfiguration", targets: ["RiggingSwiftConfiguration"]),
        .library(name: "RiggingTOML", targets: ["RiggingTOML"]),
        .library(name: "RiggingYAML", targets: ["RiggingYAML"]),
        .library(name: "RiggingTesting", targets: ["RiggingTesting"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.4.0"),
        .package(url: "https://github.com/swiftlang/swift-syntax.git", from: "604.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.7.0"),
        .package(url: "https://github.com/apple/swift-configuration.git", from: "1.0.0"),
        .package(url: "https://github.com/jpsim/Yams", from: "6.0.0"),
    ],
    targets: [
        // Core runtime with zero external dependencies
        .target(
            name: "RiggingCore"
        ),

        // SwiftSyntax macro compiler plugin
        .macro(
            name: "RiggingMacros",
            dependencies: [
                .product(name: "SwiftSyntaxMacros", package: "swift-syntax"),
                .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
                .product(name: "SwiftSyntax", package: "swift-syntax"),
                .product(name: "SwiftSyntaxBuilder", package: "swift-syntax"),
                .product(name: "SwiftDiagnostics", package: "swift-syntax"),
            ]
        ),

        // Primary user-facing library re-exporting RiggingCore + macro declarations
        .target(
            name: "Rigging",
            dependencies: [
                "RiggingCore",
                "RiggingMacros",
            ]
        ),

        // Secret provider modules
        .target(
            name: "RiggingOnePassword",
            dependencies: ["RiggingCore"]
        ),
        .target(
            name: "RiggingKeychain",
            dependencies: ["RiggingCore"]
        ),
        .target(
            name: "RiggingBitwarden",
            dependencies: ["RiggingCore"]
        ),
        .target(
            name: "RiggingUnixPass",
            dependencies: ["RiggingCore"]
        ),

        // Ecosystem integration modules
        .target(
            name: "RiggingArgumentParser",
            dependencies: [
                "RiggingCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .target(
            name: "RiggingSwiftConfiguration",
            dependencies: [
                "RiggingCore",
                .product(name: "Configuration", package: "swift-configuration"),
            ]
        ),

        // File format extension modules
        .target(
            name: "RiggingTOML",
            dependencies: ["RiggingCore"]
        ),
        .target(
            name: "RiggingYAML",
            dependencies: [
                "RiggingCore",
                .product(name: "Yams", package: "Yams"),
            ]
        ),

        // Testing utilities (mock filesystem, mock subprocess, mock secret providers)
        .target(
            name: "RiggingTesting",
            dependencies: ["RiggingCore"]
        ),

        // Test suites
        .testTarget(
            name: "RiggingCoreTests",
            dependencies: [
                "RiggingCore",
                "RiggingTOML",
                "RiggingYAML",
                "RiggingTesting",
            ]
        ),
        .testTarget(
            name: "RiggingMacroTests",
            dependencies: [
                "Rigging",
                "RiggingMacros",
                "RiggingTesting",
                .product(name: "SwiftSyntaxMacrosTestSupport", package: "swift-syntax"),
                .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
            ]
        ),
        .testTarget(
            name: "SecretProvidersTests",
            dependencies: [
                "RiggingCore",
                "RiggingOnePassword",
                "RiggingKeychain",
                "RiggingBitwarden",
                "RiggingUnixPass",
                "RiggingTesting",
            ]
        ),
        .testTarget(
            name: "ArgumentParserIntegrationTests",
            dependencies: [
                "Rigging",
                "RiggingArgumentParser",
                "RiggingTOML",
                "RiggingYAML",
                "RiggingTesting",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "SwiftConfigurationAdapterTests",
            dependencies: [
                "Rigging",
                "RiggingSwiftConfiguration",
                "RiggingTesting",
                .product(name: "Configuration", package: "swift-configuration"),
            ]
        ),
    ]
)
