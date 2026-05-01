// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "PackProtocol",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(name: "PackProtocol", targets: ["PackProtocol"]),
    ],
    targets: [
        .target(
            name: "CPackProtocolFFI",
            path: "CPackProtocolFFI",
            publicHeadersPath: "include"
        ),
        .target(
            name: "PackProtocol",
            dependencies: ["CPackProtocolFFI"],
            path: "Sources/PackProtocol"
        ),
        .testTarget(
            name: "PackProtocolTests",
            dependencies: ["PackProtocol"],
            path: "Tests/PackProtocolTests"
        ),
    ]
)
