// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NFCDocumentReader",
    defaultLocalization: "en",
    platforms: [.iOS(.v17)],
    products: [.library(name: "NFCDocumentReader", targets: ["NFCDocumentReader"])],
    targets: [
        .target(name: "NFCDocumentReader", resources: [.process("Resources")]),
        .testTarget(name: "NFCDocumentReaderTests", dependencies: ["NFCDocumentReader"], path: "Tests")
    ]
)
