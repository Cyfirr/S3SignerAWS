import PackageDescription

let package = Package(
    name: "S3SignerAWS",
    targets: [],
    dependencies: [
        .Package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", majorVersion: 0)
        ]
)
