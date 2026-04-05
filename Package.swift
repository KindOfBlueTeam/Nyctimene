// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Nyctimene",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "6.0.0")
    ],
    targets: [
        // Shared core: config, storage, engine, VT client
        .target(
            name: "NyctimeneCore",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift")
            ],
            path: "Sources/NyctimeneCore"
        ),
        // Menubar app (UI + app lifecycle)
        .executableTarget(
            name: "Nyctimene",
            dependencies: ["NyctimeneCore"],
            path: "Sources/Nyctimene",
            resources: [.process("Resources")]
        )
    ]
)
