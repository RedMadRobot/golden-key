// swift-tools-version:5.0
//
//  Package.swift
//  GoldenKey
//
//  Created by Ivan Vavilov on 11/10/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import PackageDescription

let package = Package(
    name: "GoldenKey",
    platforms: [
        .macOS(.v10_12),
        .iOS(.v10),
        .tvOS(.v10),
        .watchOS(.v3)
    ],
    products: [
        .library(
            name: "GoldenKey",
            targets: ["GoldenKey"])
    ],
    targets: [
        .target(
            name: "GoldenKey",
            path: "GoldenKey"),
        .testTarget(
            name: "GoldenKeyTests",
            dependencies: ["GoldenKey"],
            path: "GoldenKeyTests")
    ],
    swiftLanguageVersions: [
        .v5
    ]
)