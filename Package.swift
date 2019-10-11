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
        .iOS(.v10)
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