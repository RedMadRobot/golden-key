//
//  MD2Tests.swift
//  GoldenKeyTests
//
//  Created by Alexander Ignatev on 11/06/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import XCTest
import GoldenKey

final class MD2Tests: XCTestCase {

    private let bytes: [UInt8] = [
        235, 145, 101, 56,  135, 25,  239, 143,
        204, 182, 39,  223, 13,  220, 80,  19
    ]

    func testUpdateAndFinalize() {
        var hasher1 = MD2()
        hasher1.update(data: Data("hello".utf8))

        var hasher2 = hasher1
        hasher2.update(data: Data(" word".utf8))

        let digest = hasher1.finalize()
        XCTAssertEqual(digest, hasher1.finalize())
        XCTAssertEqual(digest, hasher1.finalize())
        XCTAssertEqual(digest, hasher2.finalize())
        XCTAssertEqual(Array(digest), bytes)
    }

    func testHash() {
        let digest = MD2.hash(data: Data("hello word".utf8))
        XCTAssertEqual(Array(digest), bytes)
    }

    func testDigest() {
        let digest1 = bytes.withUnsafeBytes { MD2Digest(bufferPointer: $0)! }
        XCTAssertEqual(Array(digest1), bytes)

        var bytes = self.bytes
        bytes.append(contentsOf: [21, 32])
        let digest2 = bytes.withUnsafeBytes { MD2Digest(bufferPointer: $0) }
        XCTAssertNil(digest2)
    }

}
