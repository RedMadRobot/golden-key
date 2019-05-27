//
//  SHA256Tests.swift
//  GoldenKeyTests
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import XCTest
import GoldenKey

final class SHA256Tests: XCTestCase {

    func testCombineWithFinalize() throws {
        let sha = SHA256()
        sha.combine(Data("user".utf8))
        sha.combine(Data("_id".utf8))
        let hash = sha.finalize()
        XCTAssertEqual(hash.base64EncodedString(), "+J1raWBFMkG8Wwm00NithtU3aeBRRzNQwr+U45B3lns=")
    }

    func testDigest() {
        let hash = SHA256.hash(Data("user_id".utf8))
        XCTAssertEqual(hash.base64EncodedString(), "+J1raWBFMkG8Wwm00NithtU3aeBRRzNQwr+U45B3lns=")
    }

}
