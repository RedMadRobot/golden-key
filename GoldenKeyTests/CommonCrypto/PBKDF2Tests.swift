//
//  PBKDF2Tests.swift
//  GoldenKeyTests
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import XCTest
import GoldenKey

final class PBKDF2Tests: XCTestCase {

    func testKeyDerivation() throws {
        let pbkdf = PBKDF2(password: "123", salt: Data("random_bytes".utf8))
        let key = try pbkdf.keyDerivation(.sha256, keyCount: 32, rounds: 1024)

        XCTAssertEqual(key.count, 32)
        XCTAssertEqual(key.base64EncodedString(), "3d92oChv+aHXbJQp9R0oHIVDeru/tl8RC55f1jRUw00=")
    }

}
