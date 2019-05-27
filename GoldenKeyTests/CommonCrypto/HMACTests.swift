//
//  HMACTests.swift
//  GoldenKeyTests
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import XCTest
import GoldenKey

final class HMACTests: XCTestCase {

    func testMD5CombineWithFinalize() throws {
        let hmac = HMAC(
            algorithm: .md5,
            key: Data("secret_key".utf8)
        )
        hmac.combine(Data("ab".utf8))
        hmac.combine(Data("cd".utf8))
        let hash = hmac.finalize().base64EncodedString()
        XCTAssertEqual(hash, "CHYyx9XVLDvprNC0Mjq8Gw==")
    }

    func testDigestMD5() throws {
        let hash = HMAC.hash(
            algorithm: .md5,
            data: Data("abcd".utf8),
            key: Data("secret_key".utf8)
        ).base64EncodedString()
        XCTAssertEqual(hash, "CHYyx9XVLDvprNC0Mjq8Gw==")
    }

    func testDigestSHA1() throws {
        let hash = HMAC.hash(
            algorithm: .sha1,
            data: Data("abcd".utf8),
            key: Data("secret_key_2".utf8)
        ).base64EncodedString()
        XCTAssertEqual(hash, "2DNHZktCDQWRODkleoT6ZWUMo+M=")
    }

    func testDigestSHA224() throws {
        let hash = HMAC.hash(
            algorithm: .sha224,
            data: Data("abcd".utf8),
            key: Data("secret_key_3".utf8)
        ).base64EncodedString()
        XCTAssertEqual(hash, "s9zKzHD4fHf5LMGL5Q8LlwkHAAr9BOr1qLhRkA==")
    }

    func testDigestSHA256() throws {
        let hash = HMAC.hash(
            algorithm: .sha256,
            data: Data("abcd".utf8),
            key: Data("secret_key_4".utf8)
        ).base64EncodedString()
        XCTAssertEqual(hash, "S5i/m1NtdkG1dXppNZnI/1deJRj4RIla805OEi6UoI4=")
    }

    func testDigestSHA384() throws {
        let hash = HMAC.hash(
            algorithm: .sha384,
            data: Data("abcd".utf8),
            key: Data("secret_key_5".utf8)
        ).base64EncodedString()
        XCTAssertEqual(hash, "b7xeaROiF+2NUxwLLK/YRo1num78hAs99E5eViQW5LkhorqPyPd905NZLV5f7jTR")
    }

}
