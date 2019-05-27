//
//  RandomBytesTests.swift
//  GoldenKeyTests
//
//  Created by Anton Glezman on 18/04/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import XCTest
import GoldenKey

final class RandomBytesTests: XCTestCase {
    
    func testGenerateBytes() {
        let count = CryptorAlgorithm.aes128.blockSize
        XCTAssertEqual(try RandomBytes.generate(count: count).count, count)
    }
    
}
