//
//  RandomBytes.swift
//  GoldenKey
//
//  Created by Anton Glezman on 18/04/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation
import CommonCrypto.Random

/// The functions provided in RandomBytes implement high-level accessors
/// to cryptographically secure random numbers.
public enum RandomBytes {
    
    /// Returns cryptographically strong random bits suitable for use as cryptographic keys, IVs, nonces etc.
    ///
    /// - Parameter count: Number of random bytes to return.
    /// - Returns: random `Data`.
    /// - Throws: `CryptorError`.
    public static func generate(count: Int) throws -> Data {
        var bytes = [Int8](repeating: 0, count: count)
        let status = CCRandomGenerateBytes(&bytes, bytes.count)
        try CryptorError.verify(status)
        return Data(bytes: bytes, count: bytes.count)
    }
    
}
