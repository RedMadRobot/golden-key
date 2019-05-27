//
//  PBKDF2.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation
import CommonCrypto.CommonKeyDerivation

/// Password Based Key Derivation 2.
public struct PBKDF2 {

    /// The Pseudo Random Algorithm to use for the derivation iterations.
    public enum PseudoRandomAlgorithm {
        case sha1
        case sha224
        case sha256
        case sha384
        case sha1512
    }

    /// The text password used as input to the derivation function.
    private let password: String

    /// The salt byte values used as input to the derivation function.
    private let salt: Data

    /// Password Based Key Derivation 2.
    ///
    /// - Parameters:
    ///   - password: The text password used as input to the derivation function.
    ///   - salt: The salt byte values used as input to the derivation function.
    public init(password: String, salt: Data) {
        self.password = password
        self.salt = salt
    }

    /// Derive a key from a text password/passphrase.
    ///
    /// - Parameters:
    ///   - algorithm: The Pseudo Random Algorithm to use for the derivation iterations.
    ///   - keyCount: The expected length of the derived key in bytes. It cannot be zero.
    ///   - rounds: The number of rounds of the Pseudo Random Algorithm to use. It cannot be zero.
    /// - Returns: Derived key.
    /// - Throws: `CryptorError`.
    public func keyDerivation(
        _ pseudoRandomAlgorithm: PseudoRandomAlgorithm,
        keyCount: Int,
        rounds: UInt32
    ) throws -> Data {

        var derivedKey = [UInt8](repeating: 0, count: keyCount)

        let status = salt.withUnsafeBytes { (saltBuffer: UnsafeRawBufferPointer) -> CCStatus in
            return CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password, password.utf8.count,
                saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                salt.count,
                pseudoRandomAlgorithm.rawValue,
                rounds,
                &derivedKey, derivedKey.count)
        }
        try CryptorError.verify(status)

        return Data(derivedKey)
    }

    /// Calibrate PBKDF.
    ///
    /// Determine the number of PRF rounds to use for a specific delay on the current platform.
    ///
    /// - Parameters:
    ///   - pseudoRandomAlgorithm: The Pseudo Random Algorithm to use for the derivation iterations.
    ///   - keyCount: The expected length of the derived key in bytes.
    ///   - milliseconds: The targetted duration we want to achieve for a key derivation with these parameters.
    /// - Returns: The number of iterations to use for the desired processing time.
    ///             Returns a minimum of 10000 iterations (safety net, not a particularly recommended value)
    ///             The number of iterations is a trade-off of usability and security. If there is an error
    ///             the function returns (unsigned)(-1). The minimum return value is set to 10000.
    public func calibrate(
        _ pseudoRandomAlgorithm: PseudoRandomAlgorithm,
        keyCount: Int,
        milliseconds: UInt32
    ) -> UInt32 {

        return CCCalibratePBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password.utf8.count,
            salt.count,
            pseudoRandomAlgorithm.rawValue,
            keyCount,
            milliseconds)
    }
}

private extension PBKDF2.PseudoRandomAlgorithm {

    var rawValue: CCPBKDFAlgorithm {
        switch self {
        case .sha1:
            return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1)
        case .sha224:
            return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA224)
        case .sha256:
            return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256)
        case .sha384:
            return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA384)
        case .sha1512:
            return CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512)
        }
    }
}
