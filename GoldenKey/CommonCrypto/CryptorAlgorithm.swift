//
//  CryptorAlgorithm.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation
import CommonCrypto.CommonCryptor

/// Symmetric encryption algorithm.
///
/// - aes: Advanced Encryption Standard.
/// - des: Data Encryption Standard.
/// - tripleDes: Triple-DES, three key, EDE configuration.
/// - cast: CAST.
/// - rc4: RC4 stream cipher.
/// - blowfish: Blowfish block cipher.
public enum CryptorAlgorithm {
    case aes128
    case aes192
    case aes256
    case des
    case tripleDes
    case cast(keySize: Int)
    case rc2(keySize: Int)
    case rc4(keySize: Int)
    case blowfish(keySize: Int)

    var rawValue: CCAlgorithm {
        switch self {
        case .aes128, .aes192, .aes256:
            return CCAlgorithm(kCCAlgorithmAES)
        case .des:
            return CCAlgorithm(kCCAlgorithmDES)
        case .tripleDes:
            return CCAlgorithm(kCCAlgorithm3DES)
        case .cast:
            return CCAlgorithm(kCCAlgorithmCAST)
        case .rc2:
            return CCAlgorithm(kCCAlgorithmRC2)
        case .rc4:
            return CCAlgorithm(kCCAlgorithmRC4)
        case .blowfish:
            return CCAlgorithm(kCCAlgorithmBlowfish)
        }
    }

    /// Block size.
    ///
    /// Block sizes, in bytes, for supported algorithms.
    public var blockSize: Int {
        switch self {
        case .aes128, .aes192, .aes256:
            return kCCBlockSizeAES128
        case .des:
            return kCCBlockSizeDES
        case .tripleDes:
            return kCCBlockSize3DES
        case .cast:
            return kCCBlockSizeCAST
        case .rc4, .rc2:
            return kCCBlockSizeRC2
        case .blowfish:
            return kCCBlockSizeBlowfish
        }
    }

    /// Key size.
    public var keySize: Int {
        switch self {
        case .aes128:
            return kCCKeySizeAES128
        case .aes192:
            return kCCKeySizeAES192
        case .aes256:
            return kCCKeySizeAES256
        case .des:
            return kCCKeySizeDES
        case .tripleDes:
            return kCCKeySize3DES
        case .cast(let keySize),
             .rc2(let keySize),
             .rc4(let keySize),
             .blowfish(let keySize):
            return keySize
        }
    }

    private var availableKeySize: ClosedRange<Int> {
        switch self {
        case .cast:
            return kCCKeySizeMinCAST...kCCKeySizeMaxCAST
        case .rc2:
            return kCCKeySizeMinRC2...kCCKeySizeMaxRC2
        case .rc4:
            return kCCKeySizeMinRC4...kCCKeySizeMaxRC4
        case .blowfish:
            return kCCKeySizeMinBlowfish...kCCKeySizeMaxBlowfish
        default:
            return keySize...keySize
        }
    }

    func validate(key: Data) throws {
        guard availableKeySize.contains(key.count) else {
            throw CryptorError.paramError
        }
    }

    func validate(iv: Data) throws {
        guard iv.count == blockSize else {
            throw CryptorError.paramError
        }
    }
}
