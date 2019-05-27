//
//  CryptorError.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation
import CommonCrypto.Error

/// Errors from `Cryptor` operations.
///
/// - SeeAlso: CommonCryptoError.h
public struct CryptorError: Error, RawRepresentable, Hashable {
    public let rawValue: CCStatus

    public init(rawValue: CCStatus) {
        self.rawValue = rawValue
    }

    init(_ rawValue: Int) {
        self.rawValue = CCStatus(rawValue)
    }

    /// Verify `Cryptor` operation status.
    ///
    /// - Parameter status: `Cryptor` operation status.
    /// - Throws: `CryptorError`.
    static func verify(_ status: CCCryptorStatus) throws {
        if status == kCCSuccess { return }
        throw CryptorError(rawValue: status)
    }
}

extension CryptorError {

    /// Illegal parameter value.
    public static var paramError: CryptorError { return CryptorError(kCCParamError) }

    /// Insufficent buffer provided for specified operation.
    public static var bufferTooSmall: CryptorError { return CryptorError(kCCBufferTooSmall) }

    /// Memory allocation failure.
    public static var memoryFailure: CryptorError { return CryptorError(kCCMemoryFailure) }

    /// Input size was not aligned properly.
    public static var alignmentError: CryptorError { return CryptorError(kCCAlignmentError) }

    /// Input data did not decode or decrypt properly.
    public static var decodeError: CryptorError { return CryptorError(kCCDecodeError) }

    /// Function not implemented for the current algorithm.
    public static var unimplemented: CryptorError { return CryptorError(kCCUnimplemented) }

    /// Key is not valid.
    public static var invalidKey: CryptorError { return CryptorError(kCCInvalidKey) }
}

extension CryptorError: LocalizedError {

    /// A localized message describing what error occurred.
    public var errorDescription: String? {
        switch self {
        case .paramError:
            return "Illegal parameter value"
        case .bufferTooSmall:
            return "Insufficent buffer provided for specified operation"
        case .memoryFailure:
            return "Memory allocation failure"
        case .alignmentError:
            return "Input size was not aligned properly"
        case .decodeError:
            return "Input data did not decode or decrypt properly"
        case .unimplemented:
            return "Function not implemented for the current algorithm"
        case .invalidKey:
            return "Key is not valid"
        default:
            return "Unknown status: \(rawValue)"
        }
    }
}
