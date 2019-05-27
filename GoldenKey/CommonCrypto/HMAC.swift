//
//  HMAC.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation
import CommonCrypto.CommonHMAC

/// hash-based message authentication code
public final class HMAC: Digest {

    /// HMAC algorithm.
    public enum Algorithm {
        case md5
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512

        var rawValue: CCHmacAlgorithm {
            switch self {
            case .md5:
                return CCHmacAlgorithm(kCCHmacAlgMD5)
            case .sha1:
                return CCHmacAlgorithm(kCCHmacAlgSHA1)
            case .sha224:
                return CCHmacAlgorithm(kCCHmacAlgSHA224)
            case .sha256:
                return CCHmacAlgorithm(kCCHmacAlgSHA256)
            case .sha384:
                return CCHmacAlgorithm(kCCHmacAlgSHA384)
            case .sha512:
                return CCHmacAlgorithm(kCCHmacAlgSHA512)
            }
        }

        var digestLength: Int {
            switch self {
            case .md5:
                return Int(CC_MD5_DIGEST_LENGTH)
            case .sha1:
                return Int(CC_SHA1_DIGEST_LENGTH)
            case .sha224:
                return Int(CC_SHA224_DIGEST_LENGTH)
            case .sha256:
                return Int(CC_SHA256_DIGEST_LENGTH)
            case .sha384:
                return Int(CC_SHA384_DIGEST_LENGTH)
            case .sha512:
                return Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
    }

    /// HMAC algorithm.
    public let algorithm: Algorithm

    /// HMAC context.
    private var context = UnsafeMutablePointer<CCHmacContext>.allocate(capacity: 1)

    public init(algorithm: Algorithm, key: Data) {
        self.algorithm = algorithm
        key.withUnsafeBytes { buffer in
            CCHmacInit(context, algorithm.rawValue, buffer.baseAddress, key.count)
        }
    }

    deinit {
        context.deinitialize(count: 1)
        context.deallocate()
    }

    /// Process some data.
    ///
    /// - Parameter data: Data to process.
    public func combine(_ data: Data) {
        data.withUnsafeBytes {
            CCHmacUpdate(context, $0.baseAddress, data.count)
        }
    }

    /// Obtain the final Message Authentication Code.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: algorithm.digestLength)
        data.withUnsafeMutableBytes {
            CCHmacFinal(context, $0.baseAddress)
        }
        return data
    }

    public static func hash(algorithm: Algorithm, data: Data, key: Data) -> Data {
        var bytes = [UInt8](repeating: 0, count: algorithm.digestLength)
        key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCHmac(algorithm.rawValue, keyBytes.baseAddress, key.count, dataBytes.baseAddress, data.count, &bytes)
            }
        }
        return Data(bytes)
    }
}
