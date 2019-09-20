//
//  CommonDigest.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 02/01/2019.
//  Copyright © 2019 Alexander Ignition. All rights reserved.
//

import Foundation
import CommonCrypto.CommonDigest

public protocol Digest {

    /// Updates the digest with another data chunk. This can be called multiple times.
    /// Use this method for streaming digests.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    func combine<T>(_ bytes: T) where T: ContiguousBytes

    /// Return the digest of the data passed to the `combine(_:)` method so far.
    func finalize() -> Data
}
    
/// Class for MD2 cryptographic hash generation
public final class MD2: Digest {
    private var context = UnsafeMutablePointer<CC_MD2_CTX>.allocate(capacity: 1)

    /// Initializes a MD2_CTX structure
    public init() {
        CC_MD2_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_MD2_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the MD2 data digest (cryptographic hash).
    /// Erases the MD2_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in MD2.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_MD2_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_MD2_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the MD2 data digest.
    /// Command line analog:
    /// $ openssl MD2 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in MD2.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_MD2_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_MD2(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

/// Class for MD4 cryptographic hash generation
public final class MD4: Digest {
    private var context = UnsafeMutablePointer<CC_MD4_CTX>.allocate(capacity: 1)

    /// Initializes a MD4_CTX structure
    public init() {
        CC_MD4_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_MD4_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the MD4 data digest (cryptographic hash).
    /// Erases the MD4_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in MD4.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_MD4_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_MD4_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the MD4 data digest.
    /// Command line analog:
    /// $ openssl MD4 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in MD4.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_MD4_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_MD4(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

/// Class for MD5 cryptographic hash generation
public final class MD5: Digest {
    private var context = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)

    /// Initializes a MD5_CTX structure
    public init() {
        CC_MD5_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_MD5_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the MD5 data digest (cryptographic hash).
    /// Erases the MD5_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in MD5.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_MD5_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the MD5 data digest.
    /// Command line analog:
    /// $ openssl MD5 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in MD5.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_MD5(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

/// Class for SHA1 cryptographic hash generation
public final class SHA1: Digest {
    private var context = UnsafeMutablePointer<CC_SHA1_CTX>.allocate(capacity: 1)

    /// Initializes a SHA1_CTX structure
    public init() {
        CC_SHA1_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA1_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the SHA1 data digest (cryptographic hash).
    /// Erases the SHA1_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in SHA1.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_SHA1_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the SHA1 data digest.
    /// Command line analog:
    /// $ openssl SHA1 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in SHA1.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA1(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

/// Class for SHA224 cryptographic hash generation
public final class SHA224: Digest {
    private var context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)

    /// Initializes a SHA224_CTX structure
    public init() {
        CC_SHA224_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA224_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the SHA224 data digest (cryptographic hash).
    /// Erases the SHA224_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in SHA224.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_SHA224_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the SHA224 data digest.
    /// Command line analog:
    /// $ openssl SHA224 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in SHA224.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA224(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

/// Class for SHA256 cryptographic hash generation
public final class SHA256: Digest {
    private var context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)

    /// Initializes a SHA256_CTX structure
    public init() {
        CC_SHA256_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA256_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the SHA256 data digest (cryptographic hash).
    /// Erases the SHA256_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in SHA256.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_SHA256_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the SHA256 data digest.
    /// Command line analog:
    /// $ openssl SHA256 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in SHA256.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA256(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

/// Class for SHA384 cryptographic hash generation
public final class SHA384: Digest {
    private var context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)

    /// Initializes a SHA384_CTX structure
    public init() {
        CC_SHA384_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA384_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the SHA384 data digest (cryptographic hash).
    /// Erases the SHA384_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in SHA384.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_SHA384_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the SHA384 data digest.
    /// Command line analog:
    /// $ openssl SHA384 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in SHA384.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA384(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

/// Class for SHA512 cryptographic hash generation
public final class SHA512: Digest {
    private var context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)

    /// Initializes a SHA512_CTX structure
    public init() {
        CC_SHA512_Init(context)
    }

    deinit {
        context.deallocate()
    }

    /// Combines data to be hashed.
    /// Can be called repeatedly with chunks of the message.
    ///
    /// - Parameters: bytes: Data chunk to digest.
    public func combine<T>(_ bytes: T) where T: ContiguousBytes {
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA512_Update(context, buffer.baseAddress, CC_LONG(buffer.count))
        }
    }

    /// Computes the SHA512 data digest (cryptographic hash).
    /// Erases the SHA512_CTX structure.
    ///
    /// - Returns: data digest (cryptographic hash) in SHA512.
    public func finalize() -> Data {
        var data = Data(repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Void in
            _ = CC_SHA512_Final(buffer.bindMemory(to: UInt8.self).baseAddress, context)
        }
        return data
    }

    /// Computes the SHA512 data digest.
    /// Command line analog:
    /// $ openssl SHA512 <<< "string_to_be_hashed"
    ///
    /// - Returns: data digest (cryptographic hash) in SHA512.
    public static func hash<T>(_ bytes: T) -> Data where T: ContiguousBytes {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        bytes.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Void in
            _ = CC_SHA512(buffer.baseAddress, CC_LONG(buffer.count), &result)
        }
        return Data(result)
    }
}

