//
//  CommonDigest.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 02/01/2019.
//  Copyright © 2019 Alexander Ignition. All rights reserved.
//

import Foundation
import CommonCrypto.CommonDigest

    
public struct MD2Digest: Digest {
    public static var byteCount: Int { return Int(CC_MD2_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard MD2Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct MD2: HashFunction {
    public typealias Digest = MD2Digest

    private let context = Shared(UnsafeMutablePointer<CC_MD2_CTX>.allocate(capacity: 1))

    public init() {
        CC_MD2_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_MD2_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> MD2Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: MD2Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_MD2_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_MD2_Final(buffer.baseAddress, context)
        return MD2Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> MD2Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: MD2Digest.byteCount)
        defer { buffer.deallocate() }

        CC_MD2(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return MD2Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

public struct MD4Digest: Digest {
    public static var byteCount: Int { return Int(CC_MD4_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard MD4Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct MD4: HashFunction {
    public typealias Digest = MD4Digest

    private let context = Shared(UnsafeMutablePointer<CC_MD4_CTX>.allocate(capacity: 1))

    public init() {
        CC_MD4_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_MD4_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> MD4Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: MD4Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_MD4_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_MD4_Final(buffer.baseAddress, context)
        return MD4Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> MD4Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: MD4Digest.byteCount)
        defer { buffer.deallocate() }

        CC_MD4(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return MD4Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

public struct MD5Digest: Digest {
    public static var byteCount: Int { return Int(CC_MD5_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard MD5Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct MD5: HashFunction {
    public typealias Digest = MD5Digest

    private let context = Shared(UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1))

    public init() {
        CC_MD5_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_MD5_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> MD5Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: MD5Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_MD5_Final(buffer.baseAddress, context)
        return MD5Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> MD5Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: MD5Digest.byteCount)
        defer { buffer.deallocate() }

        CC_MD5(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return MD5Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

public struct SHA1Digest: Digest {
    public static var byteCount: Int { return Int(CC_SHA1_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard SHA1Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct SHA1: HashFunction {
    public typealias Digest = SHA1Digest

    private let context = Shared(UnsafeMutablePointer<CC_SHA1_CTX>.allocate(capacity: 1))

    public init() {
        CC_SHA1_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA1_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> SHA1Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA1Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_SHA1_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_SHA1_Final(buffer.baseAddress, context)
        return SHA1Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> SHA1Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA1Digest.byteCount)
        defer { buffer.deallocate() }

        CC_SHA1(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return SHA1Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

public struct SHA224Digest: Digest {
    public static var byteCount: Int { return Int(CC_SHA224_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard SHA224Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct SHA224: HashFunction {
    public typealias Digest = SHA224Digest

    private let context = Shared(UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1))

    public init() {
        CC_SHA224_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA224_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> SHA224Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA224Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_SHA224_Final(buffer.baseAddress, context)
        return SHA224Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> SHA224Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA224Digest.byteCount)
        defer { buffer.deallocate() }

        CC_SHA224(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return SHA224Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

public struct SHA256Digest: Digest {
    public static var byteCount: Int { return Int(CC_SHA256_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard SHA256Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct SHA256: HashFunction {
    public typealias Digest = SHA256Digest

    private let context = Shared(UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1))

    public init() {
        CC_SHA256_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA256_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> SHA256Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA256Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_SHA256_Final(buffer.baseAddress, context)
        return SHA256Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> SHA256Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA256Digest.byteCount)
        defer { buffer.deallocate() }

        CC_SHA256(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return SHA256Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

public struct SHA384Digest: Digest {
    public static var byteCount: Int { return Int(CC_SHA384_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard SHA384Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct SHA384: HashFunction {
    public typealias Digest = SHA384Digest

    private let context = Shared(UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1))

    public init() {
        CC_SHA384_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA384_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> SHA384Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA384Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_SHA384_Final(buffer.baseAddress, context)
        return SHA384Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> SHA384Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA384Digest.byteCount)
        defer { buffer.deallocate() }

        CC_SHA384(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return SHA384Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

public struct SHA512Digest: Digest {
    public static var byteCount: Int { return Int(CC_SHA512_DIGEST_LENGTH) }

    private let buffer: Shared<UnsafeRawBufferPointer>

    public init?(bufferPointer: UnsafeRawBufferPointer) {
        guard SHA512Digest.byteCount == bufferPointer.count else { return nil }
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: bufferPointer.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        buffer.copyMemory(from: bufferPointer)
        self.buffer = Shared(UnsafeRawBufferPointer(buffer))
    }

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try buffer.pointer.withUnsafeBytes(body)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: buffer.pointer)
    }
}

public struct SHA512: HashFunction {
    public typealias Digest = SHA512Digest

    private let context = Shared(UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1))

    public init() {
        CC_SHA512_Init(context.pointer)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA512_Update(context.pointer, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public func finalize() -> SHA512Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA512Digest.byteCount)
        defer { buffer.deallocate() }

        let context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)
        context.assign(from: self.context.pointer, count: 1)
        defer { context.deallocate() }

        CC_SHA512_Final(buffer.baseAddress, context)
        return SHA512Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> SHA512Digest {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SHA512Digest.byteCount)
        defer { buffer.deallocate() }

        CC_SHA512(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), buffer.baseAddress)
        return SHA512Digest(bufferPointer: UnsafeRawBufferPointer(buffer))!
    }

}

