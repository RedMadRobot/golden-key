//
//  HashFunction.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 07/06/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation

/// A type that performs cryptographically secure hashing.
///
/// https://developer.apple.com/documentation/cryptokit/hashfunction
public protocol HashFunction {

    /// The type of the digest returned by the hash function.
    associatedtype Digest: GoldenKey.Digest

    /// Computes the digest of the bytes in the buffer and returns the computed digest.
    ///
    /// - Parameter bufferPointer: A pointer to the bytes whose digest the hash function should compute.
    /// - Returns: The computed digest of the data.
    static func hash(bufferPointer: UnsafeRawBufferPointer) -> Digest

    /// Creates a hash function.
    init()

    /// Incrementally updates the hash function with the contents of the buffer.
    ///
    /// - Note: Typically, it’s safer to use an instance of Data, or some other type that conforms
    ///   to the `DataProtocol`, to hold your data. When possible, use the `update(data:)` method instead.
    /// - Parameter bufferPointer: A pointer to the next block of data for the ongoing digest calculation.
    mutating func update(bufferPointer: UnsafeRawBufferPointer)

    /// Finalizes the hash function and returns the computed digest.
    ///
    /// - Returns: The computed digest of the data.
    func finalize() -> Digest
}

extension HashFunction {

    /// Computes the digest of the bytes in the given data instance and returns the computed digest.
    ///
    /// - Parameter data: The data whose digest the hash function should compute.
    ///   This can be any type that conforms to DataProtocol, like Data or an array of UInt8 instances.
    /// - Returns: The computed digest of the data.
    @inlinable public static func hash<D>(data: D) -> Digest where D : DataProtocol {
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: data.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        defer {
            buffer.deallocate()
        }
        data.copyBytes(to: buffer)
        return buffer.withUnsafeBytes { hash(bufferPointer: $0) }
    }

    /// Incrementally updates the hash function with the given data.
    ///
    /// - Parameter data: The next block of data for the ongoing digest calculation. You can provide
    ///   this as any type that conforms to DataProtocol, like Data or an array of UInt8 instances.
    @inlinable public mutating func update<D>(data: D) where D : DataProtocol {
        for region in data.regions {
            region.withUnsafeBytes { update(bufferPointer: $0) }
        }
    }

}
