//
//  CommonDigest.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 02/01/2019.
//  Copyright © 2019 Alexander Ignition. All rights reserved.
//

import Foundation

/// A type that represents the output of a hash.
public protocol Digest: ContiguousBytes, CustomStringConvertible, Hashable, Sequence where Self.Element == UInt8 {

    /// The number of bytes in the digest.
    static var byteCount: Int { get }
}

extension Digest {

    public func makeIterator() -> Array<UInt8>.Iterator {
        return withUnsafeBytes { Array($0).makeIterator() }
    }
}

extension Digest {

    public static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.hashValue == rhs.hashValue
    }

    public static func == (lhs: Self, rhs: ContiguousBytes) -> Bool {
        return lhs.hashValue == rhs.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int in
            var hasher = Hasher()
            hasher.combine(bytes: bytes)
            return hasher.finalize()
        }
    }

    public var description: String {
        let bytes = map { "\($0)" }.joined(separator: "")
        return "\(Self.self) \(bytes)"
    }
}
