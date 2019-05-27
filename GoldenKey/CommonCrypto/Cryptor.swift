//
//  Cryptor.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation
import CommonCrypto.CommonCryptor

/// Generic class for symmetric encryption.
public final class Cryptor {

    /// Operations that an `Cryptor` can perform.
    ///
    /// - encrypt: Symmetric encryption.
    /// - decrypt: Symmetric decryption.
    public enum Operation {
        case encrypt
        case decrypt

        var rawValue: CCOperation {
            switch self {
            case .encrypt:
                return CCOperation(kCCEncrypt)
            case .decrypt:
                return CCOperation(kCCDecrypt)
            }
        }
    }


    /// Basic operation.
    public let operation: Operation

    /// Encryption algorithm.
    public let algorithm: CryptorAlgorithm

    /// Options flags.
    public let options: CryptorOptions

    /// Opaque reference to a CCCryptor object.
    private var cryptor: CCCryptorRef?
 
    /// Create a symmetric cryptor.
    ///
    /// - Parameters:
    ///   - operation: Basic operation.
    ///   - algorithm: Encryption algorithm.
    ///   - options: A struct of flags defining options.
    ///   - key: Symmetric encryption key.
    ///
    /// - Throws: `CryptorError`.
    public init(
        operation: Operation,
        algorithm: CryptorAlgorithm,
        options: CryptorOptions,
        key: Data
    ) throws {

        try algorithm.validate(key: key)
        self.operation = operation
        self.algorithm = algorithm
        self.options = options
        var initializationVector: Data
        if case .cbc(let cbcIv) = options.blockMode, let iv = cbcIv {
            try algorithm.validate(iv: iv)
            initializationVector = iv
        } else {
            // If CBC mode is selected (by the absence of any mode bits in the options flags) and no IV is present,
            // a NULL (all zeroes) IV will be used.
            let zeroBytes = [UInt8](repeating: 0, count: algorithm.blockSize)
            initializationVector = Data(bytes: zeroBytes, count: algorithm.blockSize)
        }

        let status: CCCryptorStatus = key.withUnsafeBytes { (keyBuffer: UnsafeRawBufferPointer) -> CCCryptorStatus in
            initializationVector.withUnsafeBytes { (ivBuffer: UnsafeRawBufferPointer) -> CCCryptorStatus in
                return CCCryptorCreate(
                    operation.rawValue,
                    algorithm.rawValue,
                    options.rawValue,
                    keyBuffer.baseAddress,
                    key.count,
                    ivBuffer.baseAddress,
                    &cryptor)
            }
        }
        try CryptorError.verify(status)
    }

    deinit {
        guard let cryptor = cryptor else { return }
        let status = CCCryptorRelease(cryptor)
        do {
            try CryptorError.verify(status)
        } catch {
            assertionFailure("\(error)")
        }
    }

    /// Process (encrypt, decrypt) some data.
    ///
    /// - Parameter data: Data to process.
    /// - Returns: Processed data.
    /// - Throws: `CryptorError`.
    @discardableResult
    public func process(_ data: Data) throws -> Data {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: outputLength(for: data.count, final: false))

        let status: CCCryptorStatus = data.withUnsafeBytes {
            CCCryptorUpdate(cryptor, $0.baseAddress, data.count, &outBytes, outBytes.count, &outLength)
        }
        try CryptorError.verify(status)

        return Data(outBytes[..<outLength])
    }

    /// Finish an encrypt or decrypt operation, and obtain the (possible) final data output.
    ///
    /// - Returns: final data output.
    /// - Throws: `CryptorError`.
    public func finalize() throws -> Data {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: outputLength(for: 0, final: true))

        let status = CCCryptorFinal(cryptor, &outBytes, outBytes.count, &outLength)
        try CryptorError.verify(status)

        return Data(outBytes[..<outLength])
    }

    /// Determine output buffer size required to process a given input size.
    ///
    /// - Parameters:
    ///   - inputLength: The length of data which will be provided to `CCCryptorUpdate()`.
    ///   - final: If false, the returned value will indicate the output buffer space needed when 'inputLength'
    ///            bytes are provided to `CCCryptorUpdate()`. When 'final' is true, the returned value will indicate
    ///            the total combined buffer space needed when 'inputLength' bytes are provided to `CCCryptorUpdate()`
    ///            and then CCCryptorFinal() is called.
    /// - Returns: The maximum buffer space need to perform `CCCryptorUpdate()` and optionally `CCCryptorFinal()`.
    private func outputLength(for inputLength: Int, final: Bool) -> Int {
        return CCCryptorGetOutputLength(cryptor, inputLength, final)
    }

    /// Reset an existing `Cryptor` with a (possibly) new initialization vector.
    /// The Cryptor's key is unchanged.
    ///
    /// - Precondition: Use only for CBC mode.
    /// - Parameter iv: Optional initialization vector;
    ///                 if present, must be the same size as the current algorithm's block size.
    ///                 For sound encryption, always initialize iv with random data.
    /// - Throws: `CryptorError`.
    public func reset(iv: Data? = nil) throws {
        var vector = iv
        let status = CCCryptorReset(cryptor, &vector)
        try CryptorError.verify(status)
    }

    /// Stateless, one-shot encrypt operation.
    ///
    /// - Parameters:
    ///   - algorithm: Encryption algorithm.
    ///   - options: A word of flags defining options.
    ///   - key: Symmetric encryption key.
    ///   - data: Data to encrypt or decrypt.
    ///   - iv: Initialization vector, optional.
    /// - Returns: Result data.
    /// - Throws: `CryptorError`.
    public static func encrypt(
        algorithm: CryptorAlgorithm,
        options: CryptorOptions,
        key: Data,
        data: Data
        ) throws -> Data {
        return try crypt(.encrypt, algorithm: algorithm, options: options, key: key, data: data)
    }
    
    /// Stateless, one-shot decrypt operation.
    ///
    /// - Parameters:
    ///   - algorithm: Encryption algorithm.
    ///   - options: A word of flags defining options.
    ///   - key: Symmetric encryption key.
    ///   - data: Data to encrypt or decrypt.
    ///   - iv: Initialization vector, optional.
    /// - Returns: Result data.
    /// - Throws: `CryptorError`.
    public static func decrypt(
        algorithm: CryptorAlgorithm,
        options: CryptorOptions,
        key: Data,
        data: Data
        ) throws -> Data {
        return try crypt(.decrypt, algorithm: algorithm, options: options, key: key, data: data)
    }
    
    /// Stateless, one-shot encrypt or decrypt operation.
    ///
    /// - Parameters:
    ///   - operation: Basic operation.
    ///   - algorithm: Encryption algorithm.
    ///   - options: A word of flags defining options.
    ///   - key: Symmetric encryption key.
    ///   - data: Data to encrypt or decrypt.
    ///   - iv: Initialization vector, optional.
    /// - Returns: Result data.
    /// - Throws: `CryptorError`.
    internal static func crypt(
        _ operation: Operation,
        algorithm: CryptorAlgorithm,
        options: CryptorOptions,
        key: Data,
        data: Data
    ) throws -> Data {
        
        try algorithm.validate(key: key)
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: data.count + algorithm.blockSize)
        var initializationVector: Data
        if case .cbc(let cbcIv) = options.blockMode, let iv = cbcIv {
            try algorithm.validate(iv: iv)
            initializationVector = iv
        } else {
            // If CBC mode is selected (by the absence of any mode bits in the options flags) and no IV is present,
            // a NULL (all zeroes) IV will be used.
            let zeroBytes = [UInt8](repeating: 0, count: algorithm.blockSize)
            initializationVector = Data(bytes: zeroBytes, count: algorithm.blockSize)
        }

        let status: CCCryptorStatus = data.withUnsafeBytes { (inputBuffer: UnsafeRawBufferPointer) -> CCCryptorStatus in
            return key.withUnsafeBytes { (keyBuffer: UnsafeRawBufferPointer) -> CCCryptorStatus in
                return initializationVector.withUnsafeBytes { (ivBuffer: UnsafeRawBufferPointer) -> CCCryptorStatus in
                    return CCCrypt(
                        operation.rawValue, algorithm.rawValue, options.rawValue,
                        keyBuffer.baseAddress,
                        key.count,
                        ivBuffer.baseAddress,
                        inputBuffer.baseAddress,
                        data.count,
                        &outBytes, outBytes.count, &outLength)
                }
            }
        }
        try CryptorError.verify(status)

        return Data(outBytes[..<outLength])
    }
}
