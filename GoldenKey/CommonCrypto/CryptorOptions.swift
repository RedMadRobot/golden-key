//
//  CryptorOptions.swift
//  GoldenKey
//
//  Created by Anton Glezman on 29/04/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation
import CommonCrypto.CommonCryptor

public struct CryptorOptions {
    
    public enum BlockMode {
        /// Cipher Block Chaining.
        /// - iv: Initialization Vector. Must be the same length as the AES algorithm block size, 128 bits (16  bytes).
        /// If CBC mode is selected and no IV is present, a NULL (all zeroes) IV will be used.
        case cbc(iv: Data?)
        
        /// Electronic Codebook.
        /// Not recommended for use because ECB has known cryptography weakness.
        case ecb
    }
    
    public enum Padding {
        /// PKCS#7 padding algorithm.
        case pkcs7
        
        /// In this case, the message length must be multiple of the block size.
        /// You can padded message manually before encryption.
        case noPadding
    }
    
    
    // MARK: - Public properties
    
    public let blockMode: BlockMode
    public let padding: Padding
    
    public var iv: Data? {
        switch blockMode {
        case .cbc(let iv):
            return iv
        case .ecb:
            return nil
        }
    }
    
    
    // MARK: - Init
    
    public init(blockMode: BlockMode, padding: Padding = .pkcs7) {
        self.blockMode = blockMode
        self.padding = padding
    }
    
    
    // MARK: - Internal properties
    
    internal var rawValue: CCOptions {
        // Default is CBC mode and no padding
        var options: CCOptions = 0
        switch blockMode {
        case .ecb:
            options |= CCOptions(kCCOptionECBMode)
        case .cbc:
            break
        }
        
        switch padding {
        case .pkcs7:
            options |= CCOptions(kCCOptionPKCS7Padding)
        case .noPadding:
            break
        }
        return options
    }
    
}
