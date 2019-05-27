//
//  SecurityError.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation

/// Security Error.
///
/// - SeeAlso: SecBase.h
public struct SecurityError: Error, RawRepresentable, Hashable {

    /// Security Error Code.
    public let rawValue: OSStatus

    /// Create Security Error.
    ///
    /// - Parameter rawValue: Raw security error code.
    public init(rawValue: OSStatus) {
        self.rawValue = rawValue
    }

    static func verify(_ status: OSStatus) throws {
        if status == errSecSuccess { return }
        throw SecurityError(rawValue: status)
    }
}

extension SecurityError: LocalizedError {

    /// A human-readable string describing the error.
    public var errorDescription: String? {
        if #available(iOS 11.3, watchOSApplicationExtension 4.3, tvOS 11.3, *) {
            return SecCopyErrorMessageString(rawValue, nil) as String?
        } else {
            return "OSStatus: \(rawValue)"
        }
    }
}

extension SecurityError: CustomNSError {

    /// The domain of the error.
    public static var errorDomain = NSOSStatusErrorDomain

    /// The error code within the given domain.
    public var errorCode: Int { return Int(rawValue) }

    /// The user-info dictionary.
    public var errorUserInfo: [String: Any] {
        var userInfo: [String: Any] = [:]
        userInfo[NSLocalizedDescriptionKey] = errorDescription
        return userInfo
    }
}
