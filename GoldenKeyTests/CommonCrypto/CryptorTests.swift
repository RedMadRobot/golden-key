//
//  CryptorTests.swift
//  GoldenKeyTests
//
//  Created by Alexander Ignatev on 11/01/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import XCTest
import GoldenKey

final class CryptorTests: XCTestCase {

    func testCrypt() throws {
        do {
            let token = "user_token"
            let algorithm = CryptorAlgorithm.aes128
            let options = CryptorOptions(blockMode: .ecb)

            let pbkdf = PBKDF2(password: "1111", salt: Data("12345678".utf8))
            let key = try pbkdf.keyDerivation(.sha256, keyCount: algorithm.keySize, rounds: 1024)
            XCTAssertEqual(key.base64EncodedString(), "Hp+8lUfauUgxo4CGIa8PGw==")

            let encryptedToken = try Cryptor.encrypt(algorithm: algorithm, options: options, key: key, data: Data(token.utf8))
            let decryptedToken = try Cryptor.decrypt(algorithm: algorithm, options: options, key: key, data: encryptedToken)
            XCTAssertEqual(String(data: decryptedToken, encoding: .utf8), token)

            let cryptor = try Cryptor(operation: .encrypt, algorithm: algorithm, options: options, key: key)
            try cryptor.process(Data("user".utf8))
            try cryptor.process(Data("_token".utf8))
            let result = try cryptor.finalize()
            XCTAssertEqual(result, encryptedToken)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testEncrypt_AES256_CBC_PKCS7() {
        do {
            let openText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed " +
            "do eiusmod tempor incididunt ut labore et dolore magna aliqua"
            let key = Data(base64Encoded: "NqFOyr0w3T6I29eieqFh8aKxAu9PnrgYMKeiuVWRYyE=")!
            let iv = Data(base64Encoded: "ztwCgLfy5ADD1Lx+ovq09w==") // random generated

            let encryptedData = try Cryptor.encrypt(
                algorithm: .aes256,
                options: CryptorOptions(blockMode: .cbc(iv: iv)),
                key: key,
                data: Data(openText.utf8))

            let referenceEncryptedText = "bcq961xmUYsJoMVoJhi6NKasa8s/C0gRloefkxPpN86EwKAxsJgjjDtBLVdifiCj" +
                "zBWrkdBVIR+YvJLnKrXWzxdK61Q84bCWvmiCFAZ4YsWDFMZIyOtQwIxcl7aKLQzt" +
            "d7jTPqR/Q9LS7Q5M0iULQ2NqAW/UHRzFcZ11gV9GghY="
            let referenceEncryptedData = Data(base64Encoded: referenceEncryptedText)!

            XCTAssertEqual(encryptedData, referenceEncryptedData)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDecrypt_AES256_CBC_PKCS7() {
        do {
            let encryptedText = "bcq961xmUYsJoMVoJhi6NKasa8s/C0gRloefkxPpN86EwKAxsJgjjDtBLVdifiCj" +
                "zBWrkdBVIR+YvJLnKrXWzxdK61Q84bCWvmiCFAZ4YsWDFMZIyOtQwIxcl7aKLQzt" +
            "d7jTPqR/Q9LS7Q5M0iULQ2NqAW/UHRzFcZ11gV9GghY="
            let encryptedData = Data(base64Encoded: encryptedText)!
            let key = Data(base64Encoded: "NqFOyr0w3T6I29eieqFh8aKxAu9PnrgYMKeiuVWRYyE=")!
            let iv = Data(base64Encoded: "ztwCgLfy5ADD1Lx+ovq09w==")

            let decryptedData = try Cryptor.decrypt(
                algorithm: .aes256,
                options: CryptorOptions(blockMode: .cbc(iv: iv)),
                key: key,
                data: encryptedData)
            let openText = String(data: decryptedData, encoding: .utf8)

            let referenceOpenText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed " +
            "do eiusmod tempor incididunt ut labore et dolore magna aliqua"

            XCTAssertEqual(openText, referenceOpenText)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testEncrypt_AES256_ECB_PKCS7() {
        do {
            let openText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed " +
            "do eiusmod tempor incididunt ut labore et dolore magna aliqua"
            let key = Data(base64Encoded: "NqFOyr0w3T6I29eieqFh8aKxAu9PnrgYMKeiuVWRYyE=")!

            let encryptedData = try Cryptor.encrypt(
                algorithm: .aes256,
                options: CryptorOptions(blockMode: .ecb),
                key: key,
                data: Data(openText.utf8))

            let referenceEncryptedText = "djKuuzlvuHkMFupINpfKSCoJMiiskTadgcjdfVO+rTmmF3/Jo63VcbB3dFyo/gHJ" +
                "ZRb7lxlnnJj3tMo7HHhTlpeuBvlXM1m6tO4D2ozdR9L/Sp8RJvhdfJdyRS6DdFs1" +
            "uWQ9poL3HZIvUM7IQ9rHqjUiGy5e9VNQzWGle7uahFg="
            let referenceEncryptedData = Data(base64Encoded: referenceEncryptedText)!

            XCTAssertEqual(encryptedData, referenceEncryptedData)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testDecrypt_AES256_ECB_PKCS7() {
        do {
            let encryptedText = "djKuuzlvuHkMFupINpfKSCoJMiiskTadgcjdfVO+rTmmF3/Jo63VcbB3dFyo/gHJ" +
                "ZRb7lxlnnJj3tMo7HHhTlpeuBvlXM1m6tO4D2ozdR9L/Sp8RJvhdfJdyRS6DdFs1" +
            "uWQ9poL3HZIvUM7IQ9rHqjUiGy5e9VNQzWGle7uahFg="
            let encryptedData = Data(base64Encoded: encryptedText)!
            let key = Data(base64Encoded: "NqFOyr0w3T6I29eieqFh8aKxAu9PnrgYMKeiuVWRYyE=")!

            let decryptedData = try Cryptor.decrypt(
                algorithm: .aes256,
                options: CryptorOptions(blockMode: .ecb),
                key: key,
                data: encryptedData)
            let openText = String(data: decryptedData, encoding: .utf8)

            let referenceOpenText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed " +
            "do eiusmod tempor incididunt ut labore et dolore magna aliqua"

            XCTAssertEqual(openText, referenceOpenText)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

}
