//
//  DigestTests.swift
//  GoldenKeyTests
//
//  Created by Alexander Ignatev on 24/09/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import XCTest
import GoldenKey

final class DigestTests: XCTestCase {

    private final class Message {
        let string: String
        let count: Int

        private(set) lazy var chunk = Data(string.utf8)
        private(set) lazy var data = Data(Array(repeating: chunk, count: count).joined())

        init(string: String, count: Int = 1) {
            self.string = string
            self.count = count
        }
    }

    func testAbc() {
        let input = Message(string: "abc")

        assert(input, MD2(), "da853b0d 3f88d99b 30283a69 e6ded6bb")
        assert(input, MD4(), "a448017a af21d852 5fc10ae8 7aa6729d")
        assert(input, MD5(), "90015098 3cd24fb0 d6963f7d 28e17f72")
        assert(input, SHA1(), "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d")
        assert(input, SHA224(), "23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7")
        assert(input, SHA256(), "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad")
        assert(input, SHA384(), "cb00753f 45a35e8b b5a03d69 9ac65007 272c32ab 0eded163 1a8b605a 43ff5bed 8086072b a1e7cc23 58baeca1 34c825a7")
        assert(input, SHA512(), "ddaf35a1 93617aba cc417349 ae204131 12e6fa4e 89a97ea2 0a9eeee6 4b55d39a 2192992a 274fc1a8 36ba3c23 a3feebbd 454d4423 643ce80e 2a9ac94f a54ca49f")
    }

    func testEmpty() {
        let input = Message(string: "")

        assert(input, MD2(), "8350e5a3 e24c153d f2275c9f 80692773")
        assert(input, MD4(), "31d6cfe0 d16ae931 b73c59d7 e0c089c0")
        assert(input, MD5(), "d41d8cd9 8f00b204 e9800998 ecf8427e")
        assert(input, SHA1(), "da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709")
        assert(input, SHA224(), "d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f")
        assert(input, SHA256(), "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855")
        assert(input, SHA384(), "38b060a7 51ac9638 4cd9327e b1b1e36a 21fdb711 14be0743 4c0cc7bf 63f6e1da 274edebf e76f65fb d51ad2f1 4898b95b")
        assert(input, SHA512(), "cf83e135 7eefb8bd f1542850 d66d8007 d620e405 0b5715dc 83f4a921 d36ce9ce 47d0d13c 5d85f2b0 ff8318d2 877eec2f 63b931bd 47417a81 a538327a f927da3e")
    }

    func testMessage448() {
        let input = Message(string: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")

        assert(input, MD2(), "0dff6b39 8ad5a62a c8d97566 b80c3a7f")
        assert(input, MD4(), "4691a9ec 81b1a6bd 1ab85572 40b245c5")
        assert(input, MD5(), "8215ef07 96a20bca aae116d3 876c664a")
        assert(input, SHA1(), "84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1")
        assert(input, SHA224(), "75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525")
        assert(input, SHA256(), "248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1")
        assert(input, SHA384(), "3391fddd fc8dc739 3707a65b 1b470939 7cf8b1d1 62af05ab fe8f450d e5f36bc6 b0455a85 20bc4e6f 5fe95b1f e3c8452b")
        assert(input, SHA512(), "204a8fc6 dda82f0a 0ced7beb 8e08a416 57c16ef4 68b228a8 279be331 a703c335 96fd15c1 3b1b07f9 aa1d3bea 57789ca0 31ad85c7 a71dd703 54ec6312 38ca3445")
    }

    func testMessage896() {
        let input = Message(string: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")

        assert(input, MD2(), "2c194d03 76411dc0 b8485d3a be2a4b6b")
        assert(input, MD4(), "2102d1d9 4bd58ebf 5aa25c30 5bb783ad")
        assert(input, MD5(), "03dd8807 a93175fb 062dfb55 dc7d359c")
        assert(input, SHA1(), "a49b2446 a02c645b f419f995 b6709125 3a04a259")
        assert(input, SHA224(), "c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab 14e6b8df 265fc0b3")
        assert(input, SHA256(), "cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1")
        assert(input, SHA384(), "09330c33 f71147e8 3d192fc7 82cd1b47 53111b17 3b3b05d2 2fa08086 e3b0f712 fcc7c71a 557e2db9 66c3e9fa 91746039")
        assert(input, SHA512(), "8e959b75 dae313da 8cf4f728 14fc143f 8f7779c6 eb9f7fa1 7299aead b6889018 501d289e 4900f7e4 331b99de c4b5433a c7d329ee b6dd2654 5e96e55b 874be909")
    }

    func testMessageOneMillionA() {
        let input = Message(string: "a", count: 1_000_000)

        assert(input, MD2(), "8c0a09ff 1216ecaf 95c81309 53c62efd")
        assert(input, MD4(), "bbce80cc 6bb65e5c 6745e30d 4eeca9a4")
        assert(input, MD5(), "7707d6ae 4e027c70 eea2a935 c2296f21")
        assert(input, SHA1(), "34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f")
        assert(input, SHA224(), "20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67")
        assert(input, SHA256(), "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0")
        assert(input, SHA384(), "9d0e1809 716474cb 086e834e 310a4a1c ed149e9c 00f24852 7972cec5 704c2a5b 07b8b3dc 38ecc4eb ae97ddd8 7f3d8985")
        assert(input, SHA512(), "e718483d 0ce76964 4e2e42c7 bc15b463 8e1f98b1 3b204428 5632a803 afa973eb de0ff244 877ea60a 4cb0432c e577c31b eb009c5c 2c49aa2e 4eadb217 ad8cc09b")
    }

    func _testExtremelyLong() {
        let input = Message(string: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", count: 16_777_216)

        assert(input, SHA1(), "7789f0c9 ef7bfc40 d9331114 3dfbe69e 2017f592")
        assert(input, SHA224(), "b5989713 ca4fe47a 009f8621 980b34e6 d63ed306 3b2a0a2c 867d8a85")
        assert(input, SHA256(), "50e72a0e 26442fe2 552dc393 8ac58658 228c0cbf b1d2ca87 2ae43526 6fcd055e")
        assert(input, SHA384(), "5441235c c0235341 ed806a64 fb354742 b5e5c02a 3c5cb71b 5f63fb79 3458d8fd ae599c8c d8884943 c04f11b3 1b89f023")
        assert(input, SHA512(), "b47c9334 21ea2db1 49ad6e10 fce6c7f9 3d075238 0180ffd7 f4629a71 2134831d 77be6091 b819ed35 2c2967a2 e2d4fa50 50723c96 30691f1a 05a7281d be6c1086")
    }

    private func hex(data: Data) -> String {
        var result: [String] = []
        var start = data.startIndex
        while let end = data.index(start, offsetBy: 4, limitedBy: data.endIndex) {
            let chunk = data[start..<end].map { String(format: "%02x", $0) }.joined()
            result.append(chunk)
            start = end
        }
        return result.joined(separator: " ")
    }

    private func assert(_ input: Message, _ hasher: Digest, _ output: String, file: StaticString = #file, line: UInt = #line) {
        do {
            let string = hex(data: type(of: hasher).hash(data: input.data))
            XCTAssertEqual(string, output, "One shot \(hasher)", file: file, line: line)
        }
        for _ in 0..<input.count {
            hasher.update(data: input.chunk)
        }
        let string = hex(data: hasher.finalize())
        XCTAssertEqual(string, output, "Stream \(hasher)", file: file, line: line)
    }
}
