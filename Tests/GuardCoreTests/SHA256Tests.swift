import Testing
@testable import GuardCore

@Suite struct SHA256Tests {
    @Test func emptyInput() {
        #expect(SHA256.hex(of: []) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test func abc() {
        #expect(SHA256.hex(of: Array("abc".utf8)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test func twoBlockMessage() {
        let input = Array("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)
        #expect(SHA256.hex(of: input) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    @Test func oneMillionA() {
        let input = [UInt8](repeating: UInt8(ascii: "a"), count: 1_000_000)
        #expect(SHA256.hex(of: input) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    @Test func stringConvenienceUsesUTF8() {
        #expect(SHA256.hex(of: "abc") == SHA256.hex(of: Array("abc".utf8)))
    }
}
