//
//  DocumentProtocolTests.swift
//  NFCDocumentReader
//
//  Created by Phineas Guo on 2026/11/3.
//

import Foundation
import XCTest
@testable import NFCDocumentReader

@MainActor
struct DocumentProtocolTests {
    static var checks = 0

    static func main() throws {
        let rawDN = Data((0..<32).map { UInt8($0) })
        let card = try ResidentCardData(rawResponse: rawDN)
        try expect(card.rawResponse == rawDN, "Preserve complete raw mgmt_number response")
        try expect(card.dn == Data((0..<16).map { UInt8($0) }), "mgmt_number is exactly the first 16 raw bytes")
        for count in 0..<32 {
            try expectError(.unexpectedResponseLength) {
                _ = try ResidentCardData(rawResponse: Data(repeating: 0, count: count))
            }
        }
        let extended = try ResidentCardData(rawResponse: rawDN + Data([0xAA]))
        try expect(extended.rawResponse.count == 33 && extended.dn == card.dn, "Longer responses are preserved without changing the mgmt_number prefix")

        try expect(HexCodec.decode("00a4FF") == Data([0, 0xA4, 0xFF]), "Hexadecimal decoding")
        try expect(HexCodec.encode(Data([0, 0xA4, 0xFF])) == "00A4FF", "Lossless hexadecimal display")
        try expectError(.invalidHex) { _ = try HexCodec.decode("ABC") }
        try expectError(.invalidHex) { _ = try HexCodec.decode("GG") }

        try APDUResponse(data: Data(), sw1: 0x90, sw2: 0).requireSuccess()
        try expectError(.cardStatus(0x90, 1)) {
            try APDUResponse(data: Data(), sw1: 0x90, sw2: 1).requireSuccess()
        }
        try expectError(.cardStatus(0x69, 0x82)) {
            try APDUResponse(data: Data(), sw1: 0x69, sw2: 0x82).requireSuccess()
        }
        let commands = try ResidentCardReadStep.allCases.map { try HexCodec.decode($0.command) }
        try expect(commands == [
            Data([0, 0xA4, 0, 0, 2, 0x60, 2]),
            Data([0, 0x36, 0, 0, 8]),
            Data([0x80, 0xB0, 0, 0, 0x20])
        ], "Resident-card command bytes and execution order")
        for step in ResidentCardReadStep.allCases {
            try expectError(.cardStatus(0x90, 1)) {
                try step.validate(APDUResponse(data: Data(repeating: 0, count: 32), sw1: 0x90, sw2: 1))
            }
        }
        try ResidentCardReadStep.readSn.validate(APDUResponse(data: Data(), sw1: 0x90, sw2: 0))
        for length in 0..<32 {
            try expectError(.unexpectedResponseLength) {
                try ResidentCardReadStep.readDn.validate(APDUResponse(data: Data(repeating: 0, count: length), sw1: 0x90, sw2: 0))
            }
        }
        try ResidentCardReadStep.readDn.validate(APDUResponse(data: Data(repeating: 0, count: 32), sw1: 0x90, sw2: 0))
        try ResidentCardReadStep.readDn.validate(APDUResponse(data: Data(repeating: 0, count: 33), sw1: 0x90, sw2: 0))

        let fixture = tlv([0x6B], tlv([0x5C], Data([0x5F, 0x0E])) + tlv([0x5F, 0x0E], Data("  测试姓名\n".utf8)))
        try expect(PersonalDetailsParser.fullName(fromPlaintext: fixture) == "测试姓名", "UTF-8 name and trimming")
        try expect(PersonalDetailsParser.fullName(fromPlaintext: Data([0x6B, 0])) == nil, "Missing name")
        let nested = tlv([0x6B], tlv([0xA0], tlv([0x5F, 0x0E], Data("Example".utf8))))
        try expect(PersonalDetailsParser.fullName(fromPlaintext: nested) == "Example", "Constructed TLV")
        let longName = String(repeating: "A", count: 200)
        let longFixture = tlv([0x6B], tlv([0x5F, 0x0E], Data(longName.utf8)))
        try expect(PersonalDetailsParser.fullName(fromPlaintext: longFixture) == longName, "Long-form length")
        try expectError(.invalidNameEncoding) {
            _ = try PersonalDetailsParser.fullName(fromPlaintext: tlv([0x6B], tlv([0x5F, 0x0E], Data([0xFF]))))
        }
        try expectError(.invalidPersonalDetails) {
            _ = try PersonalDetailsParser.fullName(fromPlaintext: Data([0x87, 1, 0]))
        }
        try expectError(.invalidPersonalDetails) {
            _ = try PersonalDetailsParser.fullName(fromPlaintext: fixture + Data([0x01, 0]))
        }

        for length in 0..<fixture.count {
            do {
                _ = try PersonalDetailsParser.fullName(fromPlaintext: Data(fixture.prefix(length)))
                throw Failure(description: "Truncated personal details was accepted at length \(length)")
            } catch is DocumentProtocolError {
                checks += 1
            }
        }
        for hex in ["5F", "5F80", "0180", "01850100000000", "0182FF", "0184FFFFFFFF", "6B035F0E02"] {
            try expectError(.malformedTLV) { _ = try BERTLV.parse(HexCodec.decode(hex)) }
        }
        var deep = Data([0x01, 0])
        for _ in 0..<10 { deep = tlv([0xE1], deep) }
        try expectError(.resourceLimit) { _ = try BERTLV.parse(deep) }
        try expectError(.resourceLimit) { _ = try BERTLV.parse(Data(repeating: 0, count: 65_537)) }
        var many = Data()
        for _ in 0..<4_097 { many.append(contentsOf: [0x01, 0]) }
        try expectError(.resourceLimit) { _ = try BERTLV.parse(many) }

        // Exercise malformed byte streams deterministically; parsing must return or throw, never trap.
        var seed: UInt64 = 42
        for length in 0..<64 {
            for _ in 0..<16 {
                var bytes = [UInt8]()
                for _ in 0..<length {
                    seed = seed &* 6_364_136_223_846_793_005 &+ 1
                    bytes.append(UInt8(truncatingIfNeeded: seed >> 32))
                }
                do { _ = try BERTLV.parse(Data(bytes)) } catch is DocumentProtocolError {}
                checks += 1
            }
        }
        print("Passed \(checks) protocol checks.")
    }

    private static func tlv(_ tag: [UInt8], _ value: Data) -> Data {
        precondition(value.count < 256)
        let length: [UInt8] = value.count < 128 ? [UInt8(value.count)] : [0x81, UInt8(value.count)]
        return Data(tag + length) + value
    }

    private static func expect(_ condition: @autoclosure () throws -> Bool, _ description: String) throws {
        guard try condition() else { throw Failure(description: description) }
        checks += 1
    }

    private static func expectError(_ expected: DocumentProtocolError, _ operation: () throws -> Void) throws {
        do {
            try operation()
            throw Failure(description: "Expected \(expected)")
        } catch let error as DocumentProtocolError {
            guard error == expected else { throw Failure(description: "Expected \(expected), received \(error)") }
            checks += 1
        }
    }

    private struct Failure: Error {
        let description: String
    }
}

final class DocumentProtocolTestsSuite: XCTestCase {
    @MainActor func testProtocol() throws {
        try DocumentProtocolTests.main()
    }
}
