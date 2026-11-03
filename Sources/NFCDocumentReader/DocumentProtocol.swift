//
//  DocumentProtocol.swift
//  NFCDocumentReader
//
//  Created by Phineas Guo on 2026/11/3.
//

import Foundation

nonisolated enum DocumentProtocolError: Error, Equatable, LocalizedError {
    case invalidHex
    case malformedTLV
    case resourceLimit
    case invalidPersonalDetails
    case invalidNameEncoding
    case cardStatus(UInt8, UInt8)
    case unexpectedResponseLength

    var errorDescription: String? {
        switch self {
        case .invalidHex: String(localized: "The command contains invalid hexadecimal data.", bundle: .module)
        case .malformedTLV: String(localized: "The document data is incomplete or has an invalid length.", bundle: .module)
        case .resourceLimit: String(localized: "The document data exceeds the parser limits.", bundle: .module)
        case .invalidPersonalDetails: String(localized: "The personal-details data is not valid plaintext.", bundle: .module)
        case .invalidNameEncoding: String(localized: "The document name is not valid UTF-8.", bundle: .module)
        case let .cardStatus(sw1, sw2):
            String(localized: "The document rejected the command (status \(String(format: "%02X%02X", sw1, sw2))).", bundle: .module)
        case .unexpectedResponseLength: String(localized: "The document returned an unexpected response length.", bundle: .module)
        }
    }
}

nonisolated public enum HexCodec {
    public static func encode(_ data: Data) -> String {
        data.map { String(format: "%02X", $0) }.joined()
    }

    public static func decode(_ string: String) throws -> Data {
        let characters = Array(string.utf8)
        guard characters.count.isMultiple(of: 2) else { throw DocumentProtocolError.invalidHex }
        var bytes = [UInt8]()
        bytes.reserveCapacity(characters.count / 2)
        for index in stride(from: 0, to: characters.count, by: 2) {
            guard let high = nibble(characters[index]), let low = nibble(characters[index + 1]) else {
                throw DocumentProtocolError.invalidHex
            }
            bytes.append(high << 4 | low)
        }
        return Data(bytes)
    }

    private static func nibble(_ character: UInt8) -> UInt8? {
        switch character {
        case 48...57: character - 48
        case 65...70: character - 65 + 10
        case 97...102: character - 97 + 10
        default: nil
        }
    }
}

nonisolated struct APDUResponse: Equatable, Sendable {
    let data: Data
    let sw1: UInt8
    let sw2: UInt8

    var statusWord: String { String(format: "%02X%02X", sw1, sw2) }

    func requireSuccess() throws {
        guard sw1 == 0x90, sw2 == 0 else {
            throw DocumentProtocolError.cardStatus(sw1, sw2)
        }
    }
}

nonisolated public struct ISO7816TagDetails: Equatable, Sendable {
    public let identifier: Data
    public let selectedApplication: String
    public let historicalBytes: Data?
    public let applicationData: Data?
    public let proprietaryApplicationDataCoding: Bool
}

nonisolated public struct ResidentCardData: Equatable, Sendable {
    public let rawResponse: Data

    public init(rawResponse: Data) throws {
        guard rawResponse.count >= 32 else { throw DocumentProtocolError.unexpectedResponseLength }
        self.rawResponse = rawResponse
    }

}

/// Reads the resident-card serial response and management number.
nonisolated enum ResidentCardReadStep: String, CaseIterable, Sendable {
    case selectFile
    case readSn
    case readDn

    var title: String {
        switch self {
        case .selectFile: String(localized: "Select file 6002", bundle: .module)
        case .readSn: String(localized: "Read SN response", bundle: .module)
        case .readDn: String(localized: "Read mgmt_number response", bundle: .module)
        }
    }

    var command: String {
        switch self {
        case .selectFile: "00A40000026002"
        case .readSn: "0036000008"
        case .readDn: "80B0000020"
        }
    }

    func validate(_ response: APDUResponse) throws {
        try response.requireSuccess()
        if self == .readDn, response.data.count < 32 {
            throw DocumentProtocolError.unexpectedResponseLength
        }
    }
}

nonisolated struct BERTLV: Equatable, Sendable {
    let tag: UInt32
    let value: Data
    let children: [BERTLV]

    /// Definite lengths only, with explicit limits for untrusted card data.
    static func parse(_ data: Data) throws -> [BERTLV] {
        guard data.count <= 65_536 else { throw DocumentProtocolError.resourceLimit }
        let bytes = Array(data)
        var budget = 4_096
        return try parse(bytes, range: 0..<bytes.count, depth: 0, budget: &budget)
    }

    private static func parse(
        _ bytes: [UInt8], range: Range<Int>, depth: Int, budget: inout Int
    ) throws -> [BERTLV] {
        guard depth <= 8 else { throw DocumentProtocolError.resourceLimit }
        var offset = range.lowerBound
        var nodes = [BERTLV]()
        while offset < range.upperBound {
            guard budget > 0 else { throw DocumentProtocolError.resourceLimit }
            budget -= 1
            let first = bytes[offset]
            offset += 1
            guard first != 0, first != 0xFF else { throw DocumentProtocolError.malformedTLV }
            var tag = UInt32(first)
            if first & 0x1F == 0x1F {
                var tagBytes = 1
                while true {
                    guard offset < range.upperBound, tagBytes < 4 else {
                        throw DocumentProtocolError.malformedTLV
                    }
                    let next = bytes[offset]
                    guard tagBytes != 1 || next & 0x7F != 0 else {
                        throw DocumentProtocolError.malformedTLV
                    }
                    offset += 1
                    tagBytes += 1
                    tag = tag << 8 | UInt32(next)
                    if next & 0x80 == 0 { break }
                }
            }
            guard offset < range.upperBound else { throw DocumentProtocolError.malformedTLV }
            let lengthByte = bytes[offset]
            offset += 1
            var length = Int(lengthByte)
            if lengthByte & 0x80 != 0 {
                let count = Int(lengthByte & 0x7F)
                guard count > 0, count <= 4, count <= range.upperBound - offset else {
                    throw DocumentProtocolError.malformedTLV
                }
                length = 0
                for _ in 0..<count {
                    length = length << 8 | Int(bytes[offset])
                    offset += 1
                }
            }
            guard length <= range.upperBound - offset else { throw DocumentProtocolError.malformedTLV }
            let valueRange = offset..<(offset + length)
            let children = first & 0x20 != 0
                ? try parse(bytes, range: valueRange, depth: depth + 1, budget: &budget)
                : []
            nodes.append(BERTLV(tag: tag, value: Data(bytes[valueRange]), children: children))
            offset += length
        }
        return nodes
    }
}

nonisolated enum PersonalDetailsParser {
    /// Input must already be decrypted and authenticated by secure messaging.
    /// Secure messaging must authenticate and decrypt the response before calling this parser.
    static func fullName(fromPlaintext data: Data) throws -> String? {
        let groups = try BERTLV.parse(data)
        guard groups.count == 1, let group = groups.first, group.tag == 0x6B else {
            throw DocumentProtocolError.invalidPersonalDetails
        }
        guard let nameData = findName(in: group.children) else { return nil }
        guard let name = String(data: nameData, encoding: .utf8) else {
            throw DocumentProtocolError.invalidNameEncoding
        }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func findName(in nodes: [BERTLV]) -> Data? {
        for node in nodes {
            if node.tag == 0x5F0E { return node.value }
            if let name = findName(in: node.children) { return name }
        }
        return nil
    }
}
