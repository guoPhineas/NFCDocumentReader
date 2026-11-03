//
//  BACProtocol.swift
//  NFCDocumentReader
//
//  Created by Phineas Guo on 2026/11/3.
//

import CommonCrypto
import CryptoKit
import Foundation
import Security

nonisolated enum BACError: Error, LocalizedError {
    case invalidAccessKey, invalidResponse, authenticationFailed, invalidPadding
    case cryptographyFailed, randomFailed, counterExhausted, unsupportedMRZ

    var errorDescription: String? {
        switch self {
        case .invalidAccessKey: String(localized: "Enter a document number of up to nine MRZ characters and dates in YYMMDD format.", bundle: .module)
        case .invalidResponse: String(localized: "The document returned an incomplete or invalid protected response.", bundle: .module)
        case .authenticationFailed: String(localized: "Document authentication failed. Check the document number and dates.", bundle: .module)
        case .invalidPadding: String(localized: "The protected document response has invalid padding.", bundle: .module)
        case .cryptographyFailed: String(localized: "The document cryptographic operation failed.", bundle: .module)
        case .randomFailed: String(localized: "Secure random generation failed.", bundle: .module)
        case .counterExhausted: String(localized: "The secure messaging counter is exhausted. Scan again.", bundle: .module)
        case .unsupportedMRZ: String(localized: "This document's machine-readable format is not supported yet.", bundle: .module)
        }
    }
}

nonisolated public struct BACAccessKey: Equatable, Sendable {
    public let documentNumber: String
    public let birthDate: String
    public let expiryDate: String

    public init(documentNumber: String, birthDate: String, expiryDate: String) throws {
        let number = documentNumber.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard (1...9).contains(number.utf8.count),
              number.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || $0 == 60 }),
              number.utf8.contains(where: { $0 != 60 }),
              Self.validDate(birthDate), Self.validDate(expiryDate) else {
            throw BACError.invalidAccessKey
        }
        self.documentNumber = number
        self.birthDate = birthDate
        self.expiryDate = expiryDate
    }

    var mrzInformation: Data {
        let number = documentNumber + String(repeating: "<", count: 9 - documentNumber.utf8.count)
        return Data((number + String(Self.checkDigit(number))
                     + birthDate + String(Self.checkDigit(birthDate))
                     + expiryDate + String(Self.checkDigit(expiryDate))).utf8)
    }

    static func checkDigit(_ value: String) -> Int {
        let weights = [7, 3, 1]
        return value.utf8.enumerated().reduce(0) { total, item in
            let byte = item.element
            let digit = byte == 60 ? 0 : (byte >= 65 ? Int(byte - 55) : Int(byte - 48))
            return total + digit * weights[item.offset % 3]
        } % 10
    }

    static func validDate(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count == 6, bytes.allSatisfy({ (48...57).contains($0) }) else { return false }
        let year = Int(bytes[0] - 48) * 10 + Int(bytes[1] - 48)
        let month = Int(bytes[2] - 48) * 10 + Int(bytes[3] - 48)
        let day = Int(bytes[4] - 48) * 10 + Int(bytes[5] - 48)
        guard (1...12).contains(month) else { return false }
        let days = [31, year % 4 == 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        return (1...days[month - 1]).contains(day)
    }
}

nonisolated enum BACCrypto {
    static let zeroIV = Data(repeating: 0, count: 8)

    static func random(_ count: Int) throws -> Data {
        var result = Data(count: count)
        let status = result.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw BACError.randomFailed }
        return result
    }

    static func deriveKeys(seed: Data) -> (encryption: Data, mac: Data) {
        func derive(_ counter: UInt8) -> Data {
            let hash = Insecure.SHA1.hash(data: Data(seed.prefix(16)) + Data([0, 0, 0, counter]))
            return Data(hash.prefix(16).map { byte in
                let upper = byte & 0xFE
                return upper | UInt8(upper.nonzeroBitCount.isMultiple(of: 2) ? 1 : 0)
            })
        }
        return (derive(1), derive(2))
    }

    static func pad(_ data: Data) -> Data {
        var result = data
        result.append(0x80)
        while !result.count.isMultiple(of: 8) { result.append(0) }
        return result
    }

    static func unpad(_ data: Data) throws -> Data {
        var bytes = Array(data)
        guard !bytes.isEmpty, bytes.count.isMultiple(of: 8) else { throw BACError.invalidPadding }
        var removed = 0
        while bytes.last == 0, removed < 7 { bytes.removeLast(); removed += 1 }
        guard bytes.last == 0x80 else { throw BACError.invalidPadding }
        bytes.removeLast()
        return Data(bytes)
    }

    static func equal(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    static func tripleDES(_ data: Data, key: Data, encrypt: Bool) throws -> Data {
        guard key.count == 16 else { throw BACError.cryptographyFailed }
        return try crypt(data, key: key + key.prefix(8), algorithm: CCAlgorithm(kCCAlgorithm3DES),
                         encrypt: encrypt, ecb: false)
    }

    // ISO 9797-1 MAC algorithm 3, with method 2 padding applied by the caller.
    static func retailMAC(_ padded: Data, key: Data) throws -> Data {
        guard key.count == 16, !padded.isEmpty, padded.count.isMultiple(of: 8) else {
            throw BACError.cryptographyFailed
        }
        let left = Data(key.prefix(8))
        let right = Data(key.suffix(8))
        let chain = try crypt(padded, key: left, algorithm: CCAlgorithm(kCCAlgorithmDES), encrypt: true, ecb: false)
        let middle = try crypt(Data(chain.suffix(8)), key: right, algorithm: CCAlgorithm(kCCAlgorithmDES), encrypt: false, ecb: true)
        return try crypt(middle, key: left, algorithm: CCAlgorithm(kCCAlgorithmDES), encrypt: true, ecb: true)
    }

    private static func crypt(_ data: Data, key: Data, algorithm: CCAlgorithm, encrypt: Bool, ecb: Bool) throws -> Data {
        guard !data.isEmpty, data.count.isMultiple(of: 8) else { throw BACError.cryptographyFailed }
        var output = Data(count: data.count)
        var moved = 0
        let status = output.withUnsafeMutableBytes { outputBytes in
            data.withUnsafeBytes { input in
                key.withUnsafeBytes { keyBytes in
                    zeroIV.withUnsafeBytes { iv in
                        CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), algorithm,
                                CCOptions(ecb ? kCCOptionECBMode : 0), keyBytes.baseAddress, key.count,
                                ecb ? nil : iv.baseAddress, input.baseAddress, data.count,
                                outputBytes.baseAddress, outputBytes.count, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess, moved == data.count else { throw BACError.cryptographyFailed }
        return output
    }
}

nonisolated struct BACAuthentication {
    private let encryptionKey: Data
    private let macKey: Data
    private let cardRandom: Data
    private let readerRandom: Data
    private let readerKey: Data
    let command: Data

    init(access: BACAccessKey, cardRandom: Data, readerRandom: Data, readerKey: Data) throws {
        guard cardRandom.count == 8, readerRandom.count == 8, readerKey.count == 16 else {
            throw BACError.invalidResponse
        }
        let seed = Data(Insecure.SHA1.hash(data: access.mrzInformation).prefix(16))
        let keys = BACCrypto.deriveKeys(seed: seed)
        encryptionKey = keys.encryption
        macKey = keys.mac
        self.cardRandom = cardRandom
        self.readerRandom = readerRandom
        self.readerKey = readerKey
        let encrypted = try BACCrypto.tripleDES(readerRandom + cardRandom + readerKey, key: keys.encryption, encrypt: true)
        let mac = try BACCrypto.retailMAC(BACCrypto.pad(encrypted), key: keys.mac)
        command = Data([0, 0x82, 0, 0, 0x28]) + encrypted + mac
    }

    func complete(_ response: Data) throws -> BACSecureMessaging {
        guard response.count == 40 else { throw BACError.invalidResponse }
        let ciphertext = Data(response.prefix(32))
        let mac = try BACCrypto.retailMAC(BACCrypto.pad(ciphertext), key: macKey)
        guard BACCrypto.equal(mac, Data(response.suffix(8))) else { throw BACError.authenticationFailed }
        let plaintext = try BACCrypto.tripleDES(ciphertext, key: encryptionKey, encrypt: false)
        guard BACCrypto.equal(Data(plaintext.prefix(8)), cardRandom),
              BACCrypto.equal(Data(plaintext.dropFirst(8).prefix(8)), readerRandom) else {
            throw BACError.authenticationFailed
        }
        let seed = Data(zip(plaintext.suffix(16), readerKey).map { $0 ^ $1 })
        let keys = BACCrypto.deriveKeys(seed: seed)
        return BACSecureMessaging(encryptionKey: keys.encryption, macKey: keys.mac,
                                  counter: Data(cardRandom.suffix(4)) + readerRandom.suffix(4))
    }
}

nonisolated struct BACSecureMessaging {
    private let encryptionKey: Data
    private let macKey: Data
    private(set) var counter: Data

    init(encryptionKey: Data, macKey: Data, counter: Data) {
        self.encryptionKey = encryptionKey
        self.macKey = macKey
        self.counter = counter
    }

    private mutating func increment() throws {
        guard counter.count == 8 else { throw BACError.invalidResponse }
        var bytes = Array(counter)
        for index in bytes.indices.reversed() {
            bytes[index] &+= 1
            if bytes[index] != 0 { counter = Data(bytes); return }
        }
        throw BACError.counterExhausted
    }

    mutating func readCommand(sfi: UInt8, offset: Int) throws -> Data {
        guard (1...30).contains(sfi), (0..<32_768).contains(offset) else { throw BACError.invalidResponse }
        try increment()
        let header = Data([0x0C, 0xB0, offset == 0 ? 0x80 | sfi : UInt8(offset >> 8), UInt8(offset & 0xFF)])
        let expectedLength = Data([0x97, 1, 0])
        let macInput = counter + BACCrypto.pad(header) + expectedLength
        let mac = try BACCrypto.retailMAC(BACCrypto.pad(macInput), key: macKey)
        return header + Data([0x0D]) + expectedLength + Data([0x8E, 8]) + mac + Data([0])
    }

    mutating func decodeResponse(_ data: Data) throws -> (plaintext: Data, endOfFile: Bool) {
        try increment()
        let nodes = try BERTLV.parse(data)
        // The only accepted order is [DO87,] DO99, DO8E; duplicate/trailing objects are rejected.
        guard nodes.map(\.tag) == [0x87, 0x99, 0x8E] || nodes.map(\.tag) == [0x99, 0x8E],
              let status = nodes.first(where: { $0.tag == 0x99 })?.value,
              status.count == 2, let receivedMAC = nodes.last?.value, receivedMAC.count == 8,
              data.suffix(10).prefix(2) == Data([0x8E, 8]) else { throw BACError.invalidResponse }
        let macInput = counter + data.dropLast(10)
        let mac = try BACCrypto.retailMAC(BACCrypto.pad(macInput), key: macKey)
        guard BACCrypto.equal(mac, receivedMAC) else { throw BACError.authenticationFailed }
        let statusBytes = Array(status)
        let eof = statusBytes == [0x62, 0x82]
        guard statusBytes == [0x90, 0] || eof else {
            throw DocumentProtocolError.cardStatus(statusBytes[0], statusBytes[1])
        }
        guard let encrypted = nodes.first, encrypted.tag == 0x87, encrypted.value.first == 1 else {
            throw BACError.invalidResponse
        }
        let plaintext = try BACCrypto.tripleDES(Data(encrypted.value.dropFirst()), key: encryptionKey, encrypt: false)
        return (try BACCrypto.unpad(plaintext), eof)
    }
}
