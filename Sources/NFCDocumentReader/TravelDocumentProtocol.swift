//
//  TravelDocumentProtocol.swift
//  NFCDocumentReader
//
//  Created by Phineas Guo on 2026/11/3.
//

import Foundation

nonisolated public struct DocumentIdentity: Equatable, Sendable {
    public let documentNumber: String
    public let mrzName: String
    public let nationality: String
    public let sex: String
    public let birthDate: String
    public let expiryDate: String
    public let issuingState: String
    public let documentCode: String
    public let optionalData: String
    public let mrz: String
    public internal(set) var fullName: String?

    public var displayName: String { fullName ?? mrzName }
}

nonisolated enum MachineReadableIdentityParser {
    static func identity(fromPlaintext data: Data) throws -> DocumentIdentity {
        let groups = try BERTLV.parse(data)
        guard groups.count == 1, let group = groups.first, group.tag == 0x61, group.children.count == 1,
              let mrzNode = group.children.first(where: { $0.tag == 0x5F1F }),
              mrzNode.value.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || $0 == 60 }),
              let mrz = String(data: mrzNode.value, encoding: .ascii) else {
            throw BACError.unsupportedMRZ
        }
        let bytes = Array(mrz.utf8)
        func text(_ range: Range<Int>) -> String { String(decoding: bytes[range], as: UTF8.self) }
        func field(_ range: Range<Int>) -> String { text(range).replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespaces) }
        func verify(_ range: Range<Int>, _ digit: Int) throws {
            guard bytes[digit] == UInt8(48 + BACAccessKey.checkDigit(text(range))) else {
                throw BACError.invalidResponse
            }
        }
        func composite(_ ranges: [Range<Int>], _ digit: Int) throws {
            let input = ranges.map(text).joined()
            guard bytes[digit] == UInt8(48 + BACAccessKey.checkDigit(input)) else { throw BACError.invalidResponse }
        }
        let number: Range<Int>, birth: Range<Int>, expiry: Range<Int>, name: Range<Int>
        let nationality: Range<Int>, sex: Int, optional: String
        switch bytes.count {
        case 88: // TD3
            number = 44..<53; birth = 57..<63; expiry = 65..<71; name = 5..<44
            nationality = 54..<57; sex = 64; optional = field(72..<86)
            try verify(number, 53); try verify(birth, 63); try verify(expiry, 71)
            try composite([44..<54, 57..<64, 65..<87], 87)
        case 72: // TD2
            number = 36..<45; birth = 49..<55; expiry = 57..<63; name = 5..<36
            nationality = 46..<49; sex = 56; optional = field(64..<71)
            try verify(number, 45); try verify(birth, 55); try verify(expiry, 63)
            try composite([36..<46, 49..<56, 57..<71], 71)
        case 90: // TD1; extended document numbers need a separate, verified parser.
            number = 5..<14; birth = 30..<36; expiry = 38..<44; name = 60..<90
            nationality = 45..<48; sex = 37; optional = [field(15..<30), field(48..<59)].filter { !$0.isEmpty }.joined(separator: " ")
            try verify(number, 14); try verify(birth, 36); try verify(expiry, 44)
            try composite([5..<30, 30..<37, 38..<45, 48..<59], 59)
        default: throw BACError.unsupportedMRZ
        }
        guard BACAccessKey.validDate(text(birth)), BACAccessKey.validDate(text(expiry)),
              [UInt8(77), 70, 60].contains(bytes[sex]) else { throw BACError.invalidResponse }
        let names = text(name).components(separatedBy: "<<")
        let displayName = names.map { $0.replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }.joined(separator: " ")
        guard !field(number).isEmpty, !displayName.isEmpty else { throw BACError.invalidResponse }
        return DocumentIdentity(documentNumber: field(number), mrzName: displayName,
                                nationality: field(nationality), sex: text(sex..<(sex + 1)),
                                birthDate: text(birth), expiryDate: text(expiry), issuingState: field(2..<5),
                                documentCode: field(0..<2), optionalData: optional, mrz: mrz, fullName: nil)
    }
}

/// Callback-driven protocol state, independent of Core NFC for transcript testing.
nonisolated struct TravelDocumentProtocol {
    enum Stage { case selectMF, readHeader, selectApplication, challengeIdentity, authenticateIdentity, readIdentity, challengePersonalDetails, authenticatePersonalDetails, readPersonalDetails, complete }
    private(set) var stage: Stage = .selectMF
    private(set) var identity: DocumentIdentity?
    private let access: BACAccessKey
    private var authentication: BACAuthentication?
    private var messaging: BACSecureMessaging?
    private var group = Data()
    private var expectedLength: Int?

    init(access: BACAccessKey) { self.access = access }

    var title: String {
        switch stage {
        case .selectMF: String(localized: "Select master file", bundle: .module)
        case .readHeader: String(localized: "Read file header", bundle: .module)
        case .selectApplication: String(localized: "Select document application", bundle: .module)
        case .challengeIdentity, .challengePersonalDetails: String(localized: "Get document challenge", bundle: .module)
        case .authenticateIdentity, .authenticatePersonalDetails: String(localized: "Authenticate document", bundle: .module)
        case .readIdentity: String(localized: "Read identity data", bundle: .module)
        case .readPersonalDetails: String(localized: "Read full name", bundle: .module)
        case .complete: String(localized: "Identity data read", bundle: .module)
        }
    }

    mutating func command() throws -> Data? {
        switch stage {
        case .selectMF: try HexCodec.decode("00A40000023F00")
        case .readHeader: try HexCodec.decode("00B0810003")
        case .selectApplication: try HexCodec.decode("00A4040007A0000002471001")
        case .challengeIdentity, .challengePersonalDetails: try HexCodec.decode("0084000008")
        case .authenticateIdentity, .authenticatePersonalDetails: authentication?.command
        case .readIdentity, .readPersonalDetails: try messaging?.readCommand(sfi: stage == .readIdentity ? 1 : 11, offset: group.count)
        case .complete: nil
        }
    }

    mutating func accept(_ response: APDUResponse) throws {
        try accept(response, random: BACCrypto.random)
    }

    // Deterministic randomness is injectable only at the protocol layer for synthetic transcripts.
    mutating func accept(_ response: APDUResponse, random: (Int) throws -> Data) throws {
        try response.requireSuccess()
        switch stage {
        case .selectMF: stage = .readHeader
        case .readHeader:
            stage = .selectApplication
        case .selectApplication: stage = .challengeIdentity
        case .challengeIdentity, .challengePersonalDetails:
            authentication = try BACAuthentication(access: access, cardRandom: response.data,
                                                    readerRandom: random(8), readerKey: random(16))
            stage = stage == .challengeIdentity ? .authenticateIdentity : .authenticatePersonalDetails
        case .authenticateIdentity, .authenticatePersonalDetails:
            guard let authentication else { throw BACError.invalidResponse }
            messaging = try authentication.complete(response.data)
            self.authentication = nil
            group = Data(); expectedLength = nil
            stage = stage == .authenticateIdentity ? .readIdentity : .readPersonalDetails
        case .readIdentity, .readPersonalDetails:
            guard messaging != nil else { throw BACError.invalidResponse }
            let decoded = try messaging!.decodeResponse(response.data)
            guard !decoded.plaintext.isEmpty, group.count + decoded.plaintext.count <= 32_767 else {
                throw BACError.invalidResponse
            }
            group.append(decoded.plaintext)
            if expectedLength == nil { expectedLength = try Self.totalLength(group) }
            if let expectedLength {
                guard group.count <= expectedLength else { throw BACError.invalidResponse }
                if group.count == expectedLength {
                    if stage == .readIdentity {
                        let parsed = try MachineReadableIdentityParser.identity(fromPlaintext: group)
                        // Compare the card's authenticated MRZ with the access key; inputs are never displayed as read results.
                        let cardAccess = try BACAccessKey(documentNumber: parsed.documentNumber,
                                                          birthDate: parsed.birthDate, expiryDate: parsed.expiryDate)
                        guard cardAccess.mrzInformation == access.mrzInformation else { throw BACError.authenticationFailed }
                        identity = parsed
                        stage = .challengePersonalDetails
                    } else {
                        guard let name = try PersonalDetailsParser.fullName(fromPlaintext: group) else {
                            throw DocumentProtocolError.invalidPersonalDetails
                        }
                        identity?.fullName = name
                        stage = .complete
                    }
                    messaging = nil; group = Data()
                    return
                }
            }
            guard !decoded.endOfFile else { throw BACError.invalidResponse }
        case .complete: throw BACError.invalidResponse
        }
    }

    private static func totalLength(_ data: Data) throws -> Int? {
        let bytes = Array(data)
        guard bytes.count >= 2 else { return nil }
        guard bytes[0] == 0x61 || bytes[0] == 0x6B else { throw BACError.invalidResponse }
        let marker = Int(bytes[1])
        if marker < 128 { return 2 + marker }
        let count = marker & 0x7F
        guard (1...2).contains(count) else { throw BACError.invalidResponse }
        guard bytes.count >= 2 + count else { return nil }
        let length = bytes[2..<(2 + count)].reduce(0) { $0 << 8 | Int($1) }
        guard length + 2 + count <= 32_767 else { throw BACError.invalidResponse }
        return length + 2 + count
    }
}
