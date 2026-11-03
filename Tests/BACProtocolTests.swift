//
//  BACProtocolTests.swift
//  NFCDocumentReader
//
//  Created by Phineas Guo on 2026/11/3.
//

import Foundation
import XCTest
@testable import NFCDocumentReader

struct BACProtocolTests {
    struct Failure: Error { let description: String }

    static func expect(_ condition: @autoclosure () throws -> Bool, _ description: String) throws {
        guard try condition() else { throw Failure(description: description) }
    }

    static func reject(_ description: String, _ body: () throws -> Void) throws {
        do { try body() } catch is BACError { return } catch is DocumentProtocolError { return }
        throw Failure(description: description)
    }

    static func hex(_ value: String) throws -> Data { try HexCodec.decode(value) }

    static func tlv(_ tag: [UInt8], _ value: Data) -> Data {
        let length = value.count < 128 ? [UInt8(value.count)] : [0x81, UInt8(value.count)]
        return Data(tag + length) + value
    }

    static let mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" + "L898902C<3UTO6908061F9406236ZE184226B<<<<<14"

    static func main() throws {
        // Fixed BAC example values provide independent expectations for SHA-1, DES parity,
        // 3DES-CBC without padding, and the retail MAC. No real identity data is used.
        let access = try BACAccessKey(documentNumber: "L898902C", birthDate: "690806", expiryDate: "940623")
        try expect(String(decoding: access.mrzInformation, as: UTF8.self) == "L898902C<369080619406236", "MRZ key material")
        let staticKeys = BACCrypto.deriveKeys(seed: try hex("239AB9CB282DAF66231DC5A4DF6BFBAE"))
        try expect(staticKeys.encryption == hex("AB94FDECF2674FDFB9B391F85D7F76F2"), "Static encryption key")
        try expect(staticKeys.mac == hex("7962D9ECE03D1ACD4C76089DCE131543"), "Static MAC key")
        let cardRandom = try hex("4608F91988702212")
        let readerRandom = try hex("781723860C06C226")
        let readerKey = try hex("0B795240CB7049B01C19B33E32804F0B")
        let auth = try BACAuthentication(access: access, cardRandom: cardRandom, readerRandom: readerRandom, readerKey: readerKey)
        let expectedAuth = try hex("008200002872C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7")
        try expect(auth.command == expectedAuth, "Authentication APDU without an expected response length")
        let authResponse = try hex("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449")
        var messaging = try auth.complete(authResponse)
        try expect(messaging.counter == hex("887022120C06C226"), "Initial SSC")
        let protectedRead = try messaging.readCommand(sfi: 1, offset: 0)
        try expect(protectedRead.prefix(10) == hex("0CB081000D9701008E08"), "Protected SFI read header")
        let sessionEnc = try hex("979EC13B1CBFE9DCD01AB0FED307EAE5")
        let sessionMAC = try hex("F1CB1F1FB5ADF208806B89DC579DC1F8")

        func protectedResponse(_ plaintext: Data, counter: String, status: Data = Data([0x90, 0])) throws -> Data {
            let encrypted = try BACCrypto.tripleDES(BACCrypto.pad(plaintext), key: sessionEnc, encrypt: true)
            let body = tlv([0x87], Data([1]) + encrypted) + tlv([0x99], status)
            let mac = try BACCrypto.retailMAC(BACCrypto.pad(hex(counter) + body), key: sessionMAC)
            return body + tlv([0x8E], mac)
        }

        let identityData = tlv([0x61], tlv([0x5F, 0x1F], Data(mrz.utf8)))
        let name = "测试姓名"
        let personalDetails = tlv([0x6B], tlv([0x5C], Data([0x5F, 0x0E])) + tlv([0x5F, 0x0E], Data(name.utf8)))
        let response = try protectedResponse(identityData, counter: "887022120C06C228")
        try expect(messaging.decodeResponse(response).plaintext == identityData, "Authenticated response decryption")
        for index in response.indices {
            var corrupt = response
            corrupt[index] ^= 1
            var verifier = try auth.complete(authResponse)
            _ = try verifier.readCommand(sfi: 1, offset: 0)
            try reject("Reject modified secure response at byte \(index)") { _ = try verifier.decodeResponse(corrupt) }
        }
        for index in authResponse.indices {
            var corrupt = authResponse
            corrupt[index] ^= 1
            try reject("Reject modified authentication at byte \(index)") { _ = try auth.complete(corrupt) }
        }
        for length in 0..<40 {
            try reject("Reject truncated authentication") { _ = try auth.complete(Data(authResponse.prefix(length))) }
        }
        let parsed = try MachineReadableIdentityParser.identity(fromPlaintext: identityData)
        try expect(parsed.documentNumber == "L898902C" && parsed.mrzName == "ERIKSSON ANNA MARIA", "identity data number and name")
        try expect(parsed.birthDate == "690806" && parsed.expiryDate == "940623" && parsed.nationality == "UTO" && parsed.sex == "F", "identity data dates, nationality, and sex")
        var invalidMRZ = Data(mrz.utf8)
        invalidMRZ[53] = 48
        try reject("MRZ check digit") { _ = try MachineReadableIdentityParser.identity(fromPlaintext: tlv([0x61], tlv([0x5F, 0x1F], invalidMRZ))) }

        let td1 = "I<UTOD231458907<<<<<<<<<<<<<<<" + "7408122F1204159UTO<<<<<<<<<<<6" + "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
        let td2 = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" + "D231458907UTO7408122F1204159<<<<<<<6"
        for value in [td1, td2] {
            let identity = try MachineReadableIdentityParser.identity(fromPlaintext: tlv([0x61], tlv([0x5F, 0x1F], Data(value.utf8))))
            try expect(identity.documentNumber == "D23145890" && identity.birthDate == "740812"
                       && identity.expiryDate == "120415" && identity.sex == "F", "TD1/TD2 field offsets and check digits")
        }
        var wrongNonce = cardRandom + readerRandom + Data(repeating: 0x42, count: 16)
        wrongNonce[0] ^= 1
        let badCipher = try BACCrypto.tripleDES(wrongNonce, key: staticKeys.encryption, encrypt: true)
        let badAuth = try badCipher + BACCrypto.retailMAC(BACCrypto.pad(badCipher), key: staticKeys.mac)
        try reject("Valid MAC with incorrect nonce") { _ = try auth.complete(badAuth) }

        var replayVerifier = try auth.complete(authResponse)
        _ = try replayVerifier.readCommand(sfi: 1, offset: 0)
        _ = try replayVerifier.decodeResponse(response)
        _ = try replayVerifier.readCommand(sfi: 1, offset: identityData.count)
        try reject("Replayed response with old SSC") { _ = try replayVerifier.decodeResponse(response) }
        var errorVerifier = try auth.complete(authResponse)
        _ = try errorVerifier.readCommand(sfi: 1, offset: 0)
        try reject("Authenticated card error status") {
            _ = try errorVerifier.decodeResponse(protectedResponse(identityData, counter: "887022120C06C228", status: Data([0x69, 0x82])))
        }

        var flow = TravelDocumentProtocol(access: access)
        func accept(_ data: Data) throws {
            try flow.accept(APDUResponse(data: data, sw1: 0x90, sw2: 0), random: { $0 == 8 ? readerRandom : readerKey })
        }
        try expect(flow.command() == hex("00A40000023F00"), "Select MF")
        try accept(Data())
        try expect(flow.command() == hex("00B0810003"), "Read header")
        try accept(Data([0x60, 1, 0]))
        try expect(flow.command() == hex("00A4040007A0000002471001"), "Select AID")
        try accept(Data())
        try expect(flow.command() == hex("0084000008"), "First challenge")
        try accept(cardRandom)
        try expect(flow.command() == expectedAuth, "First mutual authentication")
        try accept(authResponse)
        try expect(flow.command() == protectedRead, "identity data protected command")
        // Split inside the TLV length/value boundary to exercise bounded file assembly.
        try accept(protectedResponse(Data(identityData.prefix(3)), counter: "887022120C06C228"))
        let continuation = try flow.command()!
        try expect(continuation.prefix(4) == hex("0CB00003"), "identity data continuation offset")
        try accept(protectedResponse(Data(identityData.dropFirst(3)), counter: "887022120C06C22A"))
        try expect(flow.identity?.documentNumber == "L898902C" && flow.identity?.fullName == nil, "Partial identity is explicitly MRZ-only")
        try expect(flow.command() == hex("0084000008"), "Second challenge before personal details")
        try accept(cardRandom)
        try expect(flow.command() == expectedAuth, "Second mutual authentication")
        try accept(authResponse)
        try expect(flow.command()?.prefix(4) == hex("0CB08B00"), "personal details protected SFI command")
        try accept(protectedResponse(personalDetails, counter: "887022120C06C228"))
        try expect(flow.stage == .complete && flow.identity?.displayName == name && flow.identity?.documentNumber == "L898902C", "NFC transcript to full identity result")
        try expect(flow.command() == nil, "Stop sending after completion")
        for length in 0...32 {
            let input = Data(repeating: 0x42, count: length)
            try expect(BACCrypto.unpad(BACCrypto.pad(input)) == input, "Padding boundary \(length)")
        }
        try reject("Reject zero padding without marker") { _ = try BACCrypto.unpad(Data(repeating: 0, count: 8)) }
        try reject("Invalid date") { _ = try BACAccessKey(documentNumber: "ABC", birthDate: "691332", expiryDate: "940623") }
        try reject("Long document number") { _ = try BACAccessKey(documentNumber: "1234567890", birthDate: "690806", expiryDate: "940623") }
        var exhausted = BACSecureMessaging(encryptionKey: sessionEnc, macKey: sessionMAC, counter: Data(repeating: 255, count: 8))
        try reject("SSC overflow") { _ = try exhausted.readCommand(sfi: 1, offset: 0) }
        print("BAC fixtures, tampering checks, boundary cases, and full identity and personal-details NFC transcript passed.")
    }
}

final class BACProtocolTestsSuite: XCTestCase {
    @MainActor func testProtocol() throws {
        try BACProtocolTests.main()
    }
}
