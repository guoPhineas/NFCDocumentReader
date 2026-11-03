//
//  DocumentReader.swift
//  NFCDocumentReader
//
//  Created by Phineas Guo on 2026/11/3.
//

#if canImport(CoreNFC)
import CoreNFC
import Foundation
import Observation

@MainActor
@Observable
public final class DocumentReader: NSObject, NFCTagReaderSessionDelegate {
    public enum Status: Equatable {
        case ready, scanning, connecting, checking, dataRead, unsupported, cancelled, failed

        public var title: String {
            switch self {
            case .ready: String(localized: "Ready to Scan", bundle: .module)
            case .scanning: String(localized: "Looking for a Document", bundle: .module)
            case .connecting: String(localized: "Connecting", bundle: .module)
            case .checking: String(localized: "Reading Card Data", bundle: .module)
            case .dataRead: String(localized: "Card Data Read", bundle: .module)
            case .unsupported: String(localized: "Protocol Not Supported Yet", bundle: .module)
            case .cancelled: String(localized: "Scan Cancelled", bundle: .module)
            case .failed: String(localized: "Scan Failed", bundle: .module)
            }
        }

        public var symbol: String {
            switch self {
            case .ready, .scanning, .connecting, .checking: "wave.3.right"
            case .dataRead: "checkmark.circle"
            case .unsupported: "doc.badge.ellipsis"
            case .cancelled: "xmark.circle"
            case .failed: "exclamationmark.triangle"
            }
        }
    }

    public struct Exchange: Identifiable, Equatable {
        public let id: Int
        public let title: String
        public let statusWord: String
        public let responseData: Data

        public var responseLength: Int { responseData.count }
    }

    public private(set) var status: Status = .ready
    public private(set) var message = String(localized: "Scan the document NFC chip.", bundle: .module)
    public private(set) var isScanning = false
    public private(set) var exchanges = [Exchange]()
    public private(set) var tagDetails: ISO7816TagDetails?
    public private(set) var serialResponse: Data?
    public private(set) var cardData: ResidentCardData?
    public private(set) var identity: DocumentIdentity?

    @ObservationIgnored private var session: NFCTagReaderSession?
    @ObservationIgnored private var isFinishing = false
    @ObservationIgnored private var travelProtocol: TravelDocumentProtocol?
    @ObservationIgnored private var documentTag: (any NFCISO7816Tag)?

    public override init() {
        super.init()
    }

    public func start() {
        startSession(access: nil)
    }

    public func startTravel(access: BACAccessKey) {
        startSession(access: access)
    }

    private func startSession(access: BACAccessKey?) {
        guard session == nil else { return }
        exchanges = []
        tagDetails = nil
        serialResponse = nil
        cardData = nil
        identity = nil
        documentTag = nil
        travelProtocol = access.map { TravelDocumentProtocol(access: $0) }
        isFinishing = false
        guard NFCTagReaderSession.readingAvailable else {
            status = .failed
            message = String(localized: "NFC document scanning is unavailable. Use a compatible iPhone with NFC enabled.", bundle: .module)
            return
        }
        guard let newSession = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: .main) else {
            status = .failed
            message = String(localized: "The NFC session could not be created.", bundle: .module)
            return
        }
        session = newSession
        isScanning = true
        status = .scanning
        message = access == nil ? String(localized: "Hold one resident identity card near the top of your iPhone.", bundle: .module) : String(localized: "Hold the travel document near the top of your iPhone. Keep it still until the full name is read.", bundle: .module)
        newSession.alertMessage = message
        newSession.begin()
    }

    public func cancel() {
        guard let session, !isFinishing else { return }
        finish(session, status: .cancelled, message: String(localized: "The scan was cancelled.", bundle: .module))
    }

    // The session and all tag completion handlers use DispatchQueue.main.
    // assumeIsolated checks that contract at runtime instead of suppressing Sendable diagnostics.
    nonisolated public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    nonisolated public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        MainActor.assumeIsolated {
            guard self.session === session, !isFinishing, status == .scanning else { return }
            guard tags.count == 1, let tag = tags.first else {
                session.alertMessage = String(localized: "Present only one document, then move it away and try again.", bundle: .module)
                session.restartPolling()
                return
            }
            status = .connecting
            message = String(localized: "Keep the document still while connecting.", bundle: .module)
            guard case let .iso7816(document) = tag else {
                finish(session, status: .unsupported, message: String(localized: "This NFC tag does not support the document protocol.", bundle: .module))
                return
            }
            documentTag = document
            let sessionID = ObjectIdentifier(session)
            session.connect(to: tag) { [weak self] error in
                MainActor.assumeIsolated {
                    guard let self, let session = self.session, ObjectIdentifier(session) == sessionID,
                          !self.isFinishing, let document = self.documentTag else { return }
                    if let error {
                        self.fail(session, error: error)
                        return
                    }
                    self.tagDetails = ISO7816TagDetails(
                        identifier: document.identifier,
                        selectedApplication: document.initialSelectedAID,
                        historicalBytes: document.historicalBytes,
                        applicationData: document.applicationData,
                        proprietaryApplicationDataCoding: document.proprietaryApplicationDataCoding
                    )
                    self.status = .checking
                    if self.travelProtocol != nil {
                        self.sendTravelStep(to: document, session: session)
                    } else {
                        self.sendNextStep(0, to: document, session: session)
                    }
                }
            }
        }
    }

    private func sendNextStep(_ index: Int, to tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard self.session === session, !isFinishing else { return }
        let steps = ResidentCardReadStep.allCases
        guard index < steps.count else {
            guard let cardData else {
                fail(session, error: DocumentProtocolError.unexpectedResponseLength)
                return
            }
            finish(session, status: .dataRead, message: String(localized: "Read \(cardData.rawResponse.count) mgmt_number response bytes. SN and mgmt_number data are available for inspection.", bundle: .module))
            return
        }
        let step = steps[index]
        message = String(localized: "Keep the identity card still while its data is read.", bundle: .module)
        session.alertMessage = message
        do {
            let bytes = try HexCodec.decode(step.command)
            guard let command = NFCISO7816APDU(data: bytes) else {
                throw DocumentProtocolError.invalidHex
            }
            let sessionID = ObjectIdentifier(session)
            tag.sendCommand(apdu: command) { [weak self] data, sw1, sw2, error in
                MainActor.assumeIsolated {
                    guard let self, let session = self.session, ObjectIdentifier(session) == sessionID,
                          !self.isFinishing, let tag = self.documentTag else { return }
                    if let error {
                        self.fail(session, error: error)
                        return
                    }
                    let response = APDUResponse(data: data, sw1: sw1, sw2: sw2)
                    // Responses stay in memory for local inspection; they are never logged or sent.
                    self.exchanges.append(Exchange(id: self.exchanges.count, title: step.title, statusWord: response.statusWord, responseData: data))
                    do {
                        try step.validate(response)
                        if step == .readSn {
                            self.serialResponse = data
                        } else if step == .readDn {
                            self.cardData = try ResidentCardData(rawResponse: data)
                        }
                        self.sendNextStep(index + 1, to: tag, session: session)
                    } catch {
                        self.fail(session, error: error)
                    }
                }
            }
        } catch {
            fail(session, error: error)
        }
    }

    private func sendTravelStep(to tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard self.session === session, !isFinishing, travelProtocol != nil else { return }
        do {
            let title = travelProtocol!.title
            guard let bytes = try travelProtocol!.command() else {
                guard travelProtocol!.stage == .complete, let result = travelProtocol!.identity,
                      result.fullName != nil else { throw BACError.invalidResponse }
                identity = result
                finish(session, status: .dataRead, message: String(localized: "Read the full name and identity fields from the document chip.", bundle: .module))
                return
            }
            guard let command = NFCISO7816APDU(data: bytes) else { throw BACError.invalidResponse }
            message = String(localized: "\(title). Keep the document still.", bundle: .module)
            session.alertMessage = message
            let sessionID = ObjectIdentifier(session)
            tag.sendCommand(apdu: command) { [weak self] data, sw1, sw2, error in
                MainActor.assumeIsolated {
                    guard let self, let session = self.session, ObjectIdentifier(session) == sessionID,
                          !self.isFinishing, let tag = self.documentTag else { return }
                    if let error { self.fail(session, error: error); return }
                    let response = APDUResponse(data: data, sw1: sw1, sw2: sw2)
                    self.exchanges.append(Exchange(id: self.exchanges.count, title: title,
                                                   statusWord: response.statusWord, responseData: data))
                    do {
                        try self.travelProtocol!.accept(response)
                        self.identity = self.travelProtocol!.identity
                        self.sendTravelStep(to: tag, session: session)
                    } catch {
                        self.fail(session, error: error)
                    }
                }
            }
        } catch {
            fail(session, error: error)
        }
    }

    private func fail(_ session: NFCTagReaderSession, error: Error) {
        finish(session, status: .failed, message: error.localizedDescription, isError: true)
    }

    private func finish(_ session: NFCTagReaderSession, status: Status, message: String, isError: Bool = false) {
        guard self.session === session, !isFinishing else { return }
        isFinishing = true
        self.status = status
        self.message = message
        if isError {
            session.invalidate(errorMessage: message)
        } else {
            session.alertMessage = message
            session.invalidate()
        }
    }

    nonisolated public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        MainActor.assumeIsolated {
            guard self.session === session else { return }
            self.session = nil
            travelProtocol = nil
            documentTag = nil
            isScanning = false
            // Explicit completion wins over the subsequent Core NFC invalidation callback.
            guard !isFinishing else { return }
            if let nfcError = error as? NFCReaderError {
                switch nfcError.code {
                case .readerSessionInvalidationErrorUserCanceled:
                    status = .cancelled
                    message = String(localized: "The scan was cancelled.", bundle: .module)
                case .readerSessionInvalidationErrorSessionTimeout:
                    status = .failed
                    message = String(localized: "The NFC session timed out. Move the document and scan again.", bundle: .module)
                default:
                    status = .failed
                    message = error.localizedDescription
                }
            } else {
                status = .failed
                message = error.localizedDescription
            }
        }
    }
}

#endif
