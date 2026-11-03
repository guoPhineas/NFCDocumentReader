//
//  ContentView.swift
//  IDCardReader
//
//  Created by Phineas Guo on 2026/11/3.
//

import Foundation
import SwiftUI
import NFCDocumentReader

struct ContentView: View {
    @State private var travelReader = NFCDocumentReader.DocumentReader()
    @State private var residentReader = NFCDocumentReader.DocumentReader()

    var body: some View {
        TabView {
            Tab("Travel Documents (Passport)", systemImage: "airplane") {
                DocumentScanView(reader: travelReader, isTravel: true,
                                 otherReaderIsScanning: residentReader.isScanning)
            }
            Tab("Chinese Identity Card", systemImage: "person.text.rectangle") {
                DocumentScanView(reader: residentReader, isTravel: false,
                                 otherReaderIsScanning: travelReader.isScanning)
            }
        }
    }
}

private struct DocumentScanView: View {
    let reader: NFCDocumentReader.DocumentReader
    let isTravel: Bool
    let otherReaderIsScanning: Bool
    @State private var number = ""
    @State private var birthDate = ""
    @State private var expiryDate = ""
    @State private var inputError: String?

    var body: some View {
        NavigationStack {
            List {
                ReaderStatusSection(status: reader.status, message: reader.message)
                if isTravel {
                    Section {
                        TextField("Document Number", text: $number)
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                        TextField("Date of Birth (YYMMDD)", text: $birthDate)
                            .keyboardType(.numberPad)
                        TextField("Expiry Date (YYMMDD)", text: $expiryDate)
                            .keyboardType(.numberPad)
                        if let inputError { Text(inputError).foregroundStyle(.red) }
                    } header: {
                        Text("BAC Access")
                    } footer: {
                        Text("Enter the number and dates from the machine-readable zone to unlock chip access.")
                    }
                    .disabled(reader.isScanning)
                }
                Section {
                    Button("Scan Document", systemImage: "wave.3.right", action: scan)
                        .disabled(reader.isScanning || otherReaderIsScanning)
                    if reader.isScanning {
                        Button("Cancel Scan", role: .cancel, action: reader.cancel)
                    }
                } footer: {
                    Text("Hold one document near the top of your iPhone until the scan finishes.")
                }
                if isTravel, let identity = reader.identity {
                    IdentitySection(identity: identity)
                }
                if !isTravel {
                    if let serial = reader.serialResponse {
                        Section("SN Response") {
                            HexDataRow(title: "SN Bytes", data: serial)
                        }
                    }
                    if let cardData = reader.cardData {
                        CardResponseSection(cardData: cardData)
                    }
                }
                if let details = reader.tagDetails {
                    ConnectedTagSection(details: details)
                }
                if !reader.exchanges.isEmpty {
                    Section("Connection Details") {
                        ForEach(reader.exchanges) { exchange in
                            ExchangeRow(exchange: exchange)
                        }
                    }
                }
                if isTravel {
                    Section("Current Support") {
                        Text("BAC reads identity fields and additional personal details. PACE-only documents and extended MRZ document numbers are not supported yet.")
                        Text("BAC authenticates session messages, but does not verify the issuing authority's signature. Results stay in memory and are not uploaded.")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle(isTravel ? Text("Travel Documents") : Text("Chinese Identity Card"))
        }
        .onDisappear { reader.cancel() }
    }

    private func scan() {
        inputError = nil
        if !isTravel { reader.start(); return }
        do {
            let access = try BACAccessKey(documentNumber: number, birthDate: birthDate, expiryDate: expiryDate)
            reader.startTravel(access: access)
        } catch {
            inputError = error.localizedDescription
        }
    }
}

private struct IdentitySection: View {
    let identity: DocumentIdentity

    var body: some View {
        Section("Identity Read from Chip") {
            LabeledContent("Name", value: identity.displayName)
            if identity.fullName == nil {
                Text("Showing the MRZ name. Additional personal details have not been read.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            LabeledContent("Document Number", value: identity.documentNumber)
            LabeledContent("Date of Birth (YYMMDD)", value: identity.birthDate)
            LabeledContent("Expiry Date (YYMMDD)", value: identity.expiryDate)
            LabeledContent("Sex", value: identity.sex == "<" ? String(localized: "Unspecified") : identity.sex)
            LabeledContent("Nationality", value: identity.nationality)
            LabeledContent("Issuing State", value: identity.issuingState)
            LabeledContent("Document Code", value: identity.documentCode)
            if !identity.optionalData.isEmpty {
                LabeledContent("MRZ Optional Data", value: identity.optionalData)
            }
            DisclosureGroup("Machine-Readable Zone") {
                Text(identity.mrz).font(.footnote.monospaced())
            }
        }
        .textSelection(.enabled)
        .privacySensitive()
    }
}

private struct ConnectedTagSection: View {
    let details: ISO7816TagDetails

    var body: some View {
        Section {
            LabeledContent("Protocol", value: "ISO 7816")
            LabeledContent("Application ID", value: details.selectedApplication)
                .font(.footnote.monospaced())
                .textSelection(.enabled)
            HexDataRow(title: "Tag Identifier", data: details.identifier)
            if let historicalBytes = details.historicalBytes {
                HexDataRow(title: "Historical Bytes", data: historicalBytes)
            }
            if let applicationData = details.applicationData {
                HexDataRow(title: "Application Data", data: applicationData)
                LabeledContent("Application Data Coding", value: details.proprietaryApplicationDataCoding ? String(localized: "Proprietary") : "ISO 14443-3")
            }
        } header: {
            Text("NFC Connection")
        } footer: {
            Text("The tag identifier describes the NFC tag; it is not a decoded identity number.")
        }
    }
}

private struct CardResponseSection: View {
    let cardData: ResidentCardData

    var body: some View {
        Section("mgmt_number Response") {
            LabeledContent("Received", value: String(localized: "\(cardData.rawResponse.count) bytes"))
            HexDataRow(title: "mgmt_number Bytes", data: cardData.rawResponse)
        }
    }
}

private struct HexDataRow: View {
    let title: LocalizedStringResource
    let data: Data

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
            Text(data.isEmpty ? String(localized: "No response payload") : HexCodec.encode(data))
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }
}

private struct ReaderStatusSection: View {
    let status: NFCDocumentReader.DocumentReader.Status
    let message: String

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                Label(status.title, systemImage: status.symbol)
                    .font(.headline)
                Text(message)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 8)
        }
    }
}

private struct ExchangeRow: View {
    let exchange: NFCDocumentReader.DocumentReader.Exchange

    var body: some View {
        DisclosureGroup {
            HexDataRow(title: "Response Bytes", data: exchange.responseData)
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                Text(exchange.title)
                Text("Status \(exchange.statusWord) · \(exchange.responseLength) response bytes")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
    }
}

#Preview {
    ContentView()
}
