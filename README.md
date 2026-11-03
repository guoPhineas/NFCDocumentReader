# NFCDocumentReader

A local Swift package for reading NFC document chips, with an iOS demo app.

## Supported documents

- **Travel documents (Passport):** BAC access using the document number, date of birth, and expiry date from the machine-readable zone. Reads machine-readable identity fields and the full name from additional personal details. Dates retain their YYMMDD representation.
- **Chinese resident identity cards:** reads raw SN and mgmt_number responses.
- Both routes expose ISO 7816 tag metadata and APDU response data/status words.

PACE-only documents and extended MRZ document numbers are not supported. BAC authenticates session messages; issuer signatures are not verified. The travel route currently requires a readable full name in the personal-details file to finish successfully. Results are not proof of document authenticity.

## Public protocols and resident-card scope

The package uses public NFC interfaces and publicly documented travel-document protocols and cryptographic algorithms. It does not implement non-public algorithms, resident-card identity decryption, secret key recovery, or access-control bypasses.

**mgmt_number is a document management number.** 

## Requirements

- Swift 6.2 or later; the package uses Swift 5 language mode.
- iOS 17 or later and a compatible physical iPhone for NFC sessions.
- The demo currently targets iOS 18.0. Use a compatible Xcode/SDK.
- The protocol tests also run on macOS 14 or later. The Core NFC reader API is available only where CoreNFC can be imported.

## Package integration

Add this repository's root directory as a local Swift package in Xcode, then link the `NFCDocumentReader` product to your iOS target.

The host app must enable **Near Field Communication Tag Reading**, configure NFC entitlements and provisioning, supply `NFCReaderUsageDescription`, and declare the required ISO 7816 application identifiers in Info.plist. The demo includes the existing configuration; adjust its signing team and bundle identifier for your account.

```swift
import NFCDocumentReader
import SwiftUI

struct ResidentCardView: View {
    @State private var reader = NFCDocumentReader.DocumentReader()

    var body: some View {
        VStack {
            Text(reader.message)
            Button("Read Card") { reader.start() }
                .disabled(reader.isScanning)
            if let sn = reader.serialResponse {
                Text(HexCodec.encode(sn))
            }
        }
    }
}
```

For travel documents, create a `BACAccessKey` and call `reader.startTravel(access:)`:

```swift
let access = try BACAccessKey(
    documentNumber: "L898902C",
    birthDate: "690806",
    expiryDate: "940623"
)
reader.startTravel(access: access)
```

`DocumentReader` is a main-actor observable object. Calls start a session; results arrive asynchronously through its read-only observable properties:

| Property | Content |
| --- | --- |
| `status`, `message`, `isScanning` | Progress, completion, cancellation, or failure |
| `identity` | Travel document identity, including any partial machine-readable identity result |
| `serialResponse` | Raw resident-card SN response |
| `cardData` | Raw resident-card mgmt_number response and 16-byte mgmt_number prefix |
| `tagDetails` | ISO 7816 connection metadata |
| `exchanges` | APDU response payloads and status words |

Check `status == .dataRead` for successful completion; `identity` may appear before the full scan finishes. Call `cancel()` to stop a session. Keep the reader alive while scanning and avoid starting multiple readers concurrently. Starting another scan resets that reader's previous results.

The package has no networking or persistence. Sensitive results remain in memory; the host app controls any further use or storage. Package-owned progress and error text uses the package resource bundle.

## Demo app

Open `Demo/IDCardReader.xcodeproj`, select the `IDCardReader` scheme, configure signing, and run on a physical iPhone. The project links the root package through a relative local dependency.

The demo has two tabs with separate results: **Travel Documents (Passport)** and **Chinese Identity Card Reader**. Switching tabs cancels the outgoing scan.

## Verification

Run the package tests from the repository root:

```sh
swift test
```

Tests use synthetic data and fixed cryptographic vectors. They cover resident-card commands and response boundaries, TLV parsing, MRZ validation, BAC authentication, secure messaging, tampering, and a simulated identity and personal-details exchange sequence. They do not exercise physical NFC hardware.

Build the demo with Xcode, or use:

```sh
xcodebuild -project Demo/IDCardReader.xcodeproj \
  -scheme IDCardReader -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build
```

Hardware compatibility and successful reading of real documents require device testing.
