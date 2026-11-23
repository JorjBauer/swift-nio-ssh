//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
final class MLKEM768X25519KeyExchangeTests: XCTestCase {
    private func keyExchangeAgreed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        XCTAssertEqual(first.sessionID, second.sessionID)
        XCTAssertEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    // RFC 4251 section 5: a 4-byte big-endian length, then the bytes
    private static func sshString(_ bytes: some Sequence<UInt8>) -> [UInt8] {
        let body = Array(bytes)
        var buffer = ByteBufferAllocator().buffer(capacity: 4 + body.count)
        buffer.writeInteger(UInt32(body.count))
        buffer.writeBytes(body)
        return Array(buffer.readableBytesView)
    }

    func testRoundTripProducesMatchingKeys() throws {
        var server = try MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = try MLKEM768X25519KeyExchange(ourRole: .mlkemTest_client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 4096)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())

        // The client's init payload is the ML-KEM-768 public key (1184 bytes),
        // then the X25519 public key (32 bytes), as in OpenSSH 9.9.
        XCTAssertEqual(
            clientMessage.publicKey.readableBytes,
            MLKEM768X25519KeyExchange.mlkemPublicKeySize + MLKEM768X25519KeyExchange.x25519PublicKeySize
        )

        let (serverKeys, serverResponse) = try server.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: clientMessage,
            serverHostKey: serverHostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        // The server's reply payload is the ML-KEM-768 ciphertext (1088 bytes),
        // then the X25519 public key (32 bytes).
        XCTAssertEqual(
            serverResponse.publicKey.readableBytes,
            MLKEM768X25519KeyExchange.mlkemCiphertextSize + MLKEM768X25519KeyExchange.x25519PublicKeySize
        )

        initialExchangeBytes.clear()

        let clientKeys = try client.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: serverResponse,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testReusesPreviousSessionIdentifier() throws {
        var previousSessionIdentifier = ByteBufferAllocator().buffer(capacity: 32)
        previousSessionIdentifier.writeBytes(0..<32)

        var server = try MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: previousSessionIdentifier
        )
        var client = try MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_client,
            previousSessionIdentifier: previousSessionIdentifier
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 4096)

        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        let (serverKeys, serverResponse) = try server.completeKeyExchangeServerSide(
            clientKeyExchangeMessage: clientMessage,
            serverHostKey: serverHostKey,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        initialExchangeBytes.clear()

        let clientKeys = try client.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: serverResponse,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
        )

        self.keyExchangeAgreed(serverKeys, clientKeys)
        XCTAssertEqual(serverKeys.sessionID, previousSessionIdentifier)
    }

    // OpenSSH puts K into the exchange hash and the key derivation as an SSH
    // string (a 4-byte length, then the 32 digest bytes). The round-trip tests
    // above use our code on both ends, so they pass with any encoding of K.
    // In this test we act as the OpenSSH server. We build the exchange hash
    // and the session keys the same way OpenSSH does, then check that the
    // client derives the same values. OpenSSH encodes K in
    // kexmlkem768x25519.c, builds H in kexgen.c, and derives the keys in
    // kex.c:
    //
    // https://github.com/openssh/openssh-portable/blob/ebdaacf4907033af1cbf1fef593436081dcd67a7/kexmlkem768x25519.c#L152-L156
    // https://github.com/openssh/openssh-portable/blob/ebdaacf4907033af1cbf1fef593436081dcd67a7/kexgen.c#L67-L79
    // https://github.com/openssh/openssh-portable/blob/ebdaacf4907033af1cbf1fef593436081dcd67a7/kex.c#L1087-L1093
    func testClientMatchesOpenSSHWhenKHasHighBitSet() throws {
        var client = try MLKEM768X25519KeyExchange(ourRole: .mlkemTest_client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let keySizes = AES128GCMOpenSSHTransportProtection.keySizes

        // Stand-in for V_C, V_S, I_C and I_S, which the state machine writes
        // before the key exchange runs. (Any bytes will work.)
        let transcriptStart = Self.sshString("SSH-2.0-client".utf8) + Self.sshString("SSH-2.0-server".utf8)

        let clientInit = Array(
            client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator()).publicKey.readableBytesView
        )
        let clientMLKEMKey = try MLKEM768.PublicKey(
            rawRepresentation: clientInit.prefix(MLKEM768X25519KeyExchange.mlkemPublicKeySize)
        )
        let clientX25519Key = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: clientInit.suffix(MLKEM768X25519KeyExchange.x25519PublicKeySize)
        )

        // The mpint and string encodings of K are the same unless K's first
        // byte has its high bit set (or is zero). So we keep making new server
        // keys until K's high bit is set, which happens about half the time.
        var k: [UInt8] = []
        var serverReply: [UInt8] = []
        for _ in 0..<64 {
            let serverX25519Key = Curve25519.KeyAgreement.PrivateKey()
            let encapsulation = try clientMLKEMKey.encapsulate()
            let x25519SharedSecret = try serverX25519Key.sharedSecretFromKeyAgreement(with: clientX25519Key)

            var hasher = SHA256()
            encapsulation.sharedSecret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
            x25519SharedSecret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
            k = Array(hasher.finalize())
            serverReply = Array(encapsulation.encapsulated) + Array(serverX25519Key.publicKey.rawRepresentation)

            if k[0] & 0x80 != 0 {
                break
            }
        }
        guard k[0] & 0x80 != 0 else {
            XCTFail("K's high bit was clear in all 64 tries")
            return
        }

        var hostKeyBlob = ByteBufferAllocator().buffer(capacity: 128)
        hostKeyBlob.writeSSHHostKey(serverHostKey.publicKey)

        // H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
        var exchangeHashInput = transcriptStart
        exchangeHashInput += Self.sshString(hostKeyBlob.readableBytesView)
        exchangeHashInput += Self.sshString(clientInit)
        exchangeHashInput += Self.sshString(serverReply)
        exchangeHashInput += Self.sshString(k)
        let exchangeHash = SHA256.hash(data: exchangeHashInput)

        let replyMessage = SSHMessage.KeyExchangeECDHReplyMessage(
            hostKey: serverHostKey.publicKey,
            publicKey: ByteBuffer(bytes: serverReply),
            signature: try serverHostKey.sign(digest: exchangeHash)
        )

        // If the client hashes K some other way, its H won't match ours, so the
        // client throws invalidExchangeHashSignature here.
        var initialExchangeBytes = ByteBuffer(bytes: transcriptStart)
        let clientKeys = try client.receiveServerKeyExchangePayload(
            serverKeyExchangeMessage: replyMessage,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: ByteBufferAllocator(),
            expectedKeySizes: keySizes
        )

        // RFC 4253 section 7.2: key = HASH(K || H || letter || session_id), with
        // K as a string again. The session ID is H, since this is the first key
        // exchange. AES-128-GCM's keys and IVs are 16 bytes or less, so the
        // first digest is always long enough.
        func expectedKey(_ letter: Unicode.Scalar, size: Int) -> [UInt8] {
            var hasher = SHA256()
            hasher.update(data: Self.sshString(k))
            hasher.update(data: Array(exchangeHash))
            hasher.update(data: [UInt8(ascii: letter)])
            hasher.update(data: Array(exchangeHash))
            return Array(hasher.finalize().prefix(size))
        }

        let keys = clientKeys.keys
        XCTAssertEqual(clientKeys.sessionID, ByteBuffer(bytes: exchangeHash))
        XCTAssertEqual(keys.initialOutboundIV, expectedKey("A", size: keySizes.ivSize))
        XCTAssertEqual(keys.initialInboundIV, expectedKey("B", size: keySizes.ivSize))
        XCTAssertEqual(
            keys.outboundEncryptionKey,
            SymmetricKey(data: expectedKey("C", size: keySizes.encryptionKeySize))
        )
        XCTAssertEqual(
            keys.inboundEncryptionKey,
            SymmetricKey(data: expectedKey("D", size: keySizes.encryptionKeySize))
        )
        XCTAssertEqual(keys.outboundMACKey, SymmetricKey(data: expectedKey("E", size: keySizes.macKeySize)))
        XCTAssertEqual(keys.inboundMACKey, SymmetricKey(data: expectedKey("F", size: keySizes.macKeySize)))
    }

    func testRejectsTruncatedClientInit() throws {
        var server = try MLKEM768X25519KeyExchange(
            ourRole: .mlkemTest_server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())
        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 4096)

        var shortPayload = ByteBufferAllocator().buffer(capacity: 100)
        shortPayload.writeBytes(repeatElement(UInt8(0), count: 100))
        let badMessage = SSHMessage.KeyExchangeECDHInitMessage(publicKey: shortPayload)

        XCTAssertThrowsError(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: badMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )
    }

    func testAlgorithmName() {
        XCTAssertEqual(MLKEM768X25519KeyExchange.keyExchangeAlgorithmNames, ["mlkem768x25519-sha256"])
    }
}

/// A copy of the role helpers in `ECKeyExchangeTests.swift`, which are
/// fileprivate to that file.
extension SSHConnectionRole {
    fileprivate static func mlkemTest_server(_ hostKeys: [NIOSSHPrivateKey]) -> SSHConnectionRole {
        .server(SSHServerConfiguration(hostKeys: hostKeys, userAuthDelegate: DenyAllServerAuthDelegate()))
    }

    fileprivate static var mlkemTest_client: SSHConnectionRole {
        .client(
            SSHClientConfiguration(
                userAuthDelegate: ExplodingAuthDelegate(),
                serverAuthDelegate: AcceptAllHostKeysDelegate()
            )
        )
    }
}
