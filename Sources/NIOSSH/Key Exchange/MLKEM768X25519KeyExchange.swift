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
import NIOFoundationCompat

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Post-quantum hybrid key exchange: ML-KEM-768 (FIPS 203) with X25519.
///
/// The wire format and the key derivation follow OpenSSH 9.9's
/// `mlkem768x25519-sha256` and the IETF draft
/// `draft-kampanakis-curdle-ssh-pq-ke`:
///
///   * The client's init payload is one SSH string: the ML-KEM-768
///     encapsulation key (1184 bytes), then the X25519 public key (32 bytes).
///   * The server's reply payload is one SSH string: the ML-KEM-768
///     ciphertext (1088 bytes), then the X25519 public key (32 bytes).
///   * The shared secret is `K = SHA-256(MLKEM_SS || X25519_SS)`. It's
///     encoded as an SSH `string`, not as an `mpint` the way the ECDH
///     methods encode it. OpenSSH does the same in `kexmlkem768x25519.c`.
///   * The exchange hash is SHA-256.
///
/// `K` is a hash of both shared secrets: an attacker who breaks only one
/// of ML-KEM and X25519 still can't recover the session keys. ML-KEM is
/// there for quantum resistance, and X25519 is a well-studied classical
/// method. OpenSSH 9.9 combines them the same way (and this is an
/// intentional copy of that model).
///
/// > Important: We don't make the ephemeral keys in `init`, because
/// > `MLKEM768.PrivateKey.init` can throw and
/// > `EllipticCurveKeyExchangeProtocol.init` can't. We make them in
/// > `initiateKeyExchangeClientSide(allocator:)` on the client and in
/// > `completeKeyExchangeServerSide(...)` on the server.
@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
struct MLKEM768X25519KeyExchange: EllipticCurveKeyExchangeProtocol {
    /// Size in bytes of an ML-KEM-768 encapsulation (public) key (FIPS 203, section 8)
    static let mlkemPublicKeySize = 1184

    /// Size in bytes of an ML-KEM-768 ciphertext (FIPS 203, section 8)
    static let mlkemCiphertextSize = 1088

    /// Size in bytes of an X25519 public key (RFC 7748, section 6.1)
    static let x25519PublicKeySize = 32

    private var previousSessionIdentifier: ByteBuffer?
    private var ourRole: SSHConnectionRole

    // The client's ephemeral keys, made in initiateKeyExchangeClientSide
    private var clientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var clientMLKEMPrivateKey: MLKEM768.PrivateKey?

    // The server's ephemeral key, made in completeKeyExchangeServerSide
    private var serverX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey?

    // K, the SHA-256 digest of (MLKEM_SS || X25519_SS). We keep it as raw
    // bytes because it goes into the exchange hash as a `string`.
    private var sharedSecretDigest: [UInt8]?

    // Both payloads go into the exchange hash exactly as they were sent, so
    // we keep them until we compute the hash.
    private var clientInitPayload: ByteBuffer?
    private var serverReplyPayload: ByteBuffer?

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
    }

    static var keyExchangeAlgorithmNames: [Substring] {
        ["mlkem768x25519-sha256"]
    }

    // MARK: - Client side

    mutating func initiateKeyExchangeClientSide(
        allocator: ByteBufferAllocator
    ) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")

        // MLKEM768.PrivateKey() can throw, but this method can't, so we crash
        // if making the key fails. We don't expect that to happen. A later
        // change to the protocol could let this method throw instead.
        let x25519PrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let mlkemPrivateKey: MLKEM768.PrivateKey
        do {
            mlkemPrivateKey = try MLKEM768.PrivateKey()
        } catch {
            preconditionFailure("MLKEM768 keypair generation failed: \(error)")
        }

        self.clientX25519PrivateKey = x25519PrivateKey
        self.clientMLKEMPrivateKey = mlkemPrivateKey

        var payload = allocator.buffer(capacity: Self.mlkemPublicKeySize + Self.x25519PublicKeySize)
        payload.writeBytes(mlkemPrivateKey.publicKey.rawRepresentation)
        payload.writeBytes(x25519PrivateKey.publicKey.rawRepresentation)

        self.clientInitPayload = payload
        return .init(publicKey: payload)
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        precondition(self.ourRole.isClient, "Only clients may receive a server key exchange packet!")

        guard
            let clientX25519PrivateKey = self.clientX25519PrivateKey,
            let clientMLKEMPrivateKey = self.clientMLKEMPrivateKey,
            let clientInitPayload = self.clientInitPayload
        else {
            preconditionFailure("receiveServerKeyExchangePayload called before initiateKeyExchangeClientSide")
        }

        var replyBytes = message.publicKey
        guard replyBytes.readableBytes == Self.mlkemCiphertextSize + Self.x25519PublicKeySize else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        self.serverReplyPayload = replyBytes

        guard
            let mlkemCiphertext = replyBytes.readBytes(length: Self.mlkemCiphertextSize),
            let serverX25519PublicKeyBytes = replyBytes.readBytes(length: Self.x25519PublicKeySize)
        else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        let mlkemSharedSecret = try clientMLKEMPrivateKey.decapsulate(mlkemCiphertext)
        let serverX25519PublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: serverX25519PublicKeyBytes
        )
        let x25519SharedSecret = try clientX25519PrivateKey.sharedSecretFromKeyAgreement(
            with: serverX25519PublicKey
        )

        self.deriveHybridSharedSecret(
            mlkemSharedSecret: mlkemSharedSecret,
            x25519SharedSecret: x25519SharedSecret
        )

        let (kexResult, exchangeHash) = self.finalizeKeyExchange(
            clientInitPayload: clientInitPayload,
            serverReplyPayload: self.serverReplyPayload!,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: message.hostKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        guard message.hostKey.isValidSignature(message.signature, for: exchangeHash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }

        return kexResult
    }

    // MARK: - Server side

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        precondition(self.ourRole.isServer, "Only servers may receive a client key exchange packet!")

        var initBytes = message.publicKey
        guard initBytes.readableBytes == Self.mlkemPublicKeySize + Self.x25519PublicKeySize else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }
        self.clientInitPayload = initBytes

        guard
            let mlkemPublicKeyBytes = initBytes.readBytes(length: Self.mlkemPublicKeySize),
            let clientX25519PublicKeyBytes = initBytes.readBytes(length: Self.x25519PublicKeySize)
        else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        let serverX25519PrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.serverX25519PrivateKey = serverX25519PrivateKey

        let mlkemPublicKey = try MLKEM768.PublicKey(rawRepresentation: mlkemPublicKeyBytes)
        let encapsulation = try mlkemPublicKey.encapsulate()
        let mlkemSharedSecret = encapsulation.sharedSecret
        let mlkemCiphertext = encapsulation.encapsulated

        let clientX25519PublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: clientX25519PublicKeyBytes
        )
        let x25519SharedSecret = try serverX25519PrivateKey.sharedSecretFromKeyAgreement(
            with: clientX25519PublicKey
        )

        self.deriveHybridSharedSecret(
            mlkemSharedSecret: mlkemSharedSecret,
            x25519SharedSecret: x25519SharedSecret
        )

        guard mlkemCiphertext.count == Self.mlkemCiphertextSize else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        var replyPayload = allocator.buffer(capacity: Self.mlkemCiphertextSize + Self.x25519PublicKeySize)
        replyPayload.writeBytes(mlkemCiphertext)
        replyPayload.writeBytes(serverX25519PrivateKey.publicKey.rawRepresentation)
        self.serverReplyPayload = replyPayload

        let (kexResult, exchangeHash) = self.finalizeKeyExchange(
            clientInitPayload: self.clientInitPayload!,
            serverReplyPayload: replyPayload,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: serverHostKey.publicKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        let exchangeHashSignature = try serverHostKey.sign(digest: exchangeHash)
        let responseMessage = SSHMessage.KeyExchangeECDHReplyMessage(
            hostKey: serverHostKey.publicKey,
            publicKey: replyPayload,
            signature: exchangeHashSignature
        )

        return (kexResult, responseMessage)
    }

    // MARK: - Hybrid secret derivation

    /// Sets `K` to `SHA-256(MLKEM_SS || X25519_SS)`. Per the IETF draft,
    /// hashing the two secrets avoids domain separation problems. It also
    /// gives `K` a fixed length, so the key derivation after it works the same
    /// as in the other SHA-256 key exchange methods.
    private mutating func deriveHybridSharedSecret(
        mlkemSharedSecret: SymmetricKey,
        x25519SharedSecret: SharedSecret
    ) {
        var hasher = SHA256()
        mlkemSharedSecret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        x25519SharedSecret.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        self.sharedSecretDigest = Array(hasher.finalize())
    }

    // MARK: - Exchange hash and session keys

    private func finalizeKeyExchange(
        clientInitPayload: ByteBuffer,
        serverReplyPayload: ByteBuffer,
        initialExchangeBytes: inout ByteBuffer,
        serverHostKey: NIOSSHPublicKey,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) -> (KeyExchangeResult, SHA256.Digest) {
        guard let sharedSecretDigest = self.sharedSecretDigest else {
            preconditionFailure("finalizeKeyExchange called before deriveHybridSharedSecret")
        }

        initialExchangeBytes.writeCompositeSSHString {
            $0.writeSSHHostKey(serverHostKey)
        }

        // Both sides hash the client's init payload, then the server's reply.
        // That's the order in the IETF draft and in OpenSSH 9.9.
        var initPayloadCopy = clientInitPayload
        var replyPayloadCopy = serverReplyPayload
        initialExchangeBytes.writeCompositeSSHString { $0.writeBuffer(&initPayloadCopy) }
        initialExchangeBytes.writeCompositeSSHString { $0.writeBuffer(&replyPayloadCopy) }

        var hasher = SHA256()
        hasher.update(data: initialExchangeBytes.readableBytesView)
        Self.updateAsSSHString(&hasher, sharedSecretDigest: sharedSecretDigest)

        let exchangeHash = hasher.finalize()

        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: SHA256.Digest.byteCount)
            hashBytes.writeContiguousBytes(exchangeHash)
            sessionID = hashBytes
        }

        let keys = self.generateKeys(
            sharedSecretDigest: sharedSecretDigest,
            exchangeHash: exchangeHash,
            sessionID: sessionID,
            expectedKeySizes: expectedKeySizes
        )

        return (KeyExchangeResult(sessionID: sessionID, keys: keys), exchangeHash)
    }

    /// For this method `K` goes into the exchange hash and the key
    /// derivation as an SSH `string`: a 4-byte big-endian length (always 32
    /// here), then the digest bytes as they are. Unlike an `mpint`, there's
    /// no leading zero added when the high bit is set and no leading zeros
    /// stripped. If we encoded it as an `mpint`, we'd only match OpenSSH when
    /// the digest's first byte is nonzero with its high bit clear. About half
    /// of all connections to OpenSSH would fail with
    /// `invalidExchangeHashSignature`.
    ///
    /// https://github.com/openssh/openssh-portable/blob/ebdaacf4907033af1cbf1fef593436081dcd67a7/kexmlkem768x25519.c#L152-L156
    private static func updateAsSSHString(_ hasher: inout SHA256, sharedSecretDigest: [UInt8]) {
        var lengthBE = UInt32(sharedSecretDigest.count).bigEndian
        withUnsafeBytes(of: &lengthBE) { hasher.update(bufferPointer: $0) }
        hasher.update(data: sharedSecretDigest)
    }

    /// Derives the six session keys (an IV, an encryption key and a MAC key
    /// for each direction) from `K`, `H` and the session ID. This is RFC 4253
    /// section 7.2 with `HASH = SHA-256`.
    private func generateKeys(
        sharedSecretDigest: [UInt8],
        exchangeHash: SHA256.Digest,
        sessionID: ByteBuffer,
        expectedKeySizes: ExpectedKeySizes
    ) -> NIOSSHSessionKeys {
        func deriveKey(letter: UInt8, expectedSize: Int) -> [UInt8] {
            // K1 = HASH(K || H || letter || session_id)
            var hasher = SHA256()
            Self.updateAsSSHString(&hasher, sharedSecretDigest: sharedSecretDigest)
            exchangeHash.withUnsafeBytes { hasher.update(bufferPointer: $0) }
            hasher.update(data: [letter])
            hasher.update(data: sessionID.readableBytesView)
            var out = Array(hasher.finalize())
            // K2 = HASH(K || H || K1); K3 = HASH(K || H || K1 || K2); ...
            while out.count < expectedSize {
                var extend = SHA256()
                Self.updateAsSSHString(&extend, sharedSecretDigest: sharedSecretDigest)
                exchangeHash.withUnsafeBytes { extend.update(bufferPointer: $0) }
                extend.update(data: out)
                out.append(contentsOf: extend.finalize())
            }
            return Array(out.prefix(expectedSize))
        }

        let ivCToS = deriveKey(letter: UInt8(ascii: "A"), expectedSize: expectedKeySizes.ivSize)
        let ivSToC = deriveKey(letter: UInt8(ascii: "B"), expectedSize: expectedKeySizes.ivSize)
        let encCToS = deriveKey(letter: UInt8(ascii: "C"), expectedSize: expectedKeySizes.encryptionKeySize)
        let encSToC = deriveKey(letter: UInt8(ascii: "D"), expectedSize: expectedKeySizes.encryptionKeySize)
        let macCToS = deriveKey(letter: UInt8(ascii: "E"), expectedSize: expectedKeySizes.macKeySize)
        let macSToC = deriveKey(letter: UInt8(ascii: "F"), expectedSize: expectedKeySizes.macKeySize)

        switch self.ourRole {
        case .client:
            return NIOSSHSessionKeys(
                initialInboundIV: ivSToC,
                initialOutboundIV: ivCToS,
                inboundEncryptionKey: SymmetricKey(data: encSToC),
                outboundEncryptionKey: SymmetricKey(data: encCToS),
                inboundMACKey: SymmetricKey(data: macSToC),
                outboundMACKey: SymmetricKey(data: macCToS)
            )
        case .server:
            return NIOSSHSessionKeys(
                initialInboundIV: ivCToS,
                initialOutboundIV: ivSToC,
                inboundEncryptionKey: SymmetricKey(data: encCToS),
                outboundEncryptionKey: SymmetricKey(data: encSToC),
                inboundMACKey: SymmetricKey(data: macCToS),
                outboundMACKey: SymmetricKey(data: macSToC)
            )
        }
    }
}
