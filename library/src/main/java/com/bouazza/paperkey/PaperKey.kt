package com.bouazza.paperkey

import com.bouazza.paperkey.internal.HexUtils
import com.bouazza.paperkey.internal.MetaPacker
import com.bouazza.paperkey.internal.PaperKeyCrypto
import java.io.File

class PaperKey private constructor(
    val info: PaperKeyInfo,
    private val rawContainer: ByteArray
) {
    companion object {

        @JvmStatic
        fun generate(keyId: String, passphrase: CharArray): PaperKey {
            require(keyId.isNotEmpty()) { "Key ID cannot be empty" }
            require(keyId.length <= 8) { "Key ID cannot exceed 8 characters" }

            val secretKey = PaperKeyCrypto.generateRandomBytes(PaperKeyCrypto.KEY_SZ)
            val nonce = PaperKeyCrypto.generateRandomBytes(PaperKeyCrypto.NONCE_SZ)
            val ts = System.currentTimeMillis() / 1000
            val metaBytes = MetaPacker.pack(keyId, ts)

            val passphraseBytes = String(passphrase).toByteArray(Charsets.UTF_8)
            val container = PaperKeyCrypto.encrypt(secretKey, passphraseBytes, nonce, metaBytes)

            val info = PaperKeyInfo(
                signature = HexUtils.encodeHex(PaperKeyCrypto.HEADER_SIG),
                keyId = keyId,
                timestamp = ts,
                containerSize = PaperKeyCrypto.CTR_SZ
            )

            return PaperKey(info, container)
        }

        @JvmStatic
        @Throws(PaperKeyException::class)
        fun open(file: File): PaperKey = open(file.readText(Charsets.US_ASCII))

        @JvmStatic
        @Throws(PaperKeyException::class)
        fun open(hexData: String): PaperKey {
            return try {
                open(HexUtils.decodeHex(hexData))
            } catch (e: IllegalArgumentException) {
                throw PaperKeyException("Invalid Hex text format", e)
            }
        }

        @JvmStatic
        @Throws(PaperKeyException::class)
        fun open(bytes: ByteArray): PaperKey {
            if (bytes.size != PaperKeyCrypto.CTR_SZ) {
                throw PaperKeyException("Invalid container size: ${bytes.size} bytes (Expected ${PaperKeyCrypto.CTR_SZ})")
            }
            
            val sig = bytes.copyOfRange(0, 3)
            if (!sig.contentEquals(PaperKeyCrypto.HEADER_SIG)) {
                throw PaperKeyException("Invalid PaperKey signature or unsupported version")
            }

            val payload = bytes.copyOfRange(0, bytes.size - 1)
            val checksumByte = bytes.last()
            if (PaperKeyCrypto.calcChecksum(payload) != checksumByte) {
                throw PaperKeyException("Container corruption detected (Checksum Mismatch)!")
            }

            val (keyId, ts) = try {
                MetaPacker.unpack(bytes.copyOfRange(3, 14))
            } catch (e: Exception) {
                throw PaperKeyException("Corrupted metadata header", e)
            }

            val info = PaperKeyInfo(
                signature = HexUtils.encodeHex(sig),
                keyId = keyId,
                timestamp = ts,
                containerSize = bytes.size
            )

            return PaperKey(info, bytes)
        }
    }

    fun toHex(): String = HexUtils.formatPrettyHex(rawContainer)

    fun toByteArray(): ByteArray = rawContainer.clone()

    fun saveTo(file: File) {
        file.writeText(toHex(), Charsets.US_ASCII)
    }

    fun decrypt(
        passphrase: CharArray,
        onSuccess: (secretKey: ByteArray) -> Unit,
        onFailed: (error: PaperKeyException) -> Unit
    ) {
        try {
            val metaBytes = rawContainer.copyOfRange(3, 14)
            val nonce = rawContainer.copyOfRange(14, 26)
            val tag = rawContainer.copyOfRange(26, 42)
            val ciphertext = rawContainer.copyOfRange(42, 74)

            val passphraseBytes = String(passphrase).toByteArray(Charsets.UTF_8)
            val secretKey = PaperKeyCrypto.decrypt(
                rawContainer,
                passphraseBytes,
                nonce,
                metaBytes,
                tag,
                ciphertext
            )

            onSuccess(secretKey)
        } catch (e: Exception) {
            onFailed(PaperKeyException("Decryption failed: Incorrect passphrase or corrupted data", e))
        }
    }
}