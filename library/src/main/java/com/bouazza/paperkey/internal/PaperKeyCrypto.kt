package com.bouazza.paperkey.internal

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.Argon2Version
import java.security.SecureRandom
import java.util.zip.CRC32
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object PaperKeyCrypto {
    val HEADER_SIG = byteArrayOf('p'.code.toByte(), 'K'.code.toByte(), 0x0A.toByte())
    
    const val KEY_SZ = 32
    const val NONCE_SZ = 12
    const val TAG_SZ = 16
    const val META_SZ = 11

    const val CTR_SZ = 3 + META_SZ + NONCE_SZ + TAG_SZ + KEY_SZ + 1 // 75 Bytes

    private val argon2 = Argon2Kt()
    private val random = SecureRandom()

    fun calcChecksum(payload: ByteArray): Byte {
        val crc = CRC32()
        crc.update(payload)
        return (crc.value and 0xFFL).toByte()
    }

    fun deriveKey(passphrase: ByteArray, nonce: ByteArray): ByteArray {
        val result = argon2.hash(
            mode = Argon2Mode.ARGON2_ID,
            version = Argon2Version.V13,
            password = passphrase,
            salt = nonce,
            tCostInIterations = 3,
            mCostInKibibyte = 16384,
            parallelism = 4,
            hashLengthInBytes = KEY_SZ
        )
        return result.rawHashAsByteArray()
    }

    fun encrypt(secretKey: ByteArray, passphraseBytes: ByteArray, nonce: ByteArray, metaBytes: ByteArray): ByteArray {
        require(metaBytes.size == META_SZ) { "Meta bytes size must be $META_SZ bytes" }

        val aesKeyBytes = deriveKey(passphraseBytes, nonce)
        val aad = HEADER_SIG + metaBytes + nonce

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKeySpec = SecretKeySpec(aesKeyBytes, "AES")
        val gcmSpec = GCMParameterSpec(TAG_SZ * 8, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec)
        cipher.updateAAD(aad)
        val encryptedWithTag = cipher.doFinal(secretKey)

        val ciphertext = encryptedWithTag.copyOfRange(0, encryptedWithTag.size - TAG_SZ)
        val tag = encryptedWithTag.copyOfRange(encryptedWithTag.size - TAG_SZ, encryptedWithTag.size)

        val payload = HEADER_SIG + metaBytes + nonce + tag + ciphertext
        val checksum = calcChecksum(payload)
        return payload + byteArrayOf(checksum)
    }

    fun decrypt(container: ByteArray, passphraseBytes: ByteArray, nonce: ByteArray, metaBytes: ByteArray, tag: ByteArray, ciphertext: ByteArray): ByteArray {
        require(container.size == CTR_SZ) { "Invalid container size: ${container.size} (expected $CTR_SZ)" }
        require(metaBytes.size == META_SZ) { "Meta bytes size must be $META_SZ bytes" }

        val payload = container.copyOfRange(0, container.size - 1)
        val checksumByte = container.last()

        if (calcChecksum(payload) != checksumByte) {
            throw IllegalArgumentException("Container corruption detected (Checksum Mismatch)!")
        }

        val aesKeyBytes = deriveKey(passphraseBytes, nonce)
        val aad = HEADER_SIG + metaBytes + nonce

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKeySpec = SecretKeySpec(aesKeyBytes, "AES")
        val gcmSpec = GCMParameterSpec(TAG_SZ * 8, nonce)

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec)
        cipher.updateAAD(aad)

        val cipherInput = ciphertext + tag
        return cipher.doFinal(cipherInput)
    }

    fun generateRandomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }
}