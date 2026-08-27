package com.bouazza.paperkey.internal

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object PaperKeyCrypto {
    val HEADER_SIG = byteArrayOf('p'.code.toByte(), 'K'.code.toByte(), 0x09.toByte())
    const val KEY_SZ = 32
    const val NONCE_SZ = 12
    const val TAG_SZ = 16
    const val CTR_SZ = 3 + 12 + NONCE_SZ + TAG_SZ + KEY_SZ // 75 Bytes

    private val argon2 = Argon2Kt()
    private val random = SecureRandom()

    fun deriveKey(passphrase: ByteArray, nonce: ByteArray): ByteArray {
        val result = argon2.hash(
            mode = Argon2Mode.ARGON2_ID, // الأحرف كلها كبيرة (ARGON2_ID)
            passphrase = passphrase,
            salt = nonce,
            tCost = 3,                   // اسم المعامل الصحيح tCost
            mCostInKibibytes = 16384,    // 16 MiB
            parallelism = 4,
            hashLengthInBytes = KEY_SZ
        )
        return result.rawHash
    }

    fun encrypt(secretKey: ByteArray, passphraseBytes: ByteArray, nonce: ByteArray, metaBytes: ByteArray): ByteArray {
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

        return HEADER_SIG + metaBytes + nonce + tag + ciphertext
    }

    fun decrypt(container: ByteArray, passphraseBytes: ByteArray, nonce: ByteArray, metaBytes: ByteArray, tag: ByteArray, ciphertext: ByteArray): ByteArray {
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