package com.bouazza.paperkey.internal

import java.nio.ByteBuffer
import java.nio.ByteOrder

internal object MetaPacker {
    private const val CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val CHAR_MAP = CHARSET.withIndex().associate { it.value to it.index }

    fun pack(keyId: String, ts: Long): ByteArray {
        require(keyId.length <= 10) { "Key ID cannot exceed 10 characters" }
        require(ts in 0 until (1L shl 36)) { "Timestamp out of 36-bit range" }

        val padded = keyId.padEnd(10, CHARSET[0])
        var idBits = 0L
        for (c in padded) {
            val idx = CHAR_MAP[c] ?: throw IllegalArgumentException("Invalid character in Key ID: $c")
            idBits = (idBits shl 6) or idx.toLong()
        }

        val combined = (idBits shl 36) or (ts and ((1L shl 36) - 1))
        val buffer = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        buffer.putShort((combined ushr 80).toShort())
        buffer.putLong((combined ushr 16))
        buffer.putShort(combined.toShort())
        return buffer.array()
    }

    fun unpack(data: ByteArray): Pair<String, Long> {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val high = buffer.short.toLong() and 0xFFFFL
        val mid = buffer.long
        val low = buffer.short.toLong() and 0xFFFFL
        val combined = (high shl 80) or (mid shl 16) or low

        val ts = combined and ((1L shl 36) - 1)
        val idBits = combined ushr 36

        val chars = CharArray(10) { i ->
            val shift = (9 - i) * 6
            val idx = ((idBits ushr shift) and 0x3FL).toInt()
            CHARSET[idx]
        }
        val keyId = String(chars).trimEnd(CHARSET[0])
        return Pair(keyId, ts)
    }
}