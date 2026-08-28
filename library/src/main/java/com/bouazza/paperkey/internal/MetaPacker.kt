package com.bouazza.paperkey.internal

internal object MetaPacker {
    private const val CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val CHAR_MAP = CHARSET.withIndex().associate { it.value to it.index }

    fun pack(keyId: String, ts: Long): ByteArray {
        require(keyId.length <= 8) { "Key ID cannot exceed 8 characters" }
        require(ts >= 0 && ts < (1L shl 40)) { "Timestamp out of 40-bit range" }

        val padded = keyId.padEnd(8, CHARSET[0])
        var idBits = 0L
        for (c in padded) {
            val idx = CHAR_MAP[c] ?: throw IllegalArgumentException("Invalid character in Key ID: $c")
            idBits = (idBits shl 6) or idx.toLong()
        }

        val result = ByteArray(11)

        for (i in 0 until 6) {
            val shift = (5 - i) * 8
            result[i] = ((idBits ushr shift) and 0xFFL).toByte()
        }

        for (i in 0 until 5) {
            val shift = (4 - i) * 8
            result[6 + i] = ((ts ushr shift) and 0xFFL).toByte()
        }

        return result
    }

    fun unpack(data: ByteArray): Pair<String, Long> {
        require(data.size == 11) { "Invalid metadata length: ${data.size} (expected 11)" }

        var idBits = 0L
        for (i in 0 until 6) {
            idBits = (idBits shl 8) or (data[i].toLong() and 0xFFL)
        }

        val chars = CharArray(8) { i ->
            val shift = (7 - i) * 6
            val idx = ((idBits ushr shift) and 0x3FL).toInt()
            CHARSET[idx]
        }

        var ts = 0L
        for (i in 6 until 11) {
            ts = (ts shl 8) or (data[i].toLong() and 0xFFL)
        }

        val parsedId = String(chars).trimEnd(CHARSET[0])
        val keyId = if (parsedId.isEmpty()) CHARSET[0].toString() else parsedId

        return Pair(keyId, ts)
    }
}