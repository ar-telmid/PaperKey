package com.bouazza.paperkey.internal

internal object HexUtils {
    fun encodeHex(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it) }

    fun decodeHex(text: String): ByteArray {
        val clean = text.replace("\\s".toRegex(), "")
        if (clean.isEmpty() || clean.length % 2 != 0) {
            throw IllegalArgumentException("Invalid Hex string format")
        }
        return clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    fun formatPrettyHex(data: ByteArray): String {
        return data.toList().chunked(15).joinToString("\n") { row ->
            row.joinToString(" ") { "%02X".format(it) }
        }
    }
}