package com.bouazza.paperkey.internal

internal object MetaPacker {
    // 63 حرفاً فقط (الفهارس الفعالة من 1 إلى 63)
    private const val CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
    
    // خريطة سريعة تعتمد على ASCII مباشرة (تُرجع -1 إذا كان الحرف غير مدعوم)
    private val CHAR_TO_INDEX = IntArray(128) { -1 }.apply {
        for (i in CHARSET.indices) {
            this[CHARSET[i].code] = i + 1 // النقل بمقدار +1 لتسجيل الأحرف من 1 إلى 63
        }
    }

    fun pack(keyId: String, ts: Long): ByteArray {
        require(keyId.isNotEmpty()) { "Key ID cannot be empty" }
        require(keyId.length <= 8) { "Key ID cannot exceed 8 characters" }
        require(ts in 0 until (1L shl 40)) { "Timestamp out of 40-bit range" }

        var idBits = 0L
        
        // معالجة الأحرف الموجودة
        for (c in keyId) {
            val code = c.code
            val idx = if (code in 0..127) CHAR_TO_INDEX[code] else -1
            require(idx != -1) { "Invalid character in Key ID: $c" }
            idBits = (idBits shl 6) or idx.toLong()
        }

        // الحشو بـ 0 للخانة/الخانات المتبقية ليصل الإجمالي إلى 8 خانات (6 بت لكل خانة)
        val remainingChars = 8 - keyId.length
        if (remainingChars > 0) {
            idBits = idBits shl (remainingChars * 6)
        }

        val result = ByteArray(11)

        // تحويل 48 بت الخاصة بالـ Key ID إلى 6 بايتات
        for (i in 0 until 6) {
            val shift = (5 - i) * 8
            result[i] = (idBits ushr shift).toByte()
        }

        // تحويل 40 بت الخاصة بالـ Timestamp إلى 5 بايتات
        for (i in 0 until 5) {
            val shift = (4 - i) * 8
            result[6 + i] = (ts ushr shift).toByte()
        }

        return result
    }

    fun unpack(data: ByteArray): Pair<String, Long> {
        require(data.size == 11) { "Invalid metadata length: ${data.size} (expected 11)" }

        // استخراج 48 بت الخاصة بالـ Key ID
        var idBits = 0L
        for (i in 0 until 6) {
            idBits = (idBits shl 8) or (data[i].toLong() and 0xFFL)
        }

        // تفكيك 8 خانات (كل خانة 6 بت)
        val builder = StringBuilder(8)
        for (i in 0 until 8) {
            val shift = (7 - i) * 6
            val idx = ((idBits ushr shift) and 0x3FL).toInt()
            
            if (idx > 0) {
                // الفهرس ينقص بمقدار 1 للحصول على الحرف الصحيح من CHARSET
                builder.append(CHARSET[idx - 1])
            } else {
                // عند الوصول إلى 0 (الحشو) تتوقف قراءة باقي الحروف
                break
            }
        }

        // استخراج 40 بت الخاصة بالـ Timestamp
        var ts = 0L
        for (i in 6 until 11) {
            ts = (ts shl 8) or (data[i].toLong() and 0xFFL)
        }

        return Pair(builder.toString(), ts)
    }
}