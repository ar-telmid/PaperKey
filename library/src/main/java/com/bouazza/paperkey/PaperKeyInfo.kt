package com.bouazza.paperkey

data class PaperKeyInfo(
    val signature: String,
    val keyId: String,
    val timestamp: Long,
    val containerSize: Int
)