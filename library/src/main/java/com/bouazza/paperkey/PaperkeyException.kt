package com.bouazza.paperkey

class PaperKeyException @JvmOverloads constructor(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)