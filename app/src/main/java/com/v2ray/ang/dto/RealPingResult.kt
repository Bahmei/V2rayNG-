package com.v2ray.ang.dto

import java.io.Serializable

data class RealPingResult(
    val guid: String,
    val delayMillis: Long,
    val downloadSpeedMbps: Double? = null,
    val uploadSpeedMbps: Double? = null,
    val pingMs: Long? = null,
    val jitterMs: Double? = null,
    val testStatus: String? = null,
) : Serializable
