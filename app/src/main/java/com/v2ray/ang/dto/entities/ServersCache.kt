package com.v2ray.ang.dto.entities

data class ServersCache(
    val guid: String,
    val profile: ProfileItem,
    val testDelayMillis: Long = 0L,
    val downloadSpeedMbps: Double? = null,
    val uploadSpeedMbps: Double? = null,
    val pingMs: Long? = null,
    val jitterMs: Double? = null,
    val testStatus: String? = null,
    val testTimestamp: Long = 0L,
)
