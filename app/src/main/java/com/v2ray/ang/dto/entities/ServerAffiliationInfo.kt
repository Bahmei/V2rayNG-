package com.v2ray.ang.dto.entities

import java.io.Serializable

data class ServerAffiliationInfo(
    var testDelayMillis: Long = 0L,
    var downloadSpeedMbps: Double? = null,
    var uploadSpeedMbps: Double? = null,
    var pingMs: Long? = null,
    var jitterMs: Double? = null,
    var testTimestamp: Long = 0L,
    var testStatus: String? = null,
    var benchmarkServer: String? = null,
) : Serializable
