package com.v2ray.ang.dto

sealed class RealPingEvent {

    /** Periodic progress update while the batch is still running. */
    data class Progress(val text: String) : RealPingEvent()

    /** A single server result is available. */
    data class Result(
        val guid: String,
        val delayMillis: Long,
        val downloadSpeedMbps: Double? = null,
        val uploadSpeedMbps: Double? = null,
        val pingMs: Long? = null,
        val jitterMs: Double? = null,
        val testStatus: String? = null,
    ) : RealPingEvent()

    /** The entire batch has finished or been cancelled. */
    data class Finish(val status: String) : RealPingEvent()
}
