package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.extension.nullIfBlank
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.Utils
import java.net.URI

object NaiveFmt : FmtBase() {

    /**
     * Parses a NaïveProxy URI into a ProfileItem.
     * Supported formats:
     * - naive+https://user:password@example.com:443?padding=true#remarks
     * - naive://user:password@example.com:443#remarks
     * - naive+quic://user:password@example.com:443#remarks
     */
    fun parse(str: String): ProfileItem {
        val config = ProfileItem.create(EConfigType.NAIVE)

        val isQuic = str.startsWith(AppConfig.NAIVE_QUIC, ignoreCase = true)
        val normalized = when {
            str.startsWith(AppConfig.NAIVE, ignoreCase = true) -> "https://" + str.substring(AppConfig.NAIVE.length)
            str.startsWith(AppConfig.NAIVE_QUIC, ignoreCase = true) -> "https://" + str.substring(AppConfig.NAIVE_QUIC.length)
            str.startsWith(AppConfig.NAIVE_ALT, ignoreCase = true) -> "https://" + str.substring(AppConfig.NAIVE_ALT.length)
            else -> str
        }

        val uri = URI(Utils.fixIllegalUrl(normalized))
        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).ifEmpty { "NaïveProxy" }
        config.server = uri.idnHost
        config.serverPort = (if (uri.port == -1) 443 else uri.port).toString()
        config.security = AppConfig.TLS
        config.network = if (isQuic) "quic" else "https"

        uri.userInfo?.let { info ->
            val decoded = Utils.decodeURIComponent(info)
            if (decoded.contains(":")) {
                config.username = decoded.substringBefore(":")
                config.password = decoded.substringAfter(":")
            } else {
                config.username = decoded
                config.password = ""
            }
        }

        if (!uri.rawQuery.isNullOrEmpty()) {
            val queryParam = getQueryParam(uri)
            config.sni = queryParam["sni"] ?: queryParam["peer"]
            config.alpn = queryParam["alpn"] ?: if (isQuic) "h3" else "h2,http/1.1"
            config.insecure = queryParam["insecure"] == "1" || queryParam["allowInsecure"].equals("true", true)
            config.host = queryParam["host"]
            config.path = queryParam["path"]
        } else {
            config.alpn = if (isQuic) "h3" else "h2,http/1.1"
        }

        if (config.sni.isNullOrBlank()) {
            config.sni = config.server
        }

        return config
    }

    /**
     * Converts a ProfileItem object to a NaïveProxy URI string.
     */
    fun toUri(config: ProfileItem): String {
        val dicQuery = HashMap<String, String>()

        config.sni?.nullIfBlank()?.let { dicQuery["sni"] = it }
        config.alpn?.nullIfBlank()?.let { dicQuery["alpn"] = it }
        if (config.insecure == true) {
            dicQuery["insecure"] = "1"
        }
        dicQuery["padding"] = "true"

        val query = if (dicQuery.isNotEmpty()) {
            "?" + dicQuery.entries.joinToString("&") { "${it.key}=${Utils.encodeURIComponent(it.value)}" }
        } else ""

        val scheme = if (config.network.equals("quic", ignoreCase = true)) {
            AppConfig.NAIVE_QUIC
        } else {
            AppConfig.NAIVE
        }

        val userPart = if (!config.username.isNullOrEmpty() || !config.password.isNullOrEmpty()) {
            "${Utils.encodeURIComponent(config.username.orEmpty())}:${Utils.encodeURIComponent(config.password.orEmpty())}@"
        } else ""

        val hostPort = "${Utils.getIpv6Address(HttpUtil.toIdnDomain(config.server.orEmpty()))}:${config.serverPort ?: "443"}"
        val fragment = if (config.remarks.isNotBlank()) "#${Utils.encodeURIComponent(config.remarks)}" else ""

        return "$scheme$userPart$hostPort$query$fragment"
    }
}
