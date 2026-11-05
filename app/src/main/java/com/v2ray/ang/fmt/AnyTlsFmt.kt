package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.enums.NetworkType
import com.v2ray.ang.extension.idnHost
import com.v2ray.ang.extension.nullIfBlank
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.Utils
import java.net.URI

object AnyTlsFmt : FmtBase() {

    /**
     * Parses an AnyTLS URI into a ProfileItem.
     * Supported formats:
     * - anytls://password@example.com:443?sni=example.com&insecure=1#remarks
     * - anytls://example.com:443?password=pass&sni=example.com#remarks
     */
    fun parse(str: String): ProfileItem {
        val config = ProfileItem.create(EConfigType.ANYTLS)

        val normalized = if (str.startsWith(AppConfig.ANYTLS, ignoreCase = true)) {
            "https://" + str.substring(AppConfig.ANYTLS.length)
        } else {
            str
        }

        val uri = URI(Utils.fixIllegalUrl(normalized))
        config.remarks = Utils.decodeURIComponent(uri.fragment.orEmpty()).ifEmpty { "AnyTLS" }
        config.server = uri.idnHost
        config.serverPort = (if (uri.port == -1) 443 else uri.port).toString()
        config.security = AppConfig.TLS
        config.network = NetworkType.TCP.type

        uri.userInfo?.let { info ->
            config.password = Utils.decodeURIComponent(info)
        }

        if (!uri.rawQuery.isNullOrEmpty()) {
            val queryParam = getQueryParam(uri)
            if (config.password.isNullOrEmpty()) {
                config.password = queryParam["password"] ?: queryParam["pass"]
            }
            config.sni = queryParam["sni"] ?: queryParam["peer"]
            config.alpn = queryParam["alpn"] ?: "anytls,h2,http/1.1"
            config.insecure = queryParam["insecure"] == "1" || queryParam["allowInsecure"].equals("true", true)
            config.host = queryParam["host"]
            config.path = queryParam["path"]
        } else {
            config.alpn = "anytls,h2,http/1.1"
        }

        if (config.sni.isNullOrBlank()) {
            config.sni = config.server
        }

        return config
    }

    /**
     * Converts a ProfileItem object to an AnyTLS URI string.
     */
    fun toUri(config: ProfileItem): String {
        val dicQuery = HashMap<String, String>()

        config.sni?.nullIfBlank()?.let { dicQuery["sni"] = it }
        config.alpn?.nullIfBlank()?.let { dicQuery["alpn"] = it }
        if (config.insecure == true) {
            dicQuery["insecure"] = "1"
        }

        val query = if (dicQuery.isNotEmpty()) {
            "?" + dicQuery.entries.joinToString("&") { "${it.key}=${Utils.encodeURIComponent(it.value)}" }
        } else ""

        val userPart = if (!config.password.isNullOrEmpty()) {
            "${Utils.encodeURIComponent(config.password.orEmpty())}@"
        } else ""

        val hostPort = "${Utils.getIpv6Address(HttpUtil.toIdnDomain(config.server.orEmpty()))}:${config.serverPort ?: "443"}"
        val fragment = if (config.remarks.isNotBlank()) "#${Utils.encodeURIComponent(config.remarks)}" else ""

        return "${AppConfig.ANYTLS}$userPart$hostPort$query$fragment"
    }
}
