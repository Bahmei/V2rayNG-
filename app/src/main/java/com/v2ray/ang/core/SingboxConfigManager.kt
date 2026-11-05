package com.v2ray.ang.core

import android.content.Context
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.ConfigResult
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil

/**
 * Generates sing-box JSON configuration for all supported protocols,
 * with primary focus on NaïveProxy (naive) and AnyTLS (anytls).
 */
object SingboxConfigManager {

    /**
     * Builds complete sing-box configuration for the given server GUID.
     */
    fun getSingboxConfig(context: Context, guid: String): ConfigResult {
        try {
            val profile = MmkvManager.decodeServerConfig(guid)
                ?: return ConfigResult(status = false, guid = guid, errorMessage = "Profile not found")

            val json = buildConfigJson(profile, forSpeedtest = false)
            val pretty = JsonUtil.toJsonPretty(json) ?: json.toString()
            return ConfigResult(status = true, guid = guid, content = pretty)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to generate sing-box config", e)
            return ConfigResult(status = false, guid = guid, errorMessage = e.message ?: "Failed to generate sing-box config")
        }
    }

    /**
     * Builds lightweight sing-box configuration for latency/throughput testing.
     */
    fun getSingboxConfig4Speedtest(context: Context, guid: String): ConfigResult {
        try {
            val profile = MmkvManager.decodeServerConfig(guid)
                ?: return ConfigResult(status = false, guid = guid, errorMessage = "Profile not found")

            val json = buildConfigJson(profile, forSpeedtest = true)
            val pretty = JsonUtil.toJsonPretty(json) ?: json.toString()
            return ConfigResult(status = true, guid = guid, content = pretty)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to generate sing-box speedtest config", e)
            return ConfigResult(status = false, guid = guid, errorMessage = e.message ?: "Failed to generate sing-box speedtest config")
        }
    }

    private fun buildConfigJson(profile: ProfileItem, forSpeedtest: Boolean): JsonObject {
        val root = JsonObject()

        // 1. Log block
        val logObj = JsonObject().apply {
            addProperty("disabled", false)
            addProperty("level", if (forSpeedtest) "warn" else (MmkvManager.decodeSettingsString(AppConfig.PREF_LOGLEVEL) ?: "warn"))
            addProperty("timestamp", true)
        }
        root.add("log", logObj)

        // 2. DNS block
        val dnsObj = JsonObject().apply {
            val servers = JsonArray()

            val remoteDns = JsonObject().apply {
                addProperty("tag", "dns-remote")
                addProperty("address", "https://1.1.1.1/dns-query")
                addProperty("address_resolver", "dns-direct")
                addProperty("strategy", "prefer_ipv4")
            }
            servers.add(remoteDns)

            val directDns = JsonObject().apply {
                addProperty("tag", "dns-direct")
                addProperty("address", "local")
                addProperty("detour", "direct")
            }
            servers.add(directDns)

            val blockDns = JsonObject().apply {
                addProperty("tag", "dns-block")
                addProperty("address", "rcode://success")
            }
            servers.add(blockDns)

            add("servers", servers)

            val rules = JsonArray()
            val ruleDirect = JsonObject().apply {
                addProperty("outbound", "any")
                addProperty("server", "dns-direct")
            }
            rules.add(ruleDirect)
            add("rules", rules)

            addProperty("final", "dns-remote")
            addProperty("strategy", "prefer_ipv4")
        }
        root.add("dns", dnsObj)

        // 3. Inbounds block
        val inbounds = JsonArray()
        if (!forSpeedtest && needTun()) {
            val tunObj = JsonObject().apply {
                addProperty("type", "tun")
                addProperty("tag", "tun-in")
                addProperty("interface_name", "tun0")
                addProperty("inet4_address", "172.19.0.1/30")
                addProperty("auto_route", true)
                addProperty("strict_route", true)
                addProperty("stack", "mixed")
                addProperty("sniff", true)
                addProperty("mtu", SettingsManager.getVpnMtu())
            }
            inbounds.add(tunObj)
        }

        val mixedObj = JsonObject().apply {
            addProperty("type", "mixed")
            addProperty("tag", "mixed-in")
            addProperty("listen", AppConfig.LOOPBACK)
            addProperty("listen_port", SettingsManager.getSocksPort())
            addProperty("sniff", true)
        }
        inbounds.add(mixedObj)
        root.add("inbounds", inbounds)

        // 4. Outbounds block
        val outbounds = JsonArray()
        val proxyOutbound = buildOutbound(profile)
        outbounds.add(proxyOutbound)

        val directObj = JsonObject().apply {
            addProperty("type", "direct")
            addProperty("tag", "direct")
        }
        outbounds.add(directObj)

        val bypassObj = JsonObject().apply {
            addProperty("type", "direct")
            addProperty("tag", "bypass")
        }
        outbounds.add(bypassObj)

        val blockObj = JsonObject().apply {
            addProperty("type", "block")
            addProperty("tag", "block")
        }
        outbounds.add(blockObj)

        val dnsOutObj = JsonObject().apply {
            addProperty("type", "dns")
            addProperty("tag", "dns-out")
        }
        outbounds.add(dnsOutObj)
        root.add("outbounds", outbounds)

        // 5. Route block
        val routeObj = JsonObject().apply {
            addProperty("auto_detect_interface", true)
            val routeRules = JsonArray()

            val dnsRule = JsonObject().apply {
                addProperty("protocol", "dns")
                addProperty("outbound", "dns-out")
            }
            routeRules.add(dnsRule)

            val privateRule = JsonObject().apply {
                addProperty("ip_is_private", true)
                addProperty("outbound", "direct")
            }
            routeRules.add(privateRule)

            add("rules", routeRules)
            addProperty("final", "proxy")
        }
        root.add("route", routeObj)

        return root
    }

    private fun needTun(): Boolean {
        return MmkvManager.decodeSettingsBool(AppConfig.PREF_PROXY_ONLY, false) == false
    }

    private fun buildOutbound(profile: ProfileItem): JsonObject {
        return when (profile.configType) {
            EConfigType.NAIVE -> buildNaiveOutbound(profile)
            EConfigType.ANYTLS -> buildAnyTlsOutbound(profile)
            EConfigType.HYSTERIA2 -> buildHysteria2Outbound(profile)
            EConfigType.TROJAN -> buildTrojanOutbound(profile)
            EConfigType.VLESS -> buildVlessOutbound(profile)
            EConfigType.VMESS -> buildVmessOutbound(profile)
            EConfigType.SHADOWSOCKS -> buildShadowsocksOutbound(profile)
            EConfigType.SOCKS -> buildSocksOutbound(profile)
            EConfigType.HTTP -> buildHttpOutbound(profile)
            EConfigType.WIREGUARD -> buildWireguardOutbound(profile)
            else -> buildNaiveOutbound(profile)
        }
    }

    private fun buildNaiveOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "naive")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 443)
        obj.addProperty("username", profile.username.orEmpty())
        obj.addProperty("password", profile.password.orEmpty())

        val isQuic = profile.network.equals("quic", ignoreCase = true)
        obj.addProperty("network", if (isQuic) "udp" else "tcp")

        val tlsObj = JsonObject().apply {
            addProperty("enabled", true)
            val sni = if (!profile.sni.isNullOrBlank()) profile.sni else profile.server.orEmpty()
            addProperty("server_name", sni)
            addProperty("insecure", profile.insecure == true)

            val alpnArray = JsonArray()
            if (isQuic) {
                alpnArray.add("h3")
            } else {
                val alpnList = profile.alpn?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
                if (!alpnList.isNullOrEmpty()) {
                    alpnList.forEach { alpnArray.add(it) }
                } else {
                    alpnArray.add("h2")
                    alpnArray.add("http/1.1")
                }
            }
            add("alpn", alpnArray)
        }
        obj.add("tls", tlsObj)

        return obj
    }

    private fun buildAnyTlsOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "anytls")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 443)
        obj.addProperty("password", profile.password.orEmpty())

        val tlsObj = JsonObject().apply {
            addProperty("enabled", true)
            val sni = if (!profile.sni.isNullOrBlank()) profile.sni else profile.server.orEmpty()
            addProperty("server_name", sni)
            addProperty("insecure", profile.insecure == true)

            val alpnArray = JsonArray()
            val alpnList = profile.alpn?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
            if (!alpnList.isNullOrEmpty()) {
                alpnList.forEach { alpnArray.add(it) }
            } else {
                alpnArray.add("anytls")
                alpnArray.add("h2")
                alpnArray.add("http/1.1")
            }
            add("alpn", alpnArray)
        }
        obj.add("tls", tlsObj)

        return obj
    }

    private fun buildHysteria2Outbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "hysteria2")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 443)
        obj.addProperty("password", profile.password.orEmpty())

        if (!profile.obfsPassword.isNullOrBlank()) {
            val obfsObj = JsonObject().apply {
                addProperty("type", "salamander")
                addProperty("password", profile.obfsPassword)
            }
            obj.add("obfs", obfsObj)
        }

        val tlsObj = JsonObject().apply {
            addProperty("enabled", true)
            addProperty("server_name", if (!profile.sni.isNullOrBlank()) profile.sni else profile.server.orEmpty())
            addProperty("insecure", profile.insecure == true)
        }
        obj.add("tls", tlsObj)
        return obj
    }

    private fun buildTrojanOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "trojan")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 443)
        obj.addProperty("password", profile.password.orEmpty())

        val tlsObj = JsonObject().apply {
            addProperty("enabled", true)
            addProperty("server_name", if (!profile.sni.isNullOrBlank()) profile.sni else profile.server.orEmpty())
            addProperty("insecure", profile.insecure == true)
        }
        obj.add("tls", tlsObj)
        return obj
    }

    private fun buildVlessOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "vless")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 443)
        obj.addProperty("uuid", profile.password.orEmpty())
        if (!profile.flow.isNullOrBlank()) {
            obj.addProperty("flow", profile.flow)
        }

        if (profile.security.equals("tls", true) || profile.security.equals("reality", true)) {
            val tlsObj = JsonObject().apply {
                addProperty("enabled", true)
                addProperty("server_name", if (!profile.sni.isNullOrBlank()) profile.sni else profile.server.orEmpty())
                addProperty("insecure", profile.insecure == true)
            }
            obj.add("tls", tlsObj)
        }
        return obj
    }

    private fun buildVmessOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "vmess")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 443)
        obj.addProperty("uuid", profile.password.orEmpty())
        obj.addProperty("security", profile.method ?: "auto")
        return obj
    }

    private fun buildShadowsocksOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "shadowsocks")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 8388)
        obj.addProperty("method", profile.method ?: "aes-128-gcm")
        obj.addProperty("password", profile.password.orEmpty())
        return obj
    }

    private fun buildSocksOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "socks")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 1080)
        if (!profile.username.isNullOrBlank()) {
            obj.addProperty("username", profile.username)
            obj.addProperty("password", profile.password.orEmpty())
        }
        return obj
    }

    private fun buildHttpOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "http")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 80)
        if (!profile.username.isNullOrBlank()) {
            obj.addProperty("username", profile.username)
            obj.addProperty("password", profile.password.orEmpty())
        }
        return obj
    }

    private fun buildWireguardOutbound(profile: ProfileItem): JsonObject {
        val obj = JsonObject()
        obj.addProperty("type", "wireguard")
        obj.addProperty("tag", "proxy")
        obj.addProperty("server", profile.server.orEmpty())
        obj.addProperty("server_port", profile.serverPort?.toIntOrNull() ?: 51820)
        obj.addProperty("private_key", profile.secretKey.orEmpty())
        obj.addProperty("peer_public_key", profile.publicKey.orEmpty())
        return obj
    }
}
