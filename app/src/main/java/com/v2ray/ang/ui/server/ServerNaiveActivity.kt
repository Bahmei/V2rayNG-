package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.ui.compose.FormDropdownField
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem

class ServerNaiveActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.NAIVE

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(
                initialConfig = initialConfig
            )
        }.apply {
            configType = EConfigType.NAIVE
            if (port.isBlank() || port == "10808") {
                port = "443"
            }
            if (network.isBlank() || network == "tcp") {
                network = "https"
            }
        }

        ServerEditorScaffold(
            title = stringResource(R.string.title_sub_naive),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            NaiveProtocolFields(uiState)
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean {
        if (config.server.isNullOrBlank() || config.serverPort.isNullOrBlank()) {
            return false
        }
        if (config.security.isNullOrBlank()) {
            config.security = AppConfig.TLS
        }
        if (config.sni.isNullOrBlank()) {
            config.sni = config.server
        }
        return true
    }

    @Composable
    private fun NaiveProtocolFields(state: ServerUiState) {
        FormTextField(
            label = stringResource(R.string.server_lab_username),
            value = state.username,
            onValueChange = { state.username = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_id3),
            value = state.password,
            onValueChange = { state.password = it }
        )
        FormDropdownField(
            label = stringResource(R.string.server_lab_network),
            value = state.network,
            options = listOf("https", "quic"),
            onValueChange = { state.network = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_sni),
            value = state.sni,
            onValueChange = { state.sni = it }
        )
        FormTextField(
            label = stringResource(R.string.server_lab_stream_alpn),
            value = state.alpn,
            onValueChange = { state.alpn = it }
        )
        SettingsSwitchItem(
            title = stringResource(R.string.server_lab_allow_insecure),
            checked = state.allowInsecure,
            onCheckedChange = { state.allowInsecure = it }
        )
    }
}
