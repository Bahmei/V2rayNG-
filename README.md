# v2rayNG for Android

A modern Android client for V2Ray / Xray proxy protocols built with Kotlin and Jetpack Compose.

## Features

- **Protocol Support**: VMess, VLESS, Shadowsocks, Trojan, Socks, HTTP, WireGuard, Hysteria2, Custom configs, and Proxy Chains.
- **Modern Jetpack Compose UI**: Edge-to-edge Material 3 interface with dynamic theming and light/dark modes.
- **Subscription Management**: Import and update subscription links, group servers, and parse traffic usage.
- **Routing Rules**: Bypass LAN and mainland China, global proxy, direct rulesets, and per-app proxy configuration.
- **Latency & Speed Testing**: Real delay measurement, ICMP/TCP ping testing, and speed testing.
- **QR Code & Clipboard Import/Export**: Scan QR codes with camera or gallery images, and import/export links from/to the clipboard.
- **Backup & Restore**: Local file backup/restore and WebDAV cloud synchronization.
- **Service & Quick Settings**: Android VpnService integration with status notification and Quick Settings tile.

## Architecture

- **Language**: Kotlin 2.4 / Jetpack Compose
- **Build System**: Gradle 9.3.1 with Kotlin DSL
- **Architecture**: MVVM with Kotlin Coroutines and StateFlow
- **Storage**: MMKV fast key-value persistence
- **Networking**: OkHttp 5 + Coroutines

## Building

```bash
gradle assembleDebug
```

The APK will be generated at `app/build/outputs/apk/debug/app-debug.apk`.
