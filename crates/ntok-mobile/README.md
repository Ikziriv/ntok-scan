# ntok-mobile

Android shell — a full-screen `WebView` pointed at a running `ntok-web`
instance. Not a Rust crate: this is a Gradle project and is intentionally
absent from the workspace `members` list.

The scanner never runs on the phone. Raw sockets need root (and are
impossible in the iOS sandbox), so all scanning stays on the machine
hosting `ntok-web`; the phone is the viewer/control surface.

## Point it at your server

`app/build.gradle.kts` builds the URL into `BuildConfig.NTOK_BASE_URL`.
Three ways to set it, in precedence order:

```sh
./gradlew assembleDebug -Pntok.baseUrl=http://192.168.1.50:3000   # CLI flag
```

```
# local.properties (gitignored)
ntok.baseUrl=http://192.168.1.50:3000
```

Default: `http://10.0.2.2:3000` — the emulator's alias for host loopback,
so `./gradlew installDebug` on an emulator Just Works against
`cargo run -p ntok-web` on the same machine.

On a physical phone, run the server reachable on the LAN:

```sh
HOST=0.0.0.0 cargo run -p ntok-web
# then use this machine's LAN IP as ntok.baseUrl
```

## Build & run

The Gradle wrapper is checked in (`gradlew` / `gradlew.bat`), JDK 17+
and the Android SDK are the only prerequisites.

- **CLI:** `./gradlew installDebug` with a device/emulator attached —
  Gradle itself is downloaded on first run.
- **Android Studio:** open this folder (`crates/ntok-mobile`), let it
  sync, Run → pick a device.
- **APK to sideload:** `./gradlew assembleDebug` →
  `app/build/outputs/apk/debug/app-debug.apk`

## What's wired up

- Login/session cookies — WebView keeps its own jar; sign in once inside
  the app.
- File upload — nmap XML import works (`onShowFileChooser`).
- Downloads — report/XML exports go to the system Downloads folder via
  `DownloadManager`, session cookie forwarded.
- Hardware back — walks WebView history instead of closing.
- `usesCleartextTraffic` is on so `http://<lan-ip>:3000` works; remove it
  from the manifest when you serve HTTPS only. Self-signed certs are
  rejected — use a real cert (the repo's `Caddyfile` covers this) or plain
  HTTP on a trusted LAN.

## Not included

- iOS — see `ios/` for the equivalent `WKWebView` shell (macOS + Xcode
  required).
- On-device scanning — dead end, see above.
- Push notifications, share target, widgets — add only if needed.
