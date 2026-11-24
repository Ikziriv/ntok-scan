# ntok-mobile — iOS shell

Same role as the Android shell: a full-screen `WKWebView` pointed at a
running `ntok-web` instance. One Swift file — needs macOS + Xcode.

## Setup

1. Xcode → File → New → Project → iOS → **App**.
   - Product Name: `NTOK SCAN`
   - Bundle ID: `com.ntokscan.app` (matches the Tauri identifier)
   - Interface: SwiftUI, Language: Swift
2. Delete the generated `ContentView.swift` and the default `@main` app
   file; drop `NtokMobileApp.swift` (this folder) into the project instead.
3. Set your server URL in `WebScreen.baseURL`.
4. Drag `fonts/Inter.ttf` + `fonts/WorkSans.ttf` into the project (check
   **Copy items if needed**, target membership on) and merge the
   `UIAppFonts` key from `Info.plist.snippet.xml`. Without them the shell
   falls back to system fonts.
5. For `http://` LAN targets, add the ATS key from
   `Info.plist.snippet.xml` (target → Info → Custom iOS Target Properties,
   or paste into Info.plist). Skip it for HTTPS.
6. Run on a device. `cargo run -p ntok-web` won't be reachable unless the
   host binds the LAN — use `HOST=0.0.0.0`.

## What works out of the box

JS + localStorage + cookies are on by default in WKWebView; swipe-back is
enabled via `allowsBackForwardNavigationGestures`; `<input type=file>`
opens the native file picker.

## Known gaps

- Downloads that arrive as `Content-Disposition: attachment` need a
  `WKNavigationDelegate` + `WKDownloadDelegate` — add only if report
  exports are used from iOS.
- App Store: a bare-webview app risks rejection under guideline 4.2
  (minimum functionality). Personal/enterprise sideloading is unaffected.
