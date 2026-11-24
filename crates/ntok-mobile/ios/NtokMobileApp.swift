import SwiftUI
import WebKit

// Native iOS shell: a full-screen WKWebView over a running ntok-web instance.
// Scanning stays on the host machine — raw sockets are impossible in
// the iOS sandbox, so the phone is the viewer/control surface only.

@main
struct NtokMobileApp: App {
    @AppStorage("ntok_base_url") private var baseURLString: String = "http://192.168.1.50:3000"
    @State private var activeTheme: String = "paper"
    @State private var loadError: String? = nil
    @State private var isLoading: Bool = true
    @State private var reloadToken: UUID = UUID()
    @State private var draftURL: String = ""

    private var surfaceColor: Color {
        switch activeTheme {
        case "night": return Color(red: 0.024, green: 0.039, blue: 0.071)    // #060A12
        case "terminal": return Color(red: 0.012, green: 0.020, blue: 0.039) // #03050A
        default: return Color(red: 0.953, green: 0.965, blue: 0.980)         // #F3F6FA
        }
    }

    private var preferredScheme: ColorScheme {
        activeTheme == "paper" ? .light : .dark
    }

    var body: some Scene {
        WindowGroup {
            ZStack(alignment: .top) {
                surfaceColor.ignoresSafeArea()

                if let url = URL(string: baseURLString) {
                    WebScreen(
                        url: url,
                        reloadToken: reloadToken,
                        onThemeChanged: { theme in activeTheme = theme },
                        onLoadingChanged: { loading in isLoading = loading },
                        onError: { err in loadError = err }
                    )
                    .ignoresSafeArea(.container, edges: .bottom)
                }

                if isLoading {
                    ProgressView()
                        .progressViewStyle(.linear)
                        .tint(Color(red: 0.271, green: 0.769, blue: 0.925)) // #45C4EC
                }

                if let err = loadError {
                    offlineOverlay(message: err)
                }
            }
            .preferredColorScheme(preferredScheme)
            .onAppear { draftURL = baseURLString }
        }
    }

    @ViewBuilder
    private func offlineOverlay(message: String) -> some View {
        VStack(spacing: 14) {
            Text("NTOK SCAN · OFFLINE")
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundColor(Color(red: 0.271, green: 0.769, blue: 0.925))
                .padding(.horizontal, 12)
                .padding(.vertical, 5)
                .background(Color(red: 0.075, green: 0.157, blue: 0.239))
                .clipShape(Capsule())

            Text("Scanner host unreachable")
                .font(.custom("Inter", size: 22).weight(.bold))
                .foregroundColor(Color(red: 0.941, green: 0.965, blue: 1.0))

            Text(message)
                .font(.custom("Work Sans", size: 12))
                .foregroundColor(Color(red: 0.494, green: 0.584, blue: 0.714))
                .multilineTextAlignment(.center)
                .padding(.horizontal, 12)

            TextField("http://192.168.1.50:3000", text: $draftURL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .font(.system(size: 14, design: .monospaced))
                .padding(12)
                .background(Color(red: 0.067, green: 0.110, blue: 0.188))
                .foregroundColor(.white)
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(red: 0.157, green: 0.239, blue: 0.376), lineWidth: 1)
                )

            Button(action: {
                let trimmed = draftURL.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
                    baseURLString = trimmed
                    loadError = nil
                    reloadToken = UUID()
                }
            }) {
                Text("Connect & Retry")
                    .font(.custom("Work Sans", size: 14).weight(.bold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
                    .background(Color(red: 0.271, green: 0.769, blue: 0.925))
                    .foregroundColor(Color(red: 0.016, green: 0.075, blue: 0.110))
                    .clipShape(Capsule())
            }
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(red: 0.043, green: 0.071, blue: 0.125).ignoresSafeArea())
    }
}

struct WebScreen: UIViewRepresentable {
    let url: URL
    let reloadToken: UUID
    let onThemeChanged: (String) -> Void
    let onLoadingChanged: (Bool) -> Void
    let onError: (String?) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> WKWebView {
        let contentController = WKUserContentController()
        contentController.add(context.coordinator, name: "ntokTheme")

        let config = WKWebViewConfiguration()
        config.userContentController = contentController
        config.applicationNameForUserAgent = "NtokMobile/1.0"

        let web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = context.coordinator
        web.allowsBackForwardNavigationGestures = true
        web.isOpaque = false
        web.backgroundColor = .clear

        let refresh = UIRefreshControl()
        refresh.addTarget(
            context.coordinator,
            action: #selector(Coordinator.handleRefresh(_:)),
            for: .valueChanged
        )
        web.scrollView.refreshControl = refresh

        context.coordinator.webView = web
        context.coordinator.lastReloadToken = reloadToken
        web.load(URLRequest(url: url))
        return web
    }

    func updateUIView(_ web: WKWebView, context: Context) {
        if context.coordinator.lastReloadToken != reloadToken {
            context.coordinator.lastReloadToken = reloadToken
            web.load(URLRequest(url: url))
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        private let parent: WebScreen
        weak var webView: WKWebView?
        var lastReloadToken: UUID = UUID()

        init(_ parent: WebScreen) {
            self.parent = parent
        }

        @objc func handleRefresh(_ sender: UIRefreshControl) {
            webView?.reload()
            sender.endRefreshing()
        }

        func userContentController(
            _ userContentController: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            if message.name == "ntokTheme", let mode = message.body as? String {
                DispatchQueue.main.async { self.parent.onThemeChanged(mode) }
            }
        }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            DispatchQueue.main.async {
                self.parent.onError(nil)
                self.parent.onLoadingChanged(true)
            }
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            DispatchQueue.main.async {
                self.parent.onLoadingChanged(false)
            }
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            DispatchQueue.main.async {
                self.parent.onLoadingChanged(false)
                self.parent.onError("Could not reach \(self.parent.url.absoluteString)\n\(error.localizedDescription)")
            }
        }
    }
}
