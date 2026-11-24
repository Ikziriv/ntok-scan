package com.ntokscan.app

import android.annotation.SuppressLint
import android.app.Activity
import android.app.DownloadManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowInsetsController
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.URLUtil
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView

// Native Android shell over a running ntok-web instance.
// The scanner itself never runs on the phone — raw sockets need root,
// so all privileged scans stay on the machine hosting ntok-web.
class MainActivity : Activity() {

    private lateinit var root: FrameLayout
    private lateinit var web: WebView
    private lateinit var progressBar: ProgressBar
    private lateinit var errorOverlay: LinearLayout
    private lateinit var errorDetail: TextView
    private lateinit var urlInput: EditText
    private var fileCallback: ValueCallback<Array<Uri>>? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        applySystemBars("paper")

        root = FrameLayout(this).apply {
            setBackgroundColor(Color.parseColor("#0B1220"))
        }

        web = WebView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT,
            )
            setBackgroundColor(Color.parseColor("#F3F6FA"))
            settings.javaScriptEnabled = true // htmx UI needs JS
            settings.domStorageEnabled = true // theme choice persists via localStorage
            settings.userAgentString = "${settings.userAgentString} NtokMobile/1.0"
            addJavascriptInterface(ThemeBridge(), "NtokAndroid")
        }

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                dp(3),
                Gravity.TOP,
            )
            max = 100
            visibility = View.GONE
            progressDrawable?.setTint(Color.parseColor("#45C4EC"))
        }

        errorOverlay = buildErrorOverlay()

        root.addView(web)
        root.addView(progressBar)
        root.addView(errorOverlay)
        setContentView(root)

        web.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                progressBar.visibility = View.GONE
            }

            override fun onReceivedError(
                view: WebView,
                request: WebResourceRequest,
                error: WebResourceError,
            ) {
                if (request.isForMainFrame) {
                    val desc = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        error.description?.toString() ?: "Unable to reach host"
                    } else {
                        "Unable to reach host"
                    }
                    showError("Could not reach ${currentBaseUrl()}\n$desc")
                }
            }
        }

        web.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                if (newProgress in 1..99) {
                    progressBar.visibility = View.VISIBLE
                    progressBar.progress = newProgress
                } else {
                    progressBar.visibility = View.GONE
                }
            }

            // nmap XML import — <input type=file>
            override fun onShowFileChooser(
                view: WebView,
                callback: ValueCallback<Array<Uri>>,
                params: FileChooserParams,
            ): Boolean {
                fileCallback?.onReceiveValue(null)
                fileCallback = callback
                startActivityForResult(params.createIntent(), REQ_FILE)
                return true
            }
        }

        // report/XML exports — hand to DownloadManager, forward the session cookie
        web.setDownloadListener { url, _, disposition, mime, _ ->
            val req = DownloadManager.Request(Uri.parse(url))
                .addRequestHeader("Cookie", CookieManager.getInstance().getCookie(url))
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                .setDestinationInExternalPublicDir(
                    Environment.DIRECTORY_DOWNLOADS,
                    URLUtil.guessFileName(url, disposition, mime),
                )
            (getSystemService(DOWNLOAD_SERVICE) as DownloadManager).enqueue(req)
        }

        loadConfiguredUrl()
    }

    private fun currentBaseUrl(): String {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        return prefs.getString(KEY_BASE_URL, null)
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?: BuildConfig.NTOK_BASE_URL
    }

    private fun saveBaseUrl(url: String) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putString(KEY_BASE_URL, url.trim())
            .apply()
    }

    private fun loadConfiguredUrl() {
        val url = currentBaseUrl()
        urlInput.setText(url)
        errorOverlay.visibility = View.GONE
        progressBar.visibility = View.VISIBLE
        web.loadUrl(url)
    }

    private fun showError(message: String) {
        progressBar.visibility = View.GONE
        errorDetail.text = message
        urlInput.setText(currentBaseUrl())
        errorOverlay.visibility = View.VISIBLE
        applySystemBars("night")
    }

    private fun buildErrorOverlay(): LinearLayout {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#0B1220"))
            setPadding(dp(28), dp(28), dp(28), dp(28))
            visibility = View.GONE
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT,
            )
        }

        val badge = TextView(this).apply {
            text = "NTOK SCAN · OFFLINE"
            setTextColor(Color.parseColor("#45C4EC"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            typeface = Typeface.MONOSPACE
            setPadding(dp(12), dp(5), dp(12), dp(5))
            background = pillDrawable(Color.parseColor("#13283D"), Color.parseColor("#2A5C7A"), dp(999))
        }

        val title = TextView(this).apply {
            text = "Scanner host unreachable"
            setTextColor(Color.parseColor("#F0F6FF"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            typeface = bundledFont(R.font.inter, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(0, dp(16), 0, dp(8))
        }

        errorDetail = TextView(this).apply {
            setTextColor(Color.parseColor("#7E95B6"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dp(20))
        }

        urlInput = EditText(this).apply {
            hint = "http://192.168.1.50:3000"
            setHintTextColor(Color.parseColor("#4E6484"))
            setTextColor(Color.parseColor("#F0F6FF"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            typeface = Typeface.MONOSPACE
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            isSingleLine = true
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = pillDrawable(Color.parseColor("#111C30"), Color.parseColor("#283D60"), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { bottomMargin = dp(12) }
        }

        val connectBtn = Button(this).apply {
            text = "Connect & Retry"
            isAllCaps = false
            setTextColor(Color.parseColor("#04131C"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            typeface = bundledFont(R.font.worksans, Typeface.BOLD)
            background = pillDrawable(Color.parseColor("#45C4EC"), Color.parseColor("#45C4EC"), dp(999))
            setPadding(dp(20), dp(12), dp(20), dp(12))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
            setOnClickListener {
                val entered = urlInput.text.toString().trim()
                if (entered.startsWith("http://") || entered.startsWith("https://")) {
                    saveBaseUrl(entered)
                    loadConfiguredUrl()
                } else {
                    errorDetail.text = "Enter a valid http:// or https:// ntok-web URL."
                }
            }
        }

        container.addView(badge)
        container.addView(title)
        container.addView(errorDetail)
        container.addView(urlInput)
        container.addView(connectBtn)
        return container
    }

    private fun pillDrawable(fill: Int, stroke: Int, radiusPx: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(fill)
            setStroke(dp(1), stroke)
            cornerRadius = radiusPx.toFloat()
        }

    // res/font TTFs resolve natively on API 26+; older devices keep the
    // system stack, matching the web fallback chain.
    private fun bundledFont(resId: Int, style: Int): Typeface =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            runCatching { Typeface.create(resources.getFont(resId)!!, style) }
                .getOrDefault(Typeface.create(Typeface.SANS_SERIF, style))
        } else {
            Typeface.create(Typeface.SANS_SERIF, style)
        }

    private fun applySystemBars(viewMode: String) {
        val (bgHex, lightIcons) = when (viewMode) {
            "night" -> "#060A12" to false
            "terminal" -> "#03050A" to false
            else -> "#F3F6FA" to true
        }
        val color = Color.parseColor(bgHex)
        @Suppress("DEPRECATION")
        window.statusBarColor = color
        @Suppress("DEPRECATION")
        window.navigationBarColor = color
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val flags = if (lightIcons) {
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                    WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            } else {
                0
            }
            window.insetsController?.setSystemBarsAppearance(
                flags,
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                    WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            @Suppress("DEPRECATION")
            val vis = window.decorView.systemUiVisibility
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = if (lightIcons) {
                vis or View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
            } else {
                vis and View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR.inv()
            }
        }
    }

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            value.toFloat(),
            resources.displayMetrics,
        ).toInt()

    private inner class ThemeBridge {
        @JavascriptInterface
        fun onThemeChanged(viewMode: String) {
            runOnUiThread { applySystemBars(viewMode) }
        }
    }

    @Deprecated("deprecated API; simplest that works for this shell")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQ_FILE) {
            fileCallback?.onReceiveValue(
                if (resultCode == RESULT_OK) {
                    WebChromeClient.FileChooserParams.parseResult(resultCode, data)
                } else {
                    null
                },
            )
            fileCallback = null
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    @Deprecated("plain Activity has no OnBackPressedDispatcher; fine for a single-webview shell")
    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }

    override fun onDestroy() {
        web.destroy()
        super.onDestroy()
    }

    private companion object {
        const val REQ_FILE = 1
        const val PREFS_NAME = "ntok_mobile_prefs"
        const val KEY_BASE_URL = "base_url"
    }
}
