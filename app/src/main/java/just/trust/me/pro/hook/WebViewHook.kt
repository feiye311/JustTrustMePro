package just.trust.me.pro.hook

import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.WebView
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import just.trust.me.pro.util.SSLUtils
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class WebViewHook : BaseHook() {
    private val hookedClasses = mutableSetOf<String>()

    override fun initHook(lpparam: LoadPackageParam) {
        hookWebViewClient(lpparam)
        hookX5SystemWebViewClientError(lpparam)
        hookX5WebViewClientSslError(lpparam)
        hookSmartSslErrors(lpparam)

        // Native层 hook
        hookConscryptForWebView(lpparam)
        hookChromiumSSLLayer(lpparam)
        hookTrustManagerForWebView(lpparam)
        hookOpenSSLSocket(lpparam)
        hookX509TrustManagerExtensions(lpparam)
    }

    private fun hookWebViewClient(lpparam: LoadPackageParam) {
        tryHook("WebViewClient.onReceivedSslError") {
            XposedHelpers.findAndHookMethod(
                "android.webkit.WebViewClient",
                lpparam.classLoader,
                "onReceivedSslError",
                WebView::class.java,
                SslErrorHandler::class.java,
                SslError::class.java,
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        (param.args[1] as SslErrorHandler).proceed()
                        return null
                    }
                }
            )
        }

        tryHook("WebViewClient.onReceivedError") {
            XposedHelpers.findAndHookMethod(
                "android.webkit.WebViewClient",
                lpparam.classLoader,
                "onReceivedError",
                WebView::class.java,
                Int::class.javaPrimitiveType,
                String::class.java,
                String::class.java,
                XC_MethodReplacement.DO_NOTHING
            )
        }
    }

    private fun hookX5SystemWebViewClientError(lpparam: LoadPackageParam) {
        val hasSystemWebViewClient =
            isClassExists("com.tencent.smtt.sdk.SystemWebViewClient", lpparam)
        val hasAndroidWebView = isClassExists("android.webkit.WebView", lpparam)
        if (hasSystemWebViewClient && hasAndroidWebView) {
            tryHook("X5SystemWebViewClient.onReceivedError(android.webkit.WebView,int,String,String)") {
                XposedHelpers.findAndHookMethod(
                    "com.tencent.smtt.sdk.SystemWebViewClient",
                    lpparam.classLoader,
                    "onReceivedError",
                    lpparam.classLoader.loadClass("android.webkit.WebView"),
                    Int::class.javaPrimitiveType,
                    String::class.java,
                    String::class.java,
                    object : XC_MethodReplacement() {
                        override fun replaceHookedMethod(param: MethodHookParam): Any? {
                            val handler = param.args[1]
                            handler.javaClass.getMethod("proceed").invoke(handler)
                            return null
                        }
                    }
                )
            }

            val hasWebResourceRequest = isClassExists("android.webkit.WebResourceRequest", lpparam)
            val hasWebResourceError = isClassExists("android.webkit.WebResourceError", lpparam)
            if (hasWebResourceRequest && hasWebResourceError) {
                tryHook("X5SystemWebViewClient.onReceivedError(android.webkit.WebView,WebResourceRequest,WebResourceError)") {
                    XposedHelpers.findAndHookMethod(
                        "com.tencent.smtt.sdk.SystemWebViewClient",
                        lpparam.classLoader,
                        "onReceivedError",
                        lpparam.classLoader.loadClass("android.webkit.WebView"),
                        lpparam.classLoader.loadClass("android.webkit.WebResourceRequest"),
                        lpparam.classLoader.loadClass("android.webkit.WebResourceError"),
                        object : XC_MethodReplacement() {
                            override fun replaceHookedMethod(param: MethodHookParam): Any? {
                                val handler = param.args[1]
                                handler.javaClass.getMethod("proceed").invoke(handler)
                                return null
                            }
                        }
                    )
                }
            }
        }
    }

    private fun hookX5WebViewClientSslError(lpparam: LoadPackageParam) {
        if (!isClassExists("com.tencent.smtt.sdk.WebViewClient", lpparam)
            && !isClassExists("com.tencent.smtt.sdk.WebView", lpparam)
            && !isClassExists(
                "com.tencent.smtt.export.external.interfaces.SslErrorHandler",
                lpparam
            )
            && !isClassExists("com.tencent.smtt.export.external.interfaces.SslError", lpparam)
        ) {
            return
        }
        tryHook("X5WebViewClient.onReceivedSslError") {
            XposedHelpers.findAndHookMethod(
                "com.tencent.smtt.sdk.WebViewClient",
                lpparam.classLoader,
                "onReceivedSslError",
                lpparam.classLoader.loadClass("com.tencent.smtt.sdk.WebView"),
                lpparam.classLoader.loadClass("com.tencent.smtt.export.external.interfaces.SslErrorHandler"),
                lpparam.classLoader.loadClass("com.tencent.smtt.export.external.interfaces.SslError"),
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        val handler = param.args[1]
                        handler.javaClass.getMethod("proceed").invoke(handler)
                        return null
                    }
                }
            )
        }
    }

    private fun hookSmartSslErrors(lpparam: LoadPackageParam) {
        if (!isClassExists("com.tencent.smtt.sdk.WebViewClient", lpparam)) {
            return
        }

        val targets = SSLUtils.getSmartSslHookTargets(lpparam.packageName)

        for (targetClass in targets) {
            if (isClassExists(targetClass, lpparam)) {
                tryHook("SmartSslErrors.hookTargetClass: $targetClass", false) {
                    val clazz = Class.forName(targetClass, false, lpparam.classLoader)

                    if (clazz.isInterface) {
                        return@tryHook
                    }

                    for (method in clazz.declaredMethods) {
                        if (method.name == "onReceivedSslError" && method.parameterTypes.size == 3) {
                            hookSslErrorMethodSmart(clazz.name, method, lpparam)
                        }
                    }
                }
            }
        }

        val classNames = SSLUtils.allClassNamesFromClassLoader(lpparam.classLoader)
        if (classNames.isNotEmpty()) {
            for (className in classNames) {
                if (className.contains("webview", ignoreCase = true) ||
                    className.contains("webclient", ignoreCase = true) ||
                    className.contains("ssl", ignoreCase = true) ||
                    className.contains("web", ignoreCase = true)
                ) {
                    tryHook("SmartSslErrors.hookScannedClass: $className", false) {
                        val clazz = Class.forName(className, false, lpparam.classLoader)

                        if (clazz.isInterface) {
                            return@tryHook
                        }

                        for (method in clazz.declaredMethods) {
                            if (method.name == "onReceivedSslError" && method.parameterTypes.size == 3) {
                                hookSslErrorMethodSmart(clazz.name, method, lpparam)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun hookSslErrorMethodSmart(
        className: String,
        method: java.lang.reflect.Method,
        lpparam: LoadPackageParam
    ) {
        if (java.lang.reflect.Modifier.isAbstract(method.modifiers)) {
            return
        }

        val clazz = try {
            Class.forName(className, false, lpparam.classLoader)
        } catch (e: Throwable) {
            return
        }

        if (clazz.isInterface) {
            return
        }

        val paramTypes = method.parameterTypes

        tryHook("SmartSslErrors.hookMethod: $className.onReceivedSslError", false) {
            XposedHelpers.findAndHookMethod(
                className,
                lpparam.classLoader,
                "onReceivedSslError",
                paramTypes[0],
                paramTypes[1],
                paramTypes[2],
                object : XC_MethodReplacement() {
                    override fun replaceHookedMethod(param: MethodHookParam): Any? {
                        val handler = param.args[1]

                        val continueMethodNames =
                            listOf("proceed", "continueLoad", "continue", "ignore")

                        for (methodName in continueMethodNames) {
                            try {
                                handler.javaClass.getMethod(methodName).invoke(handler)
                                return null
                            } catch (_: Throwable) {
                            }
                        }

                        return null
                    }
                }
            )
        }
    }

    // ========== Native层 Hook ==========

    private fun hookConscryptForWebView(lpparam: LoadPackageParam) {
        // Hook Conscrypt 的 TrustManagerImpl (Android 7.0+ WebView使用)
        val conscryptClasses = listOf(
            "com.android.org.conscrypt.TrustManagerImpl",
            "com.android.org.conscrypt.ConscryptEngine",
            "com.android.org.conscrypt.ConscryptEngineSocket",
            "com.android.org.conscrypt.OpenSSLSocketImpl"
        )

        for (className in conscryptClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("ConscryptWebView.hookCheckServerTrusted: $className") {
                val clazz = lpparam.classLoader.loadClass(className)
                clazz.declaredMethods
                    .filter { it.name == "checkServerTrusted" }
                    .forEach { method ->
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    // 不做任何验证，直接返回
                                    val returnType = method.returnType
                                    if (returnType == Void.TYPE || returnType == Void::class.javaPrimitiveType) {
                                        param.result = null
                                    } else if (returnType == List::class.java || returnType == java.util.List::class.java) {
                                        param.result = ArrayList<X509Certificate>()
                                    } else if (returnType == Array<X509Certificate>::class.java) {
                                        param.result = arrayOf<X509Certificate>()
                                    }
                                }
                            })
                        } catch (_: Throwable) {
                        }
                    }
            }
        }
    }

    private fun hookChromiumSSLLayer(lpparam: LoadPackageParam) {
        // 动态扫描Chromium相关的SSL类
        val classNames = SSLUtils.allClassNamesFromClassLoader(lpparam.classLoader)

        val sslKeywords = listOf(
            "CertVerifier", "SSLConfig", "SSLContext",
            "CertificateVerifier", "CertVerifyProc",
            "X509CertCheck", "SSLClientSocket",
            "QuicSSL", "BoringSSL"
        )

        for (className in classNames) {
            if (hookedClasses.contains(className)) continue

            val shouldHook = sslKeywords.any { keyword ->
                className.contains(keyword, ignoreCase = true)
            }

            if (shouldHook) {
                tryHook("ChromiumSSL.hookDynamicClass: $className", false) {
                    val clazz = Class.forName(className, false, lpparam.classLoader)

                    if (clazz.isInterface || java.lang.reflect.Modifier.isAbstract(clazz.modifiers)) {
                        return@tryHook
                    }

                    // Hook 所有 checkServerTrusted 方法
                    for (method in clazz.declaredMethods) {
                        if (method.name.contains("check", ignoreCase = true) ||
                            method.name.contains("verify", ignoreCase = true) ||
                            method.name.contains("verifyChain", ignoreCase = true)
                        ) {
                            try {
                                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                    override fun beforeHookedMethod(param: MethodHookParam) {
                                        val returnType = method.returnType
                                        when {
                                            returnType == Void.TYPE || returnType == Void::class.javaPrimitiveType -> {
                                                param.result = null
                                            }
                                            returnType == Boolean::class.javaPrimitiveType -> {
                                                param.result = true
                                            }
                                            returnType == List::class.java || returnType == java.util.List::class.java -> {
                                                param.result = ArrayList<X509Certificate>()
                                            }
                                            returnType == Array<X509Certificate>::class.java -> {
                                                param.result = arrayOf<X509Certificate>()
                                            }
                                            returnType.superclass == java.lang.Enum::class.java -> {
                                                // 枚举类型返回第一个值
                                                val values = returnType.enumConstants
                                                if (values != null && values.isNotEmpty()) {
                                                    param.result = values[0]
                                                }
                                            }
                                        }
                                    }
                                })
                                hookedClasses.add(className)
                            } catch (_: Throwable) {
                            }
                        }
                    }
                }
            }
        }
    }

    private fun hookTrustManagerForWebView(lpparam: LoadPackageParam) {
        // 全局替换所有 SSLContext 的 TrustManager
        tryHook("WebViewSSLContext.init") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.SSLContext",
                lpparam.classLoader,
                "init",
                Array<javax.net.ssl.KeyManager>::class.java,
                Array<javax.net.ssl.TrustManager>::class.java,
                java.security.SecureRandom::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val trustManagers = param.args[1] as? Array<*>
                        if (trustManagers != null) {
                            // 替换为 trust-all
                            param.args[1] = arrayOf<TrustManager>(createTrustAllForWebView())
                        }
                    }
                }
            )
        }

        // Hook SSLContext.getInstance 确保返回的 context 使用 trust-all
        tryHook("WebViewSSLContext.getInstance") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.SSLContext",
                lpparam.classLoader,
                "getInstance",
                String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val sslContext = param.result as? SSLContext
                        sslContext?.init(null, arrayOf<TrustManager>(createTrustAllForWebView()), null)
                    }
                }
            )
        }
    }

    private fun hookOpenSSLSocket(lpparam: LoadPackageParam) {
        // Hook OpenSSL Socket 的证书验证
        val openSslClasses = listOf(
            "com.android.org.conscrypt.OpenSSLSocketImpl",
            "com.android.org.conscrypt.OpenSSLEngineImpl",
            "com.android.org.conscrypt.OpenSSLSocketFactoryImpl"
        )

        for (className in openSslClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("OpenSSLSocket.hookCreateSocket: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                // Hook 所有方法来确保 SSL 验证被绕过
                for (method in clazz.declaredMethods) {
                    if (method.name == "verifyCertificateChain" ||
                        method.name == "verify" ||
                        method.name.startsWith("getVerifiedChain")
                    ) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    val returnType = method.returnType
                                    when {
                                        returnType == Void.TYPE -> param.result = null
                                        returnType == Boolean::class.javaPrimitiveType -> param.result = true
                                        returnType == List::class.java -> param.result = ArrayList<X509Certificate>()
                                        returnType == Array<X509Certificate>::class.java -> param.result = arrayOf<X509Certificate>()
                                    }
                                }
                            })
                        } catch (_: Throwable) {
                        }
                    }
                }
            }
        }
    }

    private fun hookX509TrustManagerExtensions(lpparam: LoadPackageParam) {
        if (!isClassExists("android.net.http.X509TrustManagerExtensions", lpparam)) {
            return
        }

        tryHook("WebViewX509TrustManagerExtensions.checkServerTrusted") {
            val clazz = lpparam.classLoader.loadClass("android.net.http.X509TrustManagerExtensions")

            // Hook 所有 checkServerTrusted 重载
            for (method in clazz.declaredMethods) {
                if (method.name == "checkServerTrusted") {
                    try {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                val certs = param.args[0] as? Array<*>
                                if (certs != null && certs.isNotEmpty()) {
                                    // 直接返回证书链，跳过验证
                                    param.result = certs.toList()
                                } else {
                                    param.result = ArrayList<X509Certificate>()
                                }
                            }
                        })
                    } catch (_: Throwable) {
                    }
                }
            }
        }
    }

    private fun createTrustAllForWebView(): X509TrustManager {
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
    }
}
