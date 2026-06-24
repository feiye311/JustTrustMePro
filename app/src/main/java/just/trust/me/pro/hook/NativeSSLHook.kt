package just.trust.me.pro.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import just.trust.me.pro.util.SSLUtils
import java.lang.reflect.Method
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class NativeSSLHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookAllTrustManagers(lpparam)
        hookAllSSLContext(lpparam)
        hookAllSSLSocketFactory(lpparam)
        hookAllHostnameVerifier(lpparam)
        hookCertificatePinning(lpparam)
        hookConscryptAll(lpparam)
        hookDynamicTrustManagers(lpparam)
    }

    private fun hookAllTrustManagers(lpparam: LoadPackageParam) {
        // Hook 所有 X509TrustManager 的 checkServerTrusted
        val trustManagerClasses = listOf(
            "com.android.org.conscrypt.TrustManagerImpl",
            "com.android.org.conscrypt.ConscryptEngine",
            "com.android.org.conscrypt.ConscryptEngineSocket",
            "com.android.org.conscrypt.OpenSSLSocketImpl",
            "com.android.org.conscrypt.OpenSSLEngineImpl",
            "com.android.org.conscrypt.OpenSSLSocketFactoryImpl",
            "android.net.http.X509TrustManagerExtensions",
            "com.android.org.conscrypt.CertPinManager",
            "com.android.org.conscrypt.CertificateValidatorCache"
        )

        for (className in trustManagerClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("TrustManager.hookAll: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                // Hook 所有 checkServerTrusted 方法
                for (method in clazz.declaredMethods) {
                    if (method.name == "checkServerTrusted" ||
                        method.name == "checkClientTrusted" ||
                        method.name == "checkTrusted" ||
                        method.name == "checkTrustedRecursive"
                    ) {
                        hookTrustMethod(clazz, method)
                    }
                }
            }
        }

        // 动态扫描所有实现了 X509TrustManager 的类
        tryHook("TrustManager.hookAllDynamic") {
            val classNames = SSLUtils.allClassNamesFromClassLoader(lpparam.classLoader)
            for (className in classNames) {
                if (hookedClasses.contains(className)) continue

                try {
                    val clazz = Class.forName(className, false, lpparam.classLoader)
                    if (X509TrustManager::class.java.isAssignableFrom(clazz) &&
                        !java.lang.reflect.Modifier.isAbstract(clazz.modifiers)
                    ) {
                        hookTrustManagerClass(clazz)
                        hookedClasses.add(className)
                    }
                } catch (_: Throwable) {}
            }
        }
    }

    private fun hookTrustManagerClass(clazz: Class<*>) {
        try {
            val instance = XposedHelpers.newInstance(clazz)

            for (method in clazz.declaredMethods) {
                when (method.name) {
                    "checkServerTrusted", "checkClientTrusted" -> {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                val returnType = method.returnType
                                when {
                                    returnType == Void.TYPE -> param.result = null
                                    returnType == List::class.java || returnType == java.util.List::class.java -> {
                                        val certs = param.args[0] as? Array<*> ?: arrayOf<X509Certificate>()
                                        param.result = certs.toList()
                                    }
                                    returnType == Array<X509Certificate>::class.java -> {
                                        val certs = param.args[0] as? Array<*> ?: arrayOf<X509Certificate>()
                                        param.result = certs
                                    }
                                }
                            }
                        })
                    }
                    "getAcceptedIssuers" -> {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                param.result = arrayOf<X509Certificate>()
                            }
                        })
                    }
                }
            }
        } catch (_: Throwable) {}
    }

    private fun hookTrustMethod(clazz: Class<*>, method: Method) {
        try {
            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val returnType = method.returnType
                    when {
                        returnType == Void.TYPE -> param.result = null
                        returnType == Boolean::class.javaPrimitiveType -> param.result = true
                        returnType == List::class.java || returnType == java.util.List::class.java -> {
                            param.result = ArrayList<X509Certificate>()
                        }
                        returnType == Array<X509Certificate>::class.java -> {
                            param.result = arrayOf<X509Certificate>()
                        }
                        returnType.superclass == java.lang.Enum::class.java -> {
                            val values = returnType.enumConstants
                            if (values != null && values.isNotEmpty()) {
                                param.result = values[0]
                            }
                        }
                    }
                }
            })
        } catch (_: Throwable) {}
    }

    private fun hookAllSSLContext(lpparam: LoadPackageParam) {
        // Hook SSLContext.init - 替换所有 TrustManager
        tryHook("SSLContext.hookInit") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.SSLContext",
                lpparam.classLoader,
                "init",
                Array<KeyManager>::class.java,
                Array<TrustManager>::class.java,
                SecureRandom::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[1] = arrayOf<TrustManager>(createUniversalTrustManager())
                    }
                }
            )
        }

        // Hook SSLContext.getInstance
        tryHook("SSLContext.hookGetInstance") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.SSLContext",
                lpparam.classLoader,
                "getInstance",
                String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val sslContext = param.result as? SSLContext ?: return
                        try {
                            sslContext.init(null, arrayOf<TrustManager>(createUniversalTrustManager()), null)
                        } catch (_: Throwable) {}
                    }
                }
            )
        }

        // Hook SSLContext.getSocketFactory
        tryHook("SSLContext.hookGetSocketFactory") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.SSLContext",
                lpparam.classLoader,
                "getSocketFactory",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val factory = param.result as? SSLSocketFactory ?: return
                        // 已经通过 init hook 处理了
                    }
                }
            )
        }

        // Hook 所有 SSLContext 的 getTrustManagers 方法
        tryHook("SSLContext.hookGetTrustManagers") {
            val clazz = lpparam.classLoader.loadClass("javax.net.ssl.SSLContext")
            for (method in clazz.declaredMethods) {
                if (method.name.contains("trust") || method.name.contains("Trust")) {
                    XposedBridge.hookMethod(method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = arrayOf<TrustManager>(createUniversalTrustManager())
                        }
                    })
                }
            }
        }
    }

    private fun hookAllSSLSocketFactory(lpparam: LoadPackageParam) {
        // Hook SSLSocketFactory.createSocket
        val sslSocketFactoryClasses = listOf(
            "javax.net.ssl.SSLSocketFactory",
            "com.android.org.conscrypt.ConscryptEngineSocket\$SSLSocketFactory",
            "org.conscrypt.ConscryptEngineSocket\$SSLSocketFactory"
        )

        for (className in sslSocketFactoryClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("SSLSocketFactory.hook: $className") {
                val clazz = lpparam.classLoader.loadClass(className)
                for (method in clazz.declaredMethods) {
                    if (method.name == "createSocket") {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun afterHookedMethod(param: MethodHookParam) {
                                val socket = param.result ?: return
                                try {
                                    val sslSocketClass = Class.forName("javax.net.ssl.SSLSocket")
                                    if (sslSocketClass.isInstance(socket)) {
                                        // 启用所有协议
                                        val enabledProtocols = arrayOf("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
                                        val method = sslSocketClass.getMethod("setEnabledProtocols", Array<String>::class.java)
                                        method.invoke(socket, enabledProtocols)
                                    }
                                } catch (_: Throwable) {}
                            }
                        })
                    }
                }
            }
        }
    }

    private fun hookAllHostnameVerifier(lpparam: LoadPackageParam) {
        // Hook 所有 HostnameVerifier.verify
        val hostnameVerifierClasses = listOf(
            "com.android.org.conscrypt.HostnameVerifier",
            "okhttp3.internal.tls.OkHostnameVerifier",
            "org.apache.http.conn.ssl.AbstractVerifier",
            "org.apache.http.conn.ssl.AllowAllHostnameVerifier",
            "org.apache.http.conn.ssl.BrowserCompatHostnameVerifier",
            "org.apache.http.conn.ssl.StrictHostnameVerifier"
        )

        for (className in hostnameVerifierClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("HostnameVerifier.hook: $className") {
                val clazz = lpparam.classLoader.loadClass(className)
                for (method in clazz.declaredMethods) {
                    if (method.name == "verify") {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                param.result = true
                            }
                        })
                    }
                }
            }
        }

        // 动态扫描所有 HostnameVerifier 实现
        tryHook("HostnameVerifier.hookAllDynamic") {
            val classNames = SSLUtils.allClassNamesFromClassLoader(lpparam.classLoader)
            val hostnameVerifierClass = Class.forName("javax.net.ssl.HostnameVerifier")

            for (className in classNames) {
                if (hookedClasses.contains(className)) continue

                try {
                    val clazz = Class.forName(className, false, lpparam.classLoader)
                    if (hostnameVerifierClass.isAssignableFrom(clazz) &&
                        !java.lang.reflect.Modifier.isAbstract(clazz.modifiers)
                    ) {
                        for (method in clazz.declaredMethods) {
                            if (method.name == "verify") {
                                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                    override fun beforeHookedMethod(param: MethodHookParam) {
                                        param.result = true
                                    }
                                })
                                hookedClasses.add(className)
                                break
                            }
                        }
                    }
                } catch (_: Throwable) {}
            }
        }
    }

    private fun hookCertificatePinning(lpparam: LoadPackageParam) {
        // Hook OkHttp3 CertificatePinner
        val pinnerClasses = listOf(
            "okhttp3.CertificatePinner",
            "com.squareup.okhttp.CertificatePinner"
        )

        for (className in pinnerClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("CertificatePinner.hook: $className") {
                val clazz = lpparam.classLoader.loadClass(className)
                for (method in clazz.declaredMethods) {
                    if (method.name == "check" || method.name == "findMatchingPins") {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                param.result = null
                            }
                        })
                    }
                }
            }
        }
    }

    private fun hookConscryptAll(lpparam: LoadPackageParam) {
        // Hook Conscrypt 平台的证书验证
        val conscryptClasses = listOf(
            "com.android.org.conscrypt.Platform",
            "com.android.org.conscrypt.CertBlocklistImpl",
            "com.android.org.conscrypt.CertBlocklist",
            "com.android.org.conscrypt.TrustedCertificateStore",
            "com.android.org.conscrypt.CertPinManager",
            "com.android.org.conscrypt.VerifiedChain"
        )

        for (className in conscryptClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("Conscrypt.hook: $className") {
                val clazz = lpparam.classLoader.loadClass(className)
                for (method in clazz.declaredMethods) {
                    if (method.name.contains("verify") ||
                        method.name.contains("check") ||
                        method.name.contains("pin") ||
                        method.name.contains("trust")
                    ) {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                val returnType = method.returnType
                                when {
                                    returnType == Boolean::class.javaPrimitiveType -> param.result = true
                                    returnType == Void.TYPE -> param.result = null
                                    returnType == List::class.java || returnType == java.util.List::class.java -> {
                                        param.result = ArrayList<Any>()
                                    }
                                }
                            }
                        })
                    }
                }
            }
        }
    }

    private fun hookDynamicTrustManagers(lpparam: LoadPackageParam) {
        // 扫描所有使用 TrustManagerFactory 的类
        tryHook("TrustManagerFactory.hookGetTrustManagers") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.TrustManagerFactory",
                lpparam.classLoader,
                "getTrustManagers",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = arrayOf<TrustManager>(createUniversalTrustManager())
                    }
                }
            )
        }

        // Hook 所有创建 TrustManager 的工厂方法
        tryHook("TrustManagerFactory.hookInit") {
            XposedHelpers.findAndHookMethod(
                "javax.net.ssl.TrustManagerFactory",
                lpparam.classLoader,
                "init",
                KeyStore::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        // 已经通过 getTrustManagers hook 处理
                    }
                }
            )
        }
    }

    private fun createUniversalTrustManager(): X509TrustManager {
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
    }

    companion object {
        private val hookedClasses = mutableSetOf<String>()
    }
}
