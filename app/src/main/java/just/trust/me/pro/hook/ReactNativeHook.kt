package just.trust.me.pro.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import just.trust.me.pro.util.SSLUtils
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class ReactNativeHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookOkHttpClientProvider(lpparam)
        hookOkHttpClientBuilder(lpparam)
        hookReactNativeNetworkModule(lpparam)
        hookConscryptProvider(lpparam)
        hookSSLContextInit(lpparam)
        hookOkHttp3(lpparam)
    }

    private fun hookOkHttpClientProvider(lpparam: LoadPackageParam) {
        // Hook React Native 的 OkHttpClientProvider
        val providerClasses = listOf(
            "com.facebook.react.modules.network.OkHttpClientProvider",
            "com.facebook.react.modules.network.h",
            "com.facebook.okhttp.OkHttpClientProvider"
        )

        for (className in providerClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("ReactNative.hookProvider: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                for (method in clazz.declaredMethods) {
                    if (method.name.contains("okhttp") || method.name.contains("client") || method.name.contains("build")) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun afterHookedMethod(param: MethodHookParam) {
                                    val client = param.result ?: return

                                    // 获取 OkHttpClient.Builder 并替换 SSL
                                    try {
                                        val builderField = client.javaClass.getDeclaredField("builder")
                                        builderField.isAccessible = true
                                        val builder = builderField.get(client)

                                        val trustManager = SSLUtils.createTrustAll()
                                        val sslContext = SSLContext.getInstance("TLS")
                                        sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())

                                        val builderClass = builder.javaClass
                                        val sslSocketFactoryField = builderClass.getDeclaredField("sslSocketFactory")
                                        sslSocketFactoryField.isAccessible = true
                                        sslSocketFactoryField.set(builder, sslContext.socketFactory)

                                        val hostnameVerifierField = builderClass.getDeclaredField("hostnameVerifier")
                                        hostnameVerifierField.isAccessible = true
                                        hostnameVerifierField.set(builder, SSLUtils.createTrustAllHostnameVerifier())
                                    } catch (_: Throwable) {}
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
            }
        }
    }

    private fun hookOkHttpClientBuilder(lpparam: LoadPackageParam) {
        // Hook OkHttpClient.Builder.build()
        tryHook("OkHttpClient.Builder.hookBuild") {
            XposedHelpers.findAndHookMethod(
                "okhttp3.OkHttpClient\$Builder",
                lpparam.classLoader,
                "build",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val client = param.result ?: return
                        try {
                            val trustManager = SSLUtils.createTrustAll()
                            val sslContext = SSLContext.getInstance("TLS")
                            sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())

                            XposedHelpers.setObjectField(client, "sslSocketFactory", sslContext.socketFactory)
                            XposedHelpers.setObjectField(client, "hostnameVerifier", SSLUtils.createTrustAllHostnameVerifier())
                        } catch (_: Throwable) {}
                    }
                }
            )
        }

        // Hook OkHttpClient constructor
        tryHook("OkHttpClient.hookConstructor") {
            XposedHelpers.findAndHookConstructor(
                "okhttp3.OkHttpClient",
                lpparam.classLoader,
                "okhttp3.OkHttpClient\$Builder",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val builder = param.args[0] ?: return
                        try {
                            val trustManager = SSLUtils.createTrustAll()
                            val sslContext = SSLContext.getInstance("TLS")
                            sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())

                            XposedHelpers.setObjectField(builder, "sslSocketFactory", sslContext.socketFactory)
                            XposedHelpers.setObjectField(builder, "hostnameVerifier", SSLUtils.createTrustAllHostnameVerifier())
                        } catch (_: Throwable) {}
                    }
                }
            )
        }
    }

    private fun hookReactNativeNetworkModule(lpparam: LoadPackageParam) {
        // Hook React Native NetworkingModule
        val networkClasses = listOf(
            "com.facebook.react.modules.network.NetworkingModule",
            "com.facebook.react.modules.network.c"
        )

        for (className in networkClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("ReactNative.hookNetworking: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                for (method in clazz.declaredMethods) {
                    if (method.name.contains("okhttp") || method.name.contains("client")) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun afterHookedMethod(param: MethodHookParam) {
                                    val result = param.result ?: return
                                    if (result.javaClass.name.contains("OkHttpClient")) {
                                        try {
                                            val trustManager = SSLUtils.createTrustAll()
                                            val sslContext = SSLContext.getInstance("TLS")
                                            sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())

                                            XposedHelpers.setObjectField(result, "sslSocketFactory", sslContext.socketFactory)
                                            XposedHelpers.setObjectField(result, "hostnameVerifier", SSLUtils.createTrustAllHostnameVerifier())
                                        } catch (_: Throwable) {}
                                    }
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
            }
        }
    }

    private fun hookConscryptProvider(lpparam: LoadPackageParam) {
        // Hook Conscrypt SSL Provider
        val conscryptClasses = listOf(
            "org.conscrypt.OpenSSLProvider",
            "org.conscrypt.Conscrypt",
            "org.conscrypt.Platform"
        )

        for (className in conscryptClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("Conscrypt.hookProvider: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                for (method in clazz.declaredMethods) {
                    if (method.name.contains("checkServerTrusted") ||
                        method.name.contains("verify") ||
                        method.name.contains("certificate")
                    ) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    val returnType = method.returnType
                                    when {
                                        returnType == Boolean::class.javaPrimitiveType -> param.result = true
                                        returnType == Void.TYPE -> param.result = null
                                        returnType == List::class.java || returnType == java.util.List::class.java -> {
                                            param.result = ArrayList<X509Certificate>()
                                        }
                                    }
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
            }
        }
    }

    private fun hookSSLContextInit(lpparam: LoadPackageParam) {
        // Hook SSLContext.init to replace TrustManager
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
                        val trustManagers = param.args[1] as? Array<*>
                        if (trustManagers != null && trustManagers.isNotEmpty()) {
                            // 检查是否已经是 trust-all
                            val firstTM = trustManagers[0]
                            if (firstTM != null && !firstTM.javaClass.name.contains("TrustAll")) {
                                param.args[1] = arrayOf<TrustManager>(SSLUtils.createTrustAll())
                            }
                        } else {
                            param.args[1] = arrayOf<TrustManager>(SSLUtils.createTrustAll())
                        }
                    }
                }
            )
        }
    }

    private fun hookOkHttp3(lpparam: LoadPackageParam) {
        // Hook OkHttp3 CertificatePinner
        tryHook("OkHttp3.hookCertificatePinner") {
            XposedHelpers.findAndHookMethod(
                "okhttp3.CertificatePinner",
                lpparam.classLoader,
                "check",
                String::class.java,
                List::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                    }
                }
            )
        }

        // Hook OkHttp3 RealConnection
        tryHook("OkHttp3.hookRealConnection") {
            val realConnectionClasses = listOf(
                "okhttp3.internal.connection.RealConnection",
                "okhttp3.internal.connection.b"
            )

            for (className in realConnectionClasses) {
                if (!isClassExists(className, lpparam)) continue

                val clazz = lpparam.classLoader.loadClass(className)
                for (method in clazz.declaredMethods) {
                    if (method.name.contains("verify") || method.name.contains("check")) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    val returnType = method.returnType
                                    when {
                                        returnType == Boolean::class.javaPrimitiveType -> param.result = true
                                        returnType == Void.TYPE -> param.result = null
                                    }
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
            }
        }
    }
}
