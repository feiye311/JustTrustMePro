package just.trust.me.pro.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import just.trust.me.pro.util.SSLUtils
import java.lang.reflect.Method

class CronetHook : BaseHook() {
    override fun initHook(lpparam: LoadPackageParam) {
        hookCronetEngine(lpparam)
        hookChromiumNet(lpparam)
        hookMeituanCronet(lpparam)
        hookCronetUrlRequest(lpparam)
    }

    private fun hookCronetEngine(lpparam: LoadPackageParam) {
        // Hook org.chromium.net.api.CronetEngine
        val cronetClasses = listOf(
            "org.chromium.net.api.CronetEngine",
            "org.chromium.net.api.CronetEngine\$Builder",
            "com.android.org.chromium.net.CronetEngine",
            "org.chromium.net.CronetEngine"
        )

        for (className in cronetClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("CronetEngine.hookBuilder: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                // Hook enableNetworkQualityEstimator
                for (method in clazz.declaredMethods) {
                    if (method.name.contains("enableSSL") ||
                        method.name.contains("trustManager") ||
                        method.name.contains("certificateVerifier")
                    ) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    // 返回 this 以跳过 SSL 配置
                                    param.result = param.thisObject
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
            }
        }
    }

    private fun hookChromiumNet(lpparam: LoadPackageParam) {
        // Hook org.chromium.net native SSL verification
        val chromiumClasses = listOf(
            "org.chromium.net.impl.CronetUrlRequest",
            "org.chromium.net.impl.CronetEngineBase",
            "org.chromium.net.NetworkQualityEstimator",
            "org.chromium.net.ExperimentalCronetEngine",
            "org.chromium.net.urlcomponents.UrlResponse"
        )

        for (className in chromiumClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("ChromiumNet.hookClass: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                for (method in clazz.declaredMethods) {
                    if (method.name.contains("verify") ||
                        method.name.contains("check") ||
                        method.name.contains("validate")
                    ) {
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

    private fun hookMeituanCronet(lpparam: LoadPackageParam) {
        // Hook 美团自研的 Chromium 网络栈
        val meituanChromiumClasses = listOf(
            "org.chromium.meituan.net.impl.CronetEngineImpl",
            "org.chromium.meituan.net.impl.CronetUrlRequestImpl",
            "org.chromium.meituan.net.impl.CronetUrlRequestBuilderImpl",
            "org.chromium.meituan.net.impl.CronetMetrics",
            "org.chromium.meituan.net.impl.CronetExceptionImpl"
        )

        // 动态扫描 org.chromium.meituan 包下的所有类
        val classNames = SSLUtils.allClassNamesFromClassLoader(lpparam.classLoader)
        val meituanChromiumPrefix = "org.chromium.meituan.net"

        for (className in classNames) {
            if (!className.startsWith(meituanChromiumPrefix)) continue

            tryHook("MeituanCronet.hookDynamic: $className", false) {
                val clazz = Class.forName(className, false, lpparam.classLoader)

                if (clazz.isInterface || java.lang.reflect.Modifier.isAbstract(clazz.modifiers)) {
                    return@tryHook
                }

                // Hook 所有与 SSL/证书相关的方法
                for (method in clazz.declaredMethods) {
                    if (method.name.contains("verify", ignoreCase = true) ||
                        method.name.contains("certificate", ignoreCase = true) ||
                        method.name.contains("ssl", ignoreCase = true) ||
                        method.name.contains("trust", ignoreCase = true)
                    ) {
                        try {
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
                        } catch (_: Throwable) {}
                    }
                }
            }
        }
    }

    private fun hookCronetUrlRequest(lpparam: LoadPackageParam) {
        // Hook CronetUrlRequest 的 SSL 握手
        val requestClasses = listOf(
            "org.chromium.net.impl.CronetUrlRequest",
            "org.chromium.net.impl.UrlRequestBase",
            "org.chromium.net.impl.CronetUrlRequestContext"
        )

        for (className in requestClasses) {
            if (!isClassExists(className, lpparam)) continue

            tryHook("CronetUrlRequest.hookSSL: $className") {
                val clazz = lpparam.classLoader.loadClass(className)

                // Hook onSslReceived 方法（如果存在）
                for (method in clazz.declaredMethods) {
                    if (method.name == "onSslReceived" ||
                        method.name == "onSSLCertificateVerify" ||
                        method.name == "onConnectionVerified"
                    ) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    // 不调用原始方法，直接跳过 SSL 验证
                                    param.result = null
                                }
                            })
                        } catch (_: Throwable) {}
                    }
                }
            }
        }
    }
}
