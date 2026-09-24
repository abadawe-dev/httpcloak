package io.github.sardanioss.httpcloak

/**
 * Downcalls into the JNI bridge (src/main/cpp/httpcloak_jni.c). Each function
 * forwards to the httpcloak_* C export of the same name.
 *
 * Handles are opaque Go-side identifiers; a failed call that returns one
 * returns -1 (or 0). Functions returning `String?` hand back either a result
 * or a JSON error object, see [checkError].
 */
internal object Native {
    init {
        System.loadLibrary("httpcloak")
        System.loadLibrary("httpcloak_jni")
    }

    // Library-wide
    @JvmStatic external fun version(): String
    @JvmStatic external fun availablePresets(): String
    @JvmStatic external fun setEchDnsServers(serversJson: String?): String?
    @JvmStatic external fun getEchDnsServers(): String
    @JvmStatic external fun trimMemory()
    @JvmStatic external fun setSessionCacheCallbacks()
    @JvmStatic external fun clearSessionCacheCallbacks()

    // Custom presets and preset pools
    @JvmStatic external fun presetLoadFile(path: String): String
    @JvmStatic external fun presetLoadJson(json: String): String
    @JvmStatic external fun presetUnregister(name: String)
    @JvmStatic external fun describePreset(name: String): String
    @JvmStatic external fun poolLoadFile(path: String): String
    @JvmStatic external fun poolLoadJson(json: String): String
    @JvmStatic external fun poolPick(pool: Long): String
    @JvmStatic external fun poolRandom(pool: Long): String
    @JvmStatic external fun poolNext(pool: Long): String
    @JvmStatic external fun poolGet(pool: Long, index: Long): String
    @JvmStatic external fun poolSize(pool: Long): Long
    @JvmStatic external fun poolName(pool: Long): String
    @JvmStatic external fun poolFree(pool: Long)

    // Session lifecycle
    @JvmStatic external fun sessionNew(configJson: String): Long
    @JvmStatic external fun sessionFree(session: Long)
    @JvmStatic external fun sessionFork(session: Long): Long
    @JvmStatic external fun sessionRefresh(session: Long)
    @JvmStatic external fun sessionRefreshProtocol(session: Long, protocol: String): String?
    @JvmStatic external fun sessionWarmup(session: Long, url: String, timeoutMs: Long): String?
    @JvmStatic external fun sessionSave(session: Long, path: String): String
    @JvmStatic external fun sessionLoad(path: String): Long
    @JvmStatic external fun sessionMarshal(session: Long): String
    @JvmStatic external fun sessionUnmarshal(data: String): Long
    @JvmStatic external fun lastError(session: Long): String

    // Requests. requestRaw reads the JSON "timeout" as milliseconds, the async
    // and stream entry points read it as seconds.
    @JvmStatic external fun requestRaw(session: Long, requestJson: String, body: ByteArray?): Long
    @JvmStatic external fun responseGetMetadata(response: Long): String
    @JvmStatic external fun responseGetBody(response: Long): ByteArray
    @JvmStatic external fun responseFree(response: Long)
    @JvmStatic external fun registerCallback(): Long
    @JvmStatic external fun unregisterCallback(callbackId: Long)
    @JvmStatic external fun cancelRequest(callbackId: Long)
    @JvmStatic external fun requestAsync(session: Long, requestJson: String, callbackId: Long)

    // Streaming responses and uploads
    @JvmStatic external fun streamRequest(session: Long, requestJson: String): Long
    @JvmStatic external fun streamRequestAsync(session: Long, requestJson: String, callbackId: Long)
    @JvmStatic external fun streamGetMetadata(stream: Long): String
    @JvmStatic external fun streamReadRaw(stream: Long, dst: ByteArray, off: Int, len: Int): Int
    @JvmStatic external fun streamTrailer(stream: Long): String
    @JvmStatic external fun streamClose(stream: Long)
    @JvmStatic external fun uploadStart(session: Long, url: String, optionsJson: String): Long
    @JvmStatic external fun uploadWriteRaw(upload: Long, src: ByteArray, off: Int, len: Int): Int
    @JvmStatic external fun uploadFinish(upload: Long): String
    @JvmStatic external fun uploadCancel(upload: Long)

    // Session state
    @JvmStatic external fun getCookies(session: Long): String
    @JvmStatic external fun setCookie(session: Long, cookieJson: String)
    @JvmStatic external fun deleteCookie(session: Long, name: String, domain: String)
    @JvmStatic external fun clearCookies(session: Long)
    @JvmStatic external fun setProxy(session: Long, url: String?): String
    @JvmStatic external fun setTcpProxy(session: Long, url: String?): String
    @JvmStatic external fun setUdpProxy(session: Long, url: String?): String
    @JvmStatic external fun getProxy(session: Long): String
    @JvmStatic external fun getTcpProxy(session: Long): String
    @JvmStatic external fun getUdpProxy(session: Long): String
    @JvmStatic external fun setHeaderOrder(session: Long, orderJson: String): String
    @JvmStatic external fun getHeaderOrder(session: Long): String
    @JvmStatic external fun setIdentifier(session: Long, id: String?)
    @JvmStatic external fun clearCache(session: Long)
    @JvmStatic external fun stats(session: Long): String?
    @JvmStatic external fun idleTimeNanos(session: Long): Long
    @JvmStatic external fun isActive(session: Long): Boolean
    @JvmStatic external fun touch(session: Long)
    @JvmStatic external fun setConditionalCache(session: Long, enabled: Boolean)
    @JvmStatic external fun getConditionalCache(session: Long): Boolean
    @JvmStatic external fun setClientHints(session: Long, enabled: Boolean)
    @JvmStatic external fun getClientHints(session: Long): Boolean
    @JvmStatic external fun setHighEntropyClientHints(session: Long, enabled: Boolean)
    @JvmStatic external fun getHighEntropyClientHints(session: Long): Boolean
    @JvmStatic external fun setFollowRedirects(session: Long, enabled: Boolean)
    @JvmStatic external fun getFollowRedirects(session: Long): Boolean
    @JvmStatic external fun setMaxRedirects(session: Long, max: Int)
    @JvmStatic external fun getMaxRedirects(session: Long): Int

    // Local proxy
    @JvmStatic external fun localProxyStart(configJson: String): Long
    @JvmStatic external fun localProxyStop(proxy: Long)
    @JvmStatic external fun localProxyGetPort(proxy: Long): Int
    @JvmStatic external fun localProxyIsRunning(proxy: Long): Boolean
    @JvmStatic external fun localProxyGetStats(proxy: Long): String
    @JvmStatic external fun localProxyRegisterSession(proxy: Long, id: String, session: Long): String?
    @JvmStatic external fun localProxyUnregisterSession(proxy: Long, id: String): Boolean
    @JvmStatic external fun localProxyListSessions(proxy: Long): String?
    @JvmStatic external fun localProxyHasSession(proxy: Long, id: String): Boolean
}
