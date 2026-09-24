package io.github.sardanioss.httpcloak

import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Upcalls from the JNI bridge. The library calls these on its own threads, so
 * nothing here may block for long or let an exception escape.
 */
internal object NativeCallbacks {
    private class Pending(val onResult: (json: String?, error: String?) -> Unit)

    private val pending = ConcurrentHashMap<Long, Pending>()

    /**
     * Starts an async native call with a fresh callback id and suspends until
     * it reports back. Cancelling the coroutine cancels the native call.
     *
     * [onDropped] receives a result that arrived after the caller had already
     * been cancelled, so anything it owns (a stream handle) can be released.
     */
    suspend fun await(
        onDropped: (json: String) -> Unit = {},
        start: (callbackId: Long) -> Unit,
    ): String = suspendCancellableCoroutine { cont ->
        val id = Native.registerCallback()
        pending[id] = Pending { json, error ->
            if (json != null) {
                cont.resume(json) { _, _, _ -> onDropped(json) }
            } else {
                cont.resumeWithException(HttpCloakException(asyncErrorMessage(error)))
            }
        }
        cont.invokeOnCancellation {
            if (pending.remove(id) != null) {
                Native.cancelRequest(id)
                Native.unregisterCallback(id)
            }
        }
        try {
            start(id)
        } catch (e: Throwable) {
            pending.remove(id)
            Native.unregisterCallback(id)
            throw e
        }
    }

    @JvmStatic
    fun onAsyncResult(callbackId: Long, json: String?, error: String?) {
        pending.remove(callbackId)?.onResult?.invoke(json, error)
    }

    // --- TLS session cache, see HttpCloak.setSessionCache ---

    @Volatile
    var sessionCache: SessionCache? = null

    @JvmStatic
    fun cacheGet(key: String): String? = runCatching { sessionCache?.get(key) }.getOrNull()

    @JvmStatic
    fun cachePut(key: String, value: String, ttlSeconds: Long): Boolean =
        runCatching { sessionCache?.put(key, value, ttlSeconds) }.isSuccess

    @JvmStatic
    fun cacheDelete(key: String): Boolean = runCatching { sessionCache?.delete(key) }.isSuccess

    @JvmStatic
    fun echGet(key: String): String? = runCatching { sessionCache?.getEch(key) }.getOrNull()

    @JvmStatic
    fun echPut(key: String, value: String, ttlSeconds: Long): Boolean =
        runCatching { sessionCache?.putEch(key, value, ttlSeconds) }.isSuccess

    @JvmStatic
    fun cacheError(operation: String, key: String, error: String) {
        runCatching { sessionCache?.onError(operation, key, error) }
    }
}
