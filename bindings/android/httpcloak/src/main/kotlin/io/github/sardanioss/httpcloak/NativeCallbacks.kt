package io.github.sardanioss.httpcloak

import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Upcalls from the JNI bridge. The library calls these on its own threads, so
 * nothing here may block for long or let an exception escape.
 */
internal object NativeCallbacks {
    private class Pending(val onResult: (json: String?, error: String?) -> Unit)

    private val pending = ConcurrentHashMap<Long, Pending>()

    // Where an async call is, so that starting it and cancelling it, which can
    // happen on different threads, agree on who has to do what.
    private const val NEW = 0 // not started: cancelling just forgets it
    private const val STARTING = 1 // start() is running: it cancels on return
    private const val STARTED = 2 // the library has it: cancel through it
    private const val CANCELLED = 3

    /**
     * Starts an async native call with a fresh callback id and suspends until
     * it reports back. Cancelling the coroutine cancels the native call, or
     * keeps it from starting at all.
     *
     * [onDropped] receives a result that arrived after the caller had already
     * been cancelled, so anything it owns (a stream handle) can be released.
     */
    suspend fun await(
        onDropped: (json: String) -> Unit = {},
        start: (callbackId: Long) -> Unit,
    ): String = suspendCancellableCoroutine { cont ->
        val id = Native.registerCallback()
        val state = AtomicInteger(NEW)
        // Once started, the entry stays until the library reports back, even
        // after cancellation: a result can already be on its way, and whatever
        // it owns must reach onDropped rather than be lost with the entry.
        pending[id] = Pending { json, error ->
            if (json != null) {
                cont.resume(json) { _, _, _ -> runCatching { onDropped(json) } }
            } else {
                cont.resumeWithException(HttpCloakException(asyncErrorMessage(error)))
            }
        }
        cont.invokeOnCancellation {
            when (state.getAndSet(CANCELLED)) {
                NEW -> forget(id)
                STARTED -> Native.cancelRequest(id)
                // STARTING: the library may not know the id yet, so the
                // starter cancels once start() has returned.
            }
        }
        if (!state.compareAndSet(NEW, STARTING)) return@suspendCancellableCoroutine // already cancelled
        try {
            start(id)
        } catch (e: Throwable) {
            state.set(CANCELLED)
            forget(id)
            throw e
        }
        if (!state.compareAndSet(STARTING, STARTED)) Native.cancelRequest(id)
    }

    /** Drops a call the library never started, and so will never report on. */
    private fun forget(id: Long) {
        pending.remove(id)
        Native.unregisterCallback(id)
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
