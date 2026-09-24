package io.github.sardanioss.httpcloak

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * An HTTP client whose TLS, HTTP/2 and HTTP/3 fingerprints match a real
 * browser. It keeps cookies, TLS session tickets and connections across
 * requests, and is safe to share between threads and coroutines.
 *
 * Requests come in two flavours:
 * - suspending ([request], [get], [post], ...), which are main-safe and abort
 *   the request when the calling coroutine is cancelled;
 * - blocking ([execute], [executeStream]), for background threads and Java.
 *
 * Close the session when done with it to release its connections.
 */
public class Session private constructor(handle: Long) : Closeable {
    private val handleRef = AtomicLong(handle)

    @JvmOverloads
    public constructor(config: SessionConfig = SessionConfig()) : this(create(config))

    public constructor(preset: String) : this(SessionConfig(preset = preset))

    /** Basic auth (username, password) for every request that does not set its own. */
    @Volatile
    public var auth: Pair<String, String>? = null

    internal val handle: Long
        get() = handleRef.get().takeIf { it > 0 } ?: throw IllegalStateException("Session is closed")

    // ------------------------------------------------------------------
    // Requests
    // ------------------------------------------------------------------

    /**
     * Sends [request] and suspends until the whole response has been read.
     * Cancelling the calling coroutine aborts the request. Encoding the request
     * and decoding the response, both proportional to the body, run on
     * [Dispatchers.Default] rather than the caller's dispatcher.
     */
    public suspend fun request(request: Request): Response = withContext(Dispatchers.Default) {
        val session = handle
        val json = request.toJson(auth, timeoutMillis = false, inlineBody = true)
        val start = System.nanoTime()
        val result = NativeCallbacks.await { id -> Native.requestAsync(session, json, id) }
        Response.fromJson(result, null, millisSince(start))
    }

    /**
     * Sends [request] and blocks until the whole response has been read.
     * Do not call this on the main thread.
     */
    public fun execute(request: Request): Response {
        val session = handle
        val json = request.toJson(auth, timeoutMillis = true, inlineBody = false)
        val start = System.nanoTime()
        val response = Native.requestRaw(session, json, request.body?.bytes)
        if (response < 0) throw lastError(session)
        try {
            val metadata = Native.responseGetMetadata(response)
            val body = Native.responseGetBody(response)
            return Response.fromJson(metadata, body, millisSince(start))
        } finally {
            Native.responseFree(response)
        }
    }

    public suspend fun get(
        url: String,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
    ): Response = request(Request(url, "GET", headers, params = params))

    public suspend fun post(
        url: String,
        body: Body? = null,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
    ): Response = request(Request(url, "POST", headers, body, params))

    public suspend fun put(
        url: String,
        body: Body? = null,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
    ): Response = request(Request(url, "PUT", headers, body, params))

    public suspend fun patch(
        url: String,
        body: Body? = null,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
    ): Response = request(Request(url, "PATCH", headers, body, params))

    public suspend fun delete(
        url: String,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
    ): Response = request(Request(url, "DELETE", headers, params = params))

    public suspend fun head(
        url: String,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
    ): Response = request(Request(url, "HEAD", headers, params = params))

    public suspend fun options(
        url: String,
        headers: Map<String, String> = emptyMap(),
        params: Map<String, String> = emptyMap(),
    ): Response = request(Request(url, "OPTIONS", headers, params = params))

    // ------------------------------------------------------------------
    // Streaming
    // ------------------------------------------------------------------

    /**
     * Sends [request] and suspends until the response headers arrive; the body
     * is then read from [StreamResponse.body]. Cancelling before the headers
     * arrive aborts the request. [Request.timeout] bounds the whole stream,
     * and defaults to two minutes. As with [request], encoding the request and
     * handing it to the library run on [Dispatchers.Default].
     */
    public suspend fun stream(request: Request): StreamResponse {
        val session = handle
        val opened = AtomicReference<StreamResponse?>()
        try {
            return withContext(Dispatchers.Default) {
                val json = request.toJson(auth, timeoutMillis = false, inlineBody = true)
                val result = NativeCallbacks.await(
                    onDropped = { Native.streamClose(JSONObject(it).optLong("stream_handle")) },
                ) { id -> Native.streamRequestAsync(session, json, id) }
                val metadata = checkedObject(result)
                val stream = metadata.getLong("stream_handle")
                try {
                    StreamResponse(stream, metadata).also { opened.set(it) }
                } catch (e: Throwable) {
                    Native.streamClose(stream)
                    throw e
                }
            }
        } catch (e: Throwable) {
            // withContext discards its result when the caller is cancelled on
            // the way back, and that result is an open stream.
            opened.get()?.close()
            throw e
        }
    }

    /** Blocking counterpart of [stream]. Do not call this on the main thread. */
    public fun executeStream(request: Request): StreamResponse {
        val session = handle
        val json = request.toJson(auth, timeoutMillis = false, inlineBody = true)
        val stream = Native.streamRequest(session, json)
        if (stream < 0) throw lastError(session)
        return StreamResponse(stream, checkedObject(Native.streamGetMetadata(stream)))
    }

    /**
     * Starts a request whose body is written incrementally to the returned
     * [Upload]. [timeout] is in seconds and defaults to five minutes.
     */
    @JvmOverloads
    public fun upload(
        url: String,
        method: String = "POST",
        headers: Map<String, String> = emptyMap(),
        contentType: String? = null,
        timeout: Int? = null,
    ): Upload {
        val options = JSONObject().put("method", method.uppercase())
        val allHeaders = Request(url, headers = headers).effectiveHeaders(auth)
        if (allHeaders.isNotEmpty()) options.put("headers", JSONObject(allHeaders))
        contentType?.let { options.put("content_type", it) }
        timeout?.let { options.put("timeout", it * 1000) }
        val upload = Native.uploadStart(handle, url, options.toString())
        if (upload < 0) throw HttpCloakException("could not start upload to $url")
        return Upload(upload)
    }

    // ------------------------------------------------------------------
    // Session lifecycle
    // ------------------------------------------------------------------

    /**
     * A new session sharing this one's cookies, TLS session tickets and
     * fingerprint, with its own connections: like another browser tab.
     */
    public fun fork(): Session {
        val forked = Native.sessionFork(handle)
        if (forked <= 0) throw HttpCloakException("could not fork session")
        return Session(forked).also { it.auth = auth }
    }

    /**
     * Closes all connections but keeps cookies and TLS session tickets, like a
     * browser page refresh. With [protocol] ("h1", "h2", "h3" or "auto") the
     * session also switches to that protocol from now on.
     */
    @JvmOverloads
    public fun refresh(protocol: String? = null) {
        if (protocol == null) Native.sessionRefresh(handle)
        else errorIn(Native.sessionRefreshProtocol(handle, protocol))?.let { throw HttpCloakException(it) }
    }

    /**
     * Loads [url] the way a browser loads a page, fetching the HTML and its
     * subresources, to warm TLS sessions, cookies and cache state. Blocks for
     * up to [timeout] seconds.
     */
    @JvmOverloads
    public fun warmup(url: String, timeout: Int = 60) {
        errorIn(Native.sessionWarmup(handle, url, timeout * 1000L))?.let { throw HttpCloakException(it) }
    }

    /** Writes the session (cookies, TLS tickets, config) to [path]. */
    public fun save(path: String) {
        checked(Native.sessionSave(handle, path))
    }

    /** The session state as a string, for [unmarshal]. */
    public fun marshal(): String = checked(Native.sessionMarshal(handle))

    /** True until the session has been closed. */
    public val isActive: Boolean
        get() = handleRef.get().let { it > 0 && Native.isActive(it) }

    /** Time since the session last served a request. */
    public val idleTimeMillis: Long get() = Native.idleTimeNanos(handle) / 1_000_000

    /** Resets the idle timer without sending a request. */
    public fun touch(): Unit = Native.touch(handle)

    public fun stats(): SessionStats =
        SessionStats.fromJson(Native.stats(handle) ?: throw HttpCloakException("no stats for session"))

    override fun close() {
        val h = handleRef.getAndSet(0)
        if (h > 0) Native.sessionFree(h)
    }

    // ------------------------------------------------------------------
    // Cookies
    // ------------------------------------------------------------------

    /** Every cookie in the session's jar. */
    public fun getCookies(): List<Cookie> = Cookie.listFromJson(JSONArray(checked(Native.getCookies(handle))))

    /** The first cookie named [name], if any. */
    public fun getCookie(name: String): Cookie? = getCookies().firstOrNull { it.name == name }

    public fun setCookie(cookie: Cookie): Unit = Native.setCookie(handle, cookie.toJson())

    /** Removes cookie [name]; an empty [domain] matches every domain. */
    @JvmOverloads
    public fun deleteCookie(name: String, domain: String = ""): Unit = Native.deleteCookie(handle, name, domain)

    public fun clearCookies(): Unit = Native.clearCookies(handle)

    // ------------------------------------------------------------------
    // Settings that can change after creation
    // ------------------------------------------------------------------

    /** Proxy for all traffic, or null for none. */
    public var proxy: String?
        get() = checked(Native.getProxy(handle)).ifEmpty { null }
        set(value) {
            checked(Native.setProxy(handle, value))
        }

    /** Proxy for HTTP/1.1 and HTTP/2, or null for none. */
    public var tcpProxy: String?
        get() = checked(Native.getTcpProxy(handle)).ifEmpty { null }
        set(value) {
            checked(Native.setTcpProxy(handle, value))
        }

    /** Proxy for HTTP/3 (MASQUE), or null for none. */
    public var udpProxy: String?
        get() = checked(Native.getUdpProxy(handle)).ifEmpty { null }
        set(value) {
            checked(Native.setUdpProxy(handle, value))
        }

    /**
     * The header order used for every request. Setting an empty list restores
     * the preset's own order. See [Request.headerOrder] for a per-request order.
     */
    public var headerOrder: List<String>
        get() = JSONArray(checked(Native.getHeaderOrder(handle))).toStringList()
        set(value) {
            checked(Native.setHeaderOrder(handle, JSONArray(value).toString()))
        }

    /** Whether ETag / If-Modified-Since caching is on. */
    public var conditionalCache: Boolean
        get() = Native.getConditionalCache(handle)
        set(value) = Native.setConditionalCache(handle, value)

    /** Whether any sec-ch-ua client hints are sent. */
    public var clientHints: Boolean
        get() = Native.getClientHints(handle)
        set(value) = Native.setClientHints(handle, value)

    /** Whether high-entropy client hints are sent when a server asks for them. */
    public var highEntropyClientHints: Boolean
        get() = Native.getHighEntropyClientHints(handle)
        set(value) = Native.setHighEntropyClientHints(handle, value)

    public var followRedirects: Boolean
        get() = Native.getFollowRedirects(handle)
        set(value) = Native.setFollowRedirects(handle, value)

    public var maxRedirects: Int
        get() = Native.getMaxRedirects(handle)
        set(value) = Native.setMaxRedirects(handle, value)

    /**
     * Isolates this session's TLS cache keys, for sessions registered with a
     * [LocalProxy] that share a distributed [SessionCache].
     */
    public fun setIdentifier(id: String?): Unit = Native.setIdentifier(handle, id)

    /** Drops the conditional-request cache. Cookies and TLS tickets are kept. */
    public fun clearCache(): Unit = Native.clearCache(handle)

    public companion object {
        /** Restores a session written by [save]. */
        @JvmStatic
        public fun load(path: String): Session {
            val h = Native.sessionLoad(path)
            if (h <= 0) throw HttpCloakException("could not load session from $path")
            return Session(h)
        }

        /** Restores a session from [marshal] output. */
        @JvmStatic
        public fun unmarshal(data: String): Session {
            val h = Native.sessionUnmarshal(data)
            if (h <= 0) throw HttpCloakException("could not restore session")
            return Session(h)
        }

        private fun create(config: SessionConfig): Long {
            val h = Native.sessionNew(config.toJson())
            if (h <= 0) throw HttpCloakException("could not create session")
            return h
        }

        private fun lastError(session: Long) =
            HttpCloakException(Native.lastError(session).ifEmpty { "request failed" })

        private fun millisSince(startNanos: Long) = (System.nanoTime() - startNanos) / 1_000_000
    }
}
