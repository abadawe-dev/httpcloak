package io.github.sardanioss.httpcloak

import org.json.JSONObject
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.atomic.AtomicLong

/**
 * A response whose body is read incrementally from [body]. Close it when done;
 * that releases the connection. Streaming does not follow redirects.
 */
public class StreamResponse internal constructor(handle: Long, metadata: JSONObject) : Closeable {
    private val handle = AtomicLong(handle)

    public val statusCode: Int = metadata.getInt("status_code")
    /** Response headers. Lookups ignore case. */
    public val headers: Map<String, List<String>> = metadata.optJSONObject("headers").toHeaderMap()
    public val url: String = metadata.optString("final_url")
    public val protocol: String = metadata.optString("protocol")
    /** The Content-Length, or -1 when the server did not send one. */
    public val contentLength: Long = metadata.optLong("content_length", -1)
    public val cookies: List<Cookie> = Cookie.listFromJson(metadata.optJSONArray("cookies"))
    /** The order the server sent its headers in. Empty on HTTP/1.1. */
    public val headerOrder: List<String> = metadata.optJSONArray("header_order").toStringList()

    public val ok: Boolean get() = statusCode < 400

    /** The first value of header [name], ignoring case. */
    public fun header(name: String): String? = headers.firstValue(name)

    /** The body as it arrives. Reads block until data is available. */
    public val body: InputStream = object : InputStream() {
        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) == -1) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (off < 0 || len < 0 || len > b.size - off) throw IndexOutOfBoundsException()
            if (len == 0) return 0
            val n = Native.streamReadRaw(openHandle(), b, off, len)
            if (n < 0) throw IOException("stream read failed")
            return if (n == 0) -1 else n
        }

        override fun close() = this@StreamResponse.close()
    }

    /** Reads the rest of the body. */
    public fun readBytes(): ByteArray = body.readBytes()

    /** Reads the rest of the body as text, using the charset from Content-Type. */
    public fun readText(): String = String(readBytes(), charsetOf(header("Content-Type")))

    /** Trailing headers. Only complete once the body has been read to the end. */
    public fun trailer(): Map<String, List<String>> = JSONObject(Native.streamTrailer(openHandle())).toHeaderMap()

    override fun close() {
        val h = handle.getAndSet(0)
        if (h > 0) Native.streamClose(h)
    }

    private fun openHandle(): Long = handle.get().takeIf { it > 0 } ?: throw IOException("stream is closed")
}
