package io.github.sardanioss.httpcloak

import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicLong

/**
 * A request body streamed to the server as it is written, for bodies too large
 * to hold in memory. Write the body, then call [finish] for the response.
 * Closing an upload that was not finished cancels it.
 *
 * ```
 * session.upload(url).use { upload ->
 *     file.inputStream().copyTo(upload)
 *     upload.finish()
 * }
 * ```
 */
public class Upload internal constructor(handle: Long) : OutputStream() {
    private val handle = AtomicLong(handle)
    private val startNanos = System.nanoTime()

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (off < 0 || len < 0 || len > b.size - off) throw IndexOutOfBoundsException()
        if (len == 0) return
        val h = handle.get().takeIf { it > 0 } ?: throw IOException("upload is finished or cancelled")
        if (Native.uploadWriteRaw(h, b, off, len) < 0) throw IOException("upload write failed")
    }

    /** Ends the body and blocks until the response has been read. */
    public fun finish(): Response {
        val h = handle.getAndSet(0).takeIf { it > 0 } ?: throw IOException("upload is finished or cancelled")
        val json = Native.uploadFinish(h)
        return Response.fromJson(json, null, (System.nanoTime() - startNanos) / 1_000_000)
    }

    /** Abandons the upload. Does nothing once [finish] has been called. */
    public fun cancel() {
        val h = handle.getAndSet(0)
        if (h > 0) Native.uploadCancel(h)
    }

    override fun close(): Unit = cancel()
}
