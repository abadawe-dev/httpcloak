package io.github.sardanioss.httpcloak

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.coroutines.CoroutineContext

/**
 * Request, cancellation and resource lifetimes, against servers on the device's
 * loopback so the outcome depends on nothing outside the test.
 */
@RunWith(AndroidJUnit4::class)
class LifecycleTest {
    private val session = Session()

    @After
    fun tearDown() = session.close()

    @Test
    fun paramsGoBeforeTheFragment() {
        assertEquals(
            "https://example.com/path?q=a%20b#part",
            Request("https://example.com/path#part", params = mapOf("q" to "a b")).urlWithParams(),
        )
        assertEquals(
            "https://example.com/path?x=1&q=v#p?not=query",
            Request("https://example.com/path?x=1#p?not=query", params = mapOf("q" to "v")).urlWithParams(),
        )
        assertEquals(
            "https://example.com/?q=v",
            Request("https://example.com/?", params = mapOf("q" to "v")).urlWithParams(),
        )
    }

    @Test
    fun authReplacesAnyCasingOfAuthorization() {
        val headers = Request("https://example.com", headers = mapOf("authorization" to "Bearer stale"))
            .effectiveHeaders("user" to "pass")
        assertEquals(mapOf("authorization" to "Basic dXNlcjpwYXNz"), headers)
    }

    @Test
    fun cookiesMergeWithAnyCasingOfCookie() {
        val headers = Request(
            "https://example.com",
            headers = mapOf("cookie" to "a=1", "Accept" to "*/*"),
            cookies = mapOf("b" to "2"),
        ).effectiveHeaders(null)
        assertEquals(mapOf("cookie" to "a=1; b=2", "Accept" to "*/*"), headers)
    }

    @Test
    fun cancelledCallerNeverStartsTheCall() = runBlocking {
        val started = AtomicBoolean(false)
        val job = launch(Dispatchers.Default) {
            cancel()
            NativeCallbacks.await { started.set(true) }
        }
        job.join()
        assertFalse("a call was started for a coroutine that was already cancelled", started.get())
    }

    @Test
    fun cancellingWhileStartingStillAbortsTheRequest() = runBlocking {
        LoopbackServer().use { server ->
            val inStart = CountDownLatch(1)
            val proceed = CountDownLatch(1)
            val handle = session.handle
            val json = Request(server.url).toJson(null, timeoutMillis = false, inlineBody = true)
            val job = launch(Dispatchers.Default) {
                NativeCallbacks.await { id ->
                    inStart.countDown()
                    proceed.await()
                    Native.requestAsync(handle, json, id)
                }
            }
            assertTrue(inStart.await(5, TimeUnit.SECONDS))
            // Lands inside start(), before the library knows the callback id,
            // so cancelling through the id right now would do nothing.
            job.cancel()
            proceed.countDown()
            job.join()

            // The server never answers, so only an aborted request hangs up
            // before the session's 30s timeout, if it got as far as connecting.
            val aborted = server.hungUpWithin(seconds = 10) || !server.wasConnected
            assertTrue("request was not aborted", aborted)
        }
    }

    @Test
    fun resultArrivingAfterCancellationReachesOnDropped() = runBlocking {
        val dropped = LinkedBlockingQueue<String>()
        val callbackId = LinkedBlockingQueue<Long>()
        val job = GlobalScope.async(Dispatchers.Default, CoroutineStart.UNDISPATCHED) {
            NativeCallbacks.await(onDropped = { dropped.add(it) }) { id -> callbackId.add(id) }
        }
        val id = callbackId.poll(5, TimeUnit.SECONDS)!!
        job.cancel()
        // What the library does for a call it has already finished: deliver.
        NativeCallbacks.onAsyncResult(id, """{"stream_handle":7}""", null)
        Native.unregisterCallback(id) // the library would have removed it on delivery

        assertEquals("""{"stream_handle":7}""", dropped.poll(5, TimeUnit.SECONDS))
    }

    @Test
    fun streamNobodyReceivesIsClosed() {
        LoopbackServer(respond = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n").use { server ->
            // A caller that cancelled by unregistering its callback id.
            val id = Native.registerCallback()
            Native.unregisterCallback(id)
            val json = Request(server.url).toJson(null, timeoutMillis = false, inlineBody = true)
            Native.streamRequestAsync(session.handle, json, id)

            // Unclosed, the stream would hold its connection for two minutes.
            assertTrue("undelivered stream was left open", server.hungUpWithin(seconds = 10))
        }
    }

    @Test
    fun streamPreparesTheRequestOffTheCallersThread() {
        LoopbackServer(respond = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").use { server ->
            val caller = Executors.newSingleThreadExecutor { Thread(it, "caller") }.asCoroutineDispatcher()
            val encodedOn = LinkedBlockingQueue<String>()
            // Encoding the request walks the params, so this sees which thread did it.
            val params = object : AbstractMap<String, String>() {
                override val entries: Set<Map.Entry<String, String>>
                    get() = setOf(java.util.AbstractMap.SimpleEntry("q", "v"))
                        .also { encodedOn.add(Thread.currentThread().name) }
            }
            caller.use {
                runBlocking(it) { session.stream(Request(server.url, params = params)).close() }
            }
            assertFalse(encodedOn.isEmpty())
            assertFalse("request was encoded on the caller's thread", "caller" in encodedOn)
        }
    }

    @Test
    fun streamIsClosedWhenTheCallerIsCancelledOnTheWayBack() {
        LoopbackServer(
            respond = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
            holdResponse = true,
        ).use { server ->
            // The caller only runs when this thread says so, which fixes the order.
            val caller = ManualDispatcher()
            val job = GlobalScope.launch(caller) { session.stream(Request(server.url)) }
            assertTrue(caller.runNext()) // runs up to the switch to Dispatchers.Default
            assertTrue(server.awaitConnection(seconds = 5))

            // The request can only complete now, and completing it queues the
            // return to the caller, carrying the open stream.
            server.releaseResponse()
            val handOver = caller.awaitNext(seconds = 10)
            assertTrue("stream never finished opening", handOver != null)

            job.cancel()
            handOver!!.run()
            while (!job.isCompleted && caller.runNext()) Unit
            assertTrue(job.isCompleted)
            // Unclosed, the stream would hold its connection for two minutes.
            assertTrue("stream discarded on the way back was left open", server.hungUpWithin(seconds = 10))
        }
    }

    @Test
    fun restoredSessionKeepsItsTimeout() {
        val configured = Session(SessionConfig(timeout = 60))
        val restored = Session.unmarshal(configured.marshal())
        configured.close()
        restored.use {
            // Past the 30s the blocking path used to impose on a restored session.
            LoopbackServer(respond = "HTTP/1.1 204 No Content\r\n\r\n", delayMillis = 32_000).use { server ->
                assertEquals(204, it.execute(Request(server.url)).statusCode)
            }
        }
    }
}

/**
 * A one-shot HTTP/1.1 server on 127.0.0.1. It reads a request, then after
 * [delayMillis] writes [respond], or nothing at all if that is null, and
 * holds the connection until the client hangs up. With [holdResponse] it
 * also waits for [releaseResponse] before writing.
 */
private class LoopbackServer(
    private val respond: String? = null,
    private val delayMillis: Long = 0,
    holdResponse: Boolean = false,
) : AutoCloseable {
    // Not getLoopbackAddress(), which is ::1 on Android.
    private val socket = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
    private val connected = CountDownLatch(1)
    private val hungUp = CountDownLatch(1)
    private val released = CountDownLatch(if (holdResponse) 1 else 0)

    val url = "http://127.0.0.1:${socket.localPort}/"

    init {
        thread(isDaemon = true) {
            val client = runCatching { socket.accept() }.getOrNull() ?: return@thread
            connected.countDown()
            client.use {
                runCatching {
                    val input = it.getInputStream()
                    var tail = 0
                    while (tail != 0x0D0A0D0A) {
                        val b = input.read()
                        if (b < 0) return@runCatching
                        tail = (tail shl 8) or b
                    }
                    Thread.sleep(delayMillis)
                    released.await()
                    respond?.let { r -> it.getOutputStream().apply { write(r.toByteArray()); flush() } }
                    while (input.read() >= 0) Unit
                }
                hungUp.countDown() // EOF or reset: the client let go
            }
        }
    }

    /** Whether the client connected and then dropped the connection. */
    fun hungUpWithin(seconds: Long): Boolean = hungUp.await(seconds, TimeUnit.SECONDS)

    /** Whether the client connected at all. */
    val wasConnected: Boolean get() = connected.count == 0L

    /** Waits for the client to connect. */
    fun awaitConnection(seconds: Long): Boolean = connected.await(seconds, TimeUnit.SECONDS)

    /** Lets a held response go out. */
    fun releaseResponse() = released.countDown()

    override fun close() {
        released.countDown()
        socket.close()
    }
}

/**
 * Runs the coroutines dispatched to it only when the test asks, one task at a
 * time on the test's thread, so the test decides what happens in which order.
 */
private class ManualDispatcher : CoroutineDispatcher() {
    private val tasks = LinkedBlockingQueue<Runnable>()

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        tasks.add(block)
    }

    /** Waits for the next task without running it. */
    fun awaitNext(seconds: Long): Runnable? = tasks.poll(seconds, TimeUnit.SECONDS)

    /** Runs the next task, waiting up to [seconds] for one. */
    fun runNext(seconds: Long = 5): Boolean = awaitNext(seconds)?.let { it.run(); true } ?: false
}
