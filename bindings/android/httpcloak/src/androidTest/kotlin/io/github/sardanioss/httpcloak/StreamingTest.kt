package io.github.sardanioss.httpcloak

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException

@RunWith(AndroidJUnit4::class)
class StreamingTest {
    private val session = Session()

    @After
    fun tearDown() = session.close()

    @Test
    fun streamedBodyMatchesBufferedBody() = runBlocking {
        val url = "https://httpbin.org/stream-bytes/200000?seed=3&chunk_size=4096"
        val buffered = session.get(url).body

        session.stream(Request(url)).use { stream ->
            assertEquals(200, stream.statusCode)
            assertArrayEquals(buffered, stream.readBytes())
        }
        session.executeStream(Request(url)).use { stream ->
            assertArrayEquals(buffered, stream.body.readBytes())
        }
    }

    @Test
    fun streamReadsIncrementally() = runBlocking {
        session.stream(Request("https://httpbin.org/drip?numbytes=5&duration=1&delay=0")).use { stream ->
            val buffer = ByteArray(1)
            var total = 0
            while (stream.body.read(buffer) != -1) total++
            assertEquals(5, total)
            assertTrue(stream.trailer().isEmpty())
        }
    }

    @Test(expected = IOException::class)
    fun readingAClosedStreamFails() = runBlocking<Unit> {
        val stream = session.stream(Request("https://httpbin.org/bytes/10"))
        stream.close()
        stream.body.read()
    }

    @Test
    fun uploadStreamsTheBody() {
        val chunk = "0123456789".repeat(1000).toByteArray()
        val response = session.upload("https://httpbin.org/post", contentType = "text/plain").use { upload ->
            repeat(50) { upload.write(chunk) }
            upload.finish()
        }
        assertEquals(200, response.statusCode)
        assertEquals(500_000, (response.json() as JSONObject).getString("data").length)
    }

    @Test(expected = IOException::class)
    fun writingACancelledUploadFails() {
        val upload = session.upload("https://httpbin.org/post")
        upload.cancel()
        upload.write(1)
    }
}
