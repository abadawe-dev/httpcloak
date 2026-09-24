package io.github.sardanioss.httpcloak

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class SessionTest {
    private val session = Session()

    @After
    fun tearDown() = session.close()

    @Test
    fun cookieJar() = runBlocking {
        session.get("https://httpbin.org/cookies/set?from_server=1")
        assertEquals("1", session.getCookie("from_server")?.value)

        session.setCookie(Cookie("manual", "2", domain = "httpbin.org", path = "/"))
        val sent = (session.get("https://httpbin.org/cookies").json() as JSONObject).getJSONObject("cookies")
        assertEquals("1", sent.getString("from_server"))
        assertEquals("2", sent.getString("manual"))

        session.deleteCookie("manual")
        assertNull(session.getCookie("manual"))
        session.clearCookies()
        assertTrue(session.getCookies().isEmpty())
    }

    @Test
    fun marshalSaveAndLoadKeepCookies() = runBlocking {
        session.setCookie(Cookie("kept", "yes", domain = "httpbin.org", path = "/"))

        Session.unmarshal(session.marshal()).use { restored ->
            assertEquals("yes", restored.getCookie("kept")?.value)
        }

        val file = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "session.json")
        session.save(file.path)
        Session.load(file.path).use { loaded ->
            assertEquals("yes", loaded.getCookie("kept")?.value)
            assertEquals(200, loaded.get("https://httpbin.org/get").statusCode)
        }
    }

    @Test
    fun forkSharesCookies() = runBlocking {
        session.fork().use { tab ->
            tab.get("https://httpbin.org/cookies/set?shared=1")
            assertEquals("1", session.getCookie("shared")?.value)
        }
    }

    @Test
    fun settingsRoundTrip() {
        session.proxy = "http://127.0.0.1:9"
        assertEquals("http://127.0.0.1:9", session.proxy)
        session.proxy = null
        assertNull(session.proxy)

        session.tcpProxy = "socks5://127.0.0.1:9"
        assertEquals("socks5://127.0.0.1:9", session.tcpProxy)
        session.udpProxy = "masque://127.0.0.1:9"
        assertEquals("masque://127.0.0.1:9", session.udpProxy)

        session.headerOrder = listOf("accept", "user-agent")
        assertEquals(listOf("accept", "user-agent"), session.headerOrder)

        for (flag in listOf(false, true)) {
            session.conditionalCache = flag
            assertEquals(flag, session.conditionalCache)
            session.clientHints = flag
            assertEquals(flag, session.clientHints)
            session.highEntropyClientHints = flag
            assertEquals(flag, session.highEntropyClientHints)
            session.followRedirects = flag
            assertEquals(flag, session.followRedirects)
        }
        session.maxRedirects = 3
        assertEquals(3, session.maxRedirects)

        session.setIdentifier("tenant-1")
        session.clearCache()
        session.refresh()
        session.refresh("h2")
    }

    @Test
    fun statsAndLifecycle() = runBlocking {
        session.get("https://httpbin.org/get")
        val stats = session.stats()
        assertEquals(1L, stats.requestCount)
        assertTrue(stats.active)
        session.touch()
        assertTrue(session.idleTimeMillis < 1000)

        session.close()
        session.close()
        assertFalse(session.isActive)
        try {
            session.get("https://httpbin.org/get")
            throw AssertionError("expected IllegalStateException")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun sessionOptionsReachTheLibrary() = runBlocking {
        Session(
            SessionConfig(
                preset = Presets.FIREFOX_LATEST,
                timeout = 20,
                allowRedirects = false,
                retry = 1,
                retryOnStatus = listOf(503),
                withoutClientHints = true,
                disableEch = true,
                connectTo = mapOf("example.invalid" to "httpbin.org"),
            ),
        ).use { firefox ->
            assertFalse(firefox.followRedirects)
            assertFalse(firefox.clientHints)
            val ua = (firefox.get("https://httpbin.org/headers").json() as JSONObject)
                .getJSONObject("headers").getString("User-Agent")
            assertTrue(ua, ua.contains("Firefox"))
            assertEquals(302, firefox.get("https://httpbin.org/redirect/1").statusCode)
        }
    }

    @Test
    fun customJa3Fingerprint() = runBlocking {
        val ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
            "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
        Session(SessionConfig(ja3 = ja3, httpVersion = "h2")).use { custom ->
            val tls = (custom.get("https://tls.peet.ws/api/all").json() as JSONObject).getJSONObject("tls")
            val sent = tls.getString("ja3").split(",")
            assertEquals(ja3.split(",")[1], sent[1])
        }
    }
}
