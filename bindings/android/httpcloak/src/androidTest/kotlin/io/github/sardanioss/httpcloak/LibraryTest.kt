package io.github.sardanioss.httpcloak

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
class LibraryTest {
    @Test
    fun versionAndPresets() {
        assertTrue(HttpCloak.version.matches(Regex("""\d+\.\d+\.\d+.*""")))
        val presets = HttpCloak.availablePresets()
        assertTrue(Presets.CHROME_LATEST in presets)
        assertTrue("h2" in presets.getValue(Presets.CHROME_LATEST))
        assertTrue(HttpCloak.describePreset(Presets.CHROME_LATEST).startsWith("{"))
        HttpCloak.trimMemory()
    }

    @Test
    fun customPresetAndPool() = runBlocking {
        val preset = """{"version":1,"preset":{"name":"android-test-preset","based_on":"chrome-latest",
            "headers":{"user_agent":"AndroidTestAgent/1.0"}}}"""
        assertEquals("android-test-preset", HttpCloak.loadPreset(preset))
        Session("android-test-preset").use { session ->
            val headers = (session.get("https://httpbin.org/headers").json() as JSONObject).getJSONObject("headers")
            assertEquals("AndroidTestAgent/1.0", headers.getString("User-Agent"))
        }
        HttpCloak.unregisterPreset("android-test-preset")
        assertFalse("android-test-preset" in HttpCloak.availablePresets())

        val pool = """{"version":1,"pool":{"name":"rotation","strategy":"round-robin","presets":[
            {"name":"pool-a","based_on":"chrome-latest"},{"name":"pool-b","based_on":"firefox-latest"}]}}"""
        PresetPool.fromJson(pool).use {
            assertEquals("rotation", it.name)
            assertEquals(2, it.size)
            assertEquals(listOf("pool-a", "pool-b", "pool-a"), listOf(it.next(), it.next(), it.next()))
            assertEquals("pool-b", it[1])
            assertTrue(it.random() in listOf("pool-a", "pool-b"))
            assertTrue(it.pick() in listOf("pool-a", "pool-b"))
        }
    }

    @Test(expected = HttpCloakException::class)
    fun invalidPresetIsReported() {
        HttpCloak.loadPreset("{not json")
    }

    @Test
    fun echDnsServers() {
        val defaults = HttpCloak.echDnsServers
        HttpCloak.echDnsServers = listOf("1.1.1.1:53")
        assertEquals(listOf("1.1.1.1:53"), HttpCloak.echDnsServers)
        HttpCloak.echDnsServers = emptyList()
        assertEquals(defaults, HttpCloak.echDnsServers)
    }

    @Test
    fun localProxy() = runBlocking {
        val direct = Session(Presets.CHROME_LATEST).use {
            ((it.get("https://tls.peet.ws/api/all").json() as JSONObject)).getJSONObject("tls").getString("ja4")
        }
        LocalProxy(preset = Presets.CHROME_LATEST).use { proxy ->
            assertTrue(proxy.isRunning)
            assertTrue(proxy.port > 0)

            val connection = URL("http://tls.peet.ws/api/all").openConnection(proxy.asJavaProxy()) as HttpURLConnection
            connection.setRequestProperty("X-HTTPCloak-Scheme", "https")
            val viaProxy = JSONObject(connection.inputStream.bufferedReader().readText())
            assertEquals(direct, viaProxy.getJSONObject("tls").getString("ja4"))

            Session().use { session ->
                proxy.registerSession("s1", session)
                assertTrue(proxy.hasSession("s1"))
                assertEquals(listOf("s1"), proxy.listSessions())
                assertTrue(proxy.unregisterSession("s1"))
                assertFalse(proxy.unregisterSession("s1"))
            }
            val stats = proxy.stats()
            assertTrue(stats.running)
            assertEquals(proxy.port, stats.port)
            assertTrue(stats.totalRequests >= 1)
        }
    }

    @Test
    fun sessionCacheReceivesTickets() = runBlocking {
        val store = ConcurrentHashMap<String, String>()
        val hits = AtomicInteger()
        HttpCloak.setSessionCache(object : SessionCache {
            override fun get(key: String) = store[key]?.also { hits.incrementAndGet() }
            override fun put(key: String, value: String, ttlSeconds: Long) {
                store[key] = value
            }
            override fun delete(key: String) {
                store.remove(key)
            }
        })
        try {
            Session(SessionConfig(httpVersion = "h2")).use { it.get("https://www.cloudflare.com/cdn-cgi/trace") }
            assertTrue("no ticket was stored", store.isNotEmpty())
            // A fresh session can read the stored ticket back.
            Session(SessionConfig(httpVersion = "h2")).use {
                assertEquals(200, it.get("https://www.cloudflare.com/cdn-cgi/trace").statusCode)
            }
            assertTrue("the stored ticket was never read", hits.get() > 0)
        } finally {
            HttpCloak.setSessionCache(null)
        }
    }
}
