---
title: Android (Kotlin)
sidebar_position: 5
---

# Android (Kotlin)

The Android binding is a Kotlin API over the same cgo-built library the other bindings use, cross-compiled with the NDK and reached through a thin JNI bridge. The wire behaviour is the same as everywhere else: a session on a phone sends the same JA4, HTTP/2 settings and header order as the same preset on a desktop.

The surface follows Kotlin conventions: `suspend` functions that abort the request when their coroutine is cancelled, `Closeable` for everything that owns native resources, data classes with named arguments for options.

## Install

The binding is an Android library (AAR) with native code for `arm64-v8a`, `armeabi-v7a`, `x86_64` and `x86`. Build and install it into your local Maven repository:

```bash
cd bindings/android
./gradlew :httpcloak:publishToMavenLocal
```

then depend on it:

```kotlin
repositories { mavenLocal() }
dependencies { implementation("io.github.sardanioss:httpcloak-android:1.7.2") }
```

Or build the AAR alone with `./gradlew :httpcloak:assembleRelease` and take it from `httpcloak/build/outputs/aar/`. Building needs Go, a JDK 17+ and the Android SDK with NDK 28.

Requires Android 7.0 (API 24) or newer. The library declares the `INTERNET` permission.

## Quick start

```kotlin
import io.github.sardanioss.httpcloak.*

Session(Presets.CHROME_LATEST_ANDROID).use { session ->
    val r = session.get("https://tls.peet.ws/api/all")
    println("${r.statusCode} ${r.protocol} ${r.text.length}")
}
```

Suspending calls are main-safe: the request runs on the library's own threads, so they can be called from `lifecycleScope` or `viewModelScope` directly. Cancelling the scope aborts the request in flight.

## `Session`

Created from a `SessionConfig`, whose fields match the [options reference](/reference/options). Anything left unset is decided by the native library, so defaults match the other bindings.

```kotlin
val session = Session(
    SessionConfig(
        preset = Presets.CHROME_LATEST_ANDROID,
        proxy = "socks5://user:pass@host:1080",
        timeout = 20,
        httpVersion = "h3",
        retry = 2,
        retryOnStatus = listOf(502, 503),
        withoutClientHints = true,
    ),
)
session.auth = "user" to "secret"   // default Basic auth for every request
```

`Session("chrome-latest")` is shorthand for a config with only a preset.

### Requests

Every request is a `Request`, and only the URL is required:

```kotlin
val r = session.request(
    Request(
        url = "https://api.example.com/items",
        method = "POST",
        headers = mapOf("X-Api-Key" to key),
        body = Body.json("""{"name":"widget"}"""),
        params = mapOf("dry_run" to "1"),
        cookies = mapOf("session" to "abc"),
        timeout = 10,                         // seconds
        fetchMode = "cors",
        allowRedirects = false,
        disableClientHints = true,
        headerOrder = listOf("x-api-key", "content-type"),
    ),
)
```

Shorthands cover the common cases: `get`, `post`, `put`, `patch`, `delete`, `head` and `options`, each taking the URL, headers, query parameters and (where it applies) a body.

`exactHeaders` replaces the header pipeline entirely: the pairs go out in the given order and casing, a name may repeat, and nothing else is added.

### Bodies

```kotlin
Body.text("plain or JSON text")              // JSON-looking text is sent as application/json
Body.json("""{"a":1}""")
Body.form(mapOf("user" to "me"))            // application/x-www-form-urlencoded
Body.multipart(
    fields = mapOf("title" to "report"),
    files = mapOf("file" to MultipartFile(bytes, "report.pdf", "application/pdf")),
)
Body(bytes, "application/octet-stream")     // anything else
```

Multipart bodies use a Chrome-shaped `----WebKitFormBoundary` boundary.

### Blocking calls

`execute(request)` and `executeStream(request)` block the calling thread, for background threads, Java callers and tests. Don't call them on the main thread.

```kotlin
val r = withContext(Dispatchers.IO) { session.execute(Request(url)) }
```

The blocking path hands the body across as raw bytes, while the suspending path carries it in the result JSON. Both return the same `Response`.

### Streaming responses

```kotlin
session.stream(Request("https://example.com/big.bin")).use { stream ->
    println("${stream.statusCode} ${stream.contentLength}")
    stream.body.copyTo(file.outputStream())   // an InputStream
    val grpcStatus = stream.trailer()["grpc-status"]
}
```

`stream()` suspends until the headers arrive. The request timeout bounds the whole stream and defaults to two minutes, so raise it for long-lived streams. Streaming does not follow redirects.

### Streaming uploads

For bodies too large to hold in memory:

```kotlin
val response = session.upload(url, contentType = "application/octet-stream").use { upload ->
    file.inputStream().copyTo(upload)   // an OutputStream
    upload.finish()
}
```

Closing an upload before `finish()` cancels it.

### Cookies

```kotlin
session.getCookies()                   // List<Cookie>
session.getCookie("sid")
session.setCookie(Cookie("sid", "abc", domain = "example.com", path = "/"))
session.deleteCookie("sid")
session.clearCookies()
```

### Settings after creation

```kotlin
session.proxy = "http://host:8080"   // null clears it; also tcpProxy, udpProxy
session.headerOrder = listOf("accept", "user-agent")
session.followRedirects = false
session.maxRedirects = 3
session.conditionalCache = false
session.clientHints = false
session.highEntropyClientHints = false
```

### Lifecycle and persistence

```kotlin
session.refresh()                    // new connections, same cookies and TLS tickets
session.refresh("h2")                // ...and switch protocol
session.fork().use { tab -> }        // shares cookies and tickets, own connections
session.warmup("https://example.com") // a browser-like page load
session.save(File(filesDir, "session.json").path)
Session.load(path)
Session.unmarshal(session.marshal())
session.stats()                      // SessionStats
session.close()
```

A closed session throws `IllegalStateException` on use. Sessions are not closed for you, so pair each with `use {}` or a lifecycle callback.

## `Response`

| Member | Type | Notes |
|---|---|---|
| `statusCode` | `Int` | |
| `ok` | `Boolean` | status below 400 |
| `headers` | `Map<String, List<String>>` | case-insensitive lookups |
| `header(name)` | `String?` | first value |
| `body` | `ByteArray` | |
| `text` | `String` | decoded with the Content-Type charset, UTF-8 by default |
| `json()` | `Any?` | `JSONObject`, `JSONArray` or a scalar |
| `url` | `String` | final URL after redirects |
| `protocol` | `String` | `h1`, `h2` or `h3` |
| `cookies` | `List<Cookie>` | set by this response |
| `history` | `List<RedirectInfo>` | redirects followed |
| `headerOrder`, `headerCasing` | `List<String>` | as the server sent them |
| `trailer` | `Map<String, List<String>>` | |
| `elapsedMillis` | `Long` | |
| `raiseForStatus()` | `Response` | throws on 4xx/5xx |

Failures throw `HttpCloakException`, an `IOException`. When it comes from `raiseForStatus()`, its `response` is set.

## Library-wide

```kotlin
HttpCloak.version
HttpCloak.availablePresets()               // name -> supported protocols
HttpCloak.echDnsServers = listOf("1.1.1.1:53")
HttpCloak.trimMemory()

val name = HttpCloak.loadPreset(presetJson) // custom presets, see the JSON preset spec
HttpCloak.describePreset(name)
HttpCloak.unregisterPreset(name)

PresetPool.fromJson(poolJson).use { pool -> Session(pool.next()) }
```

### TLS session cache

A `SessionCache` stores TLS session tickets outside the process, so resumption survives an app restart. It applies to sessions created after it is installed:

```kotlin
HttpCloak.setSessionCache(object : SessionCache {
    override fun get(key: String) = prefs.getString(key, null)
    override fun put(key: String, value: String, ttlSeconds: Long) { prefs.edit { putString(key, value) } }
    override fun delete(key: String) { prefs.edit { remove(key) } }
})
```

The methods run on the library's threads and may block.

### Local proxy

`LocalProxy` serves an HTTP proxy on `127.0.0.1` for clients that can only be pointed at a proxy:

```kotlin
LocalProxy(preset = Presets.CHROME_LATEST).use { proxy ->
    val client = OkHttpClient.Builder().proxy(proxy.asJavaProxy()).build()
}
```

Fingerprinting applies to plain-HTTP requests through the proxy. To reach an HTTPS origin with a fingerprint, request its `http://` URL with the header `X-HTTPCloak-Scheme: https`, because HTTPS sent as a `CONNECT` tunnel carries the client's own TLS. Android blocks cleartext HTTP by default, so allow it for `127.0.0.1` in your network security config.

## Choosing a preset

`chrome-latest` is desktop Chrome on Linux. To look like Chrome on a phone, use `Presets.CHROME_LATEST_ANDROID`.

## Java

Constructors and non-suspending methods carry `@JvmOverloads`/`@JvmStatic`, so Java can use `new Session(new SessionConfig())` with `session.execute(new Request(url))`. The `suspend` functions are Kotlin-only.

## See also

- [Options reference](/reference/options)
- [JSON preset spec](/reference/json-preset-spec)
- `bindings/android/README.md` for how the binding is built and tested
