# httpcloak for Android

A Kotlin API over the httpcloak shared library. The usage guide lives in
[docs/docs/bindings/android.md](../../docs/docs/bindings/android.md); this file covers how
the binding is put together, built and tested.

```kotlin
Session(Presets.CHROME_LATEST_ANDROID).use { session ->
    val response = session.get("https://tls.peet.ws/api/all")
    println("${response.statusCode} ${response.protocol}")
}
```

## Layout

```
httpcloak/
  build.gradle.kts            Go cross-compile tasks, CMake, publishing
  consumer-rules.pro          keeps the names the JNI bridge looks up
  src/main/cpp/
    httpcloak_jni.c           the JNI bridge
    CMakeLists.txt
  src/main/kotlin/.../
    Native.kt                 external declarations, one per C export
    NativeCallbacks.kt        upcalls: async results, TLS session cache
    Session.kt, Request.kt, Response.kt, ...   the public API
  src/androidTest/            instrumented tests, run on a device
```

## How it fits together

There are three layers, and each one does a single job:

1. **`libhttpcloak.so`** is `bindings/clib` cross-compiled with the NDK clang, one
   Gradle task per ABI (`buildGo-arm64-v8a`, ...). It is the same C ABI that Python,
   Node.js and .NET call.
2. **`libhttpcloak_jni.so`** is the bridge. Each JNI function forwards to exactly one
   `httpcloak_*` export and only marshals arguments and results. Strings cross as real
   UTF-8 through `String.getBytes`/`new String`, because JNI's own modified UTF-8 would
   corrupt emoji and NULs. When the C API changes, this is the file to update.
3. **Kotlin** builds the request JSON, parses results, maps errors to
   `HttpCloakException` and owns handle lifetimes.

Requests have two paths:

- Suspending calls use `httpcloak_request_async`. The result arrives on a Go thread
  through the `on_async_result` upcall. That thread is attached to the JVM for the call
  and resumes the waiting coroutine. Cancelling the coroutine calls
  `httpcloak_cancel_request`, which cancels the request's Go context.
- Blocking calls use `httpcloak_request_raw`, which takes and returns the body as raw
  bytes.

Mind the one quirk in the C API: `timeout` in the request JSON is milliseconds for
`httpcloak_request_raw` and upload, and seconds for the async and stream entry points.
`Request.toJson` handles the conversion.

## Building

Needs Go (the version in `bindings/clib/go.mod`), JDK 17+, and the Android SDK with NDK
28.2 and CMake 3.22.1 (`sdkmanager "ndk;28.2.13676358" "cmake;3.22.1"`).

```bash
./gradlew :httpcloak:assembleRelease          # AAR in httpcloak/build/outputs/aar/
./gradlew :httpcloak:publishToMavenLocal      # io.github.sardanioss:httpcloak-android
```

All four ABIs are built by default. For quicker local builds, narrow them:

```bash
./gradlew -Phttpcloak.abis=arm64-v8a :httpcloak:assembleDebug
```

The Go build is incremental. Its inputs are the repository's Go sources, so a change to
the core library rebuilds the `.so` files, and anything else reuses them.

Both libraries are linked with 16 KB page alignment, which Android 15+ devices and
Google Play require.

## Testing

The tests are instrumented, because they need the native library. They run against a
connected device or emulator and make real requests to httpbin.org, tls.peet.ws and
cloudflare.com:

```bash
./gradlew -Phttpcloak.abis=arm64-v8a :httpcloak:connectedDebugAndroidTest
```

Pick the ABI your device runs. A 64-bit ARM phone can also run the `armeabi-v7a` build,
which is how the 32-bit ARM library is tested. For `x86`, use an emulator with an API 30
`x86_64` image: newer `x86_64` images are 64-bit only and refuse to install it.

## Versioning

`version` in `httpcloak/build.gradle.kts` is bumped with the other bindings by
`bindings/bump-version.sh`.
