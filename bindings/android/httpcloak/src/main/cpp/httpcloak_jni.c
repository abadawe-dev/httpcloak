// JNI bridge between the Kotlin API (Native.kt) and libhttpcloak.
//
// Each downcall below forwards to exactly one httpcloak_* export and does
// nothing but marshal arguments and results. Request building, response
// parsing and error handling all live in Kotlin (or Go), so this file only
// changes when the C ABI does.
//
// Strings cross as real UTF-8 by way of String.getBytes and new String. JNI's
// own GetStringUTFChars/NewStringUTF speak "modified UTF-8", which encodes NUL
// and every character outside the BMP differently and would mangle an emoji
// in a JSON body or a header value.
//
// Strings returned by the library are owned by the caller; take_string frees
// them once they are copied into the JVM.

#include <jni.h>
#include <stdlib.h>
#include <string.h>

// The cgo-generated header carries the static helpers from clib's preamble.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "libhttpcloak.h"
#pragma clang diagnostic pop

#define JNI(ret, name) \
    JNIEXPORT ret JNICALL Java_io_github_sardanioss_httpcloak_Native_##name

static JavaVM *g_vm;
static jclass g_string_class;
static jmethodID g_string_init;      // String(byte[], Charset)
static jmethodID g_string_get_bytes; // String.getBytes(Charset)
static jobject g_utf8;               // StandardCharsets.UTF_8

static jclass g_callbacks_class;     // NativeCallbacks
static jmethodID g_on_async_result;
static jmethodID g_cache_get;
static jmethodID g_cache_put;
static jmethodID g_cache_delete;
static jmethodID g_ech_get;
static jmethodID g_ech_put;
static jmethodID g_cache_error;

// ---------------------------------------------------------------------------
// Marshalling helpers
// ---------------------------------------------------------------------------

// Java String -> malloc'd, NUL-terminated UTF-8. NULL stays NULL.
static char *utf8_from_java(JNIEnv *env, jstring s) {
    if (s == NULL) return NULL;
    jbyteArray bytes = (*env)->CallObjectMethod(env, s, g_string_get_bytes, g_utf8);
    if (bytes == NULL) return NULL;
    jsize len = (*env)->GetArrayLength(env, bytes);
    char *out = malloc((size_t) len + 1);
    if (out != NULL) {
        (*env)->GetByteArrayRegion(env, bytes, 0, len, (jbyte *) out);
        out[len] = '\0';
    }
    (*env)->DeleteLocalRef(env, bytes);
    return out;
}

// UTF-8 -> Java String, borrowing the input. NULL stays NULL.
static jstring java_from_utf8(JNIEnv *env, const char *s) {
    if (s == NULL) return NULL;
    jsize len = (jsize) strlen(s);
    jbyteArray bytes = (*env)->NewByteArray(env, len);
    if (bytes == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (const jbyte *) s);
    jstring out = (*env)->NewObject(env, g_string_class, g_string_init, bytes, g_utf8);
    (*env)->DeleteLocalRef(env, bytes);
    return out;
}

// Like java_from_utf8, then frees a string the library handed over.
static jstring take_string(JNIEnv *env, char *s) {
    jstring out = java_from_utf8(env, s);
    if (s != NULL) httpcloak_free_string(s);
    return out;
}

// Copies arr[off, off+len) into a malloc'd buffer.
static void *copy_region(JNIEnv *env, jbyteArray arr, jint off, jint len) {
    void *buf = malloc(len > 0 ? (size_t) len : 1);
    if (buf != NULL && len > 0) (*env)->GetByteArrayRegion(env, arr, off, len, buf);
    return buf;
}

// ---------------------------------------------------------------------------
// Upcalls. The library invokes these on its own threads, which the JVM has
// never seen, so each one attaches for the duration of the call. They must
// never let a Java exception escape back into Go.
// ---------------------------------------------------------------------------

static JNIEnv *attach(int *attached) {
    JNIEnv *env = NULL;
    *attached = 0;
    jint rc = (*g_vm)->GetEnv(g_vm, (void **) &env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThreadAsDaemon(g_vm, &env, NULL) != JNI_OK) return NULL;
        *attached = 1;
    } else if (rc != JNI_OK) {
        return NULL;
    }
    return env;
}

static void detach(JNIEnv *env, int attached) {
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

static void on_async_result(int64_t callback_id, const char *response_json, const char *error) {
    int attached;
    JNIEnv *env = attach(&attached);
    if (env == NULL) return;
    jstring json = java_from_utf8(env, response_json);
    jstring err = java_from_utf8(env, error);
    (*env)->CallStaticVoidMethod(env, g_callbacks_class, g_on_async_result,
                                 (jlong) callback_id, json, err);
    (*env)->DeleteLocalRef(env, json);
    (*env)->DeleteLocalRef(env, err);
    detach(env, attached);
}

// The library copies a string returned by a cache getter and never frees it.
// Each thread keeps its latest answer alive and frees it on its next call.
static __thread char *t_cache_value;

static char *cache_lookup(jmethodID method, const char *key) {
    int attached;
    JNIEnv *env = attach(&attached);
    if (env == NULL) return NULL;
    jstring jkey = java_from_utf8(env, key);
    jstring value = (*env)->CallStaticObjectMethod(env, g_callbacks_class, method, jkey);
    free(t_cache_value);
    t_cache_value = (*env)->ExceptionCheck(env) ? NULL : utf8_from_java(env, value);
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, value);
    detach(env, attached);
    return t_cache_value;
}

static int cache_store(jmethodID method, const char *key, const char *value, int64_t ttl_seconds) {
    int attached;
    JNIEnv *env = attach(&attached);
    if (env == NULL) return -1;
    jstring jkey = java_from_utf8(env, key);
    jstring jvalue = java_from_utf8(env, value);
    jboolean ok = (*env)->CallStaticBooleanMethod(env, g_callbacks_class, method,
                                                  jkey, jvalue, (jlong) ttl_seconds);
    if ((*env)->ExceptionCheck(env)) ok = JNI_FALSE;
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, jvalue);
    detach(env, attached);
    return ok ? 0 : -1;
}

static char *on_cache_get(const char *key) { return cache_lookup(g_cache_get, key); }

static char *on_ech_get(const char *key) { return cache_lookup(g_ech_get, key); }

static int on_cache_put(const char *key, const char *value, int64_t ttl) {
    return cache_store(g_cache_put, key, value, ttl);
}

static int on_ech_put(const char *key, const char *value, int64_t ttl) {
    return cache_store(g_ech_put, key, value, ttl);
}

static int on_cache_delete(const char *key) {
    int attached;
    JNIEnv *env = attach(&attached);
    if (env == NULL) return -1;
    jstring jkey = java_from_utf8(env, key);
    jboolean ok = (*env)->CallStaticBooleanMethod(env, g_callbacks_class, g_cache_delete, jkey);
    if ((*env)->ExceptionCheck(env)) ok = JNI_FALSE;
    (*env)->DeleteLocalRef(env, jkey);
    detach(env, attached);
    return ok ? 0 : -1;
}

static void on_cache_error(const char *operation, const char *key, const char *error) {
    int attached;
    JNIEnv *env = attach(&attached);
    if (env == NULL) return;
    jstring jop = java_from_utf8(env, operation);
    jstring jkey = java_from_utf8(env, key);
    jstring jerr = java_from_utf8(env, error);
    (*env)->CallStaticVoidMethod(env, g_callbacks_class, g_cache_error, jop, jkey, jerr);
    (*env)->DeleteLocalRef(env, jop);
    (*env)->DeleteLocalRef(env, jkey);
    (*env)->DeleteLocalRef(env, jerr);
    detach(env, attached);
}

// ---------------------------------------------------------------------------
// Load-time lookups
// ---------------------------------------------------------------------------

static jclass global_class(JNIEnv *env, const char *name) {
    jclass local = (*env)->FindClass(env, name);
    if (local == NULL) return NULL;
    jclass global = (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    return global;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    g_vm = vm;

    g_string_class = global_class(env, "java/lang/String");
    jclass charsets = (*env)->FindClass(env, "java/nio/charset/StandardCharsets");
    g_callbacks_class = global_class(env, "io/github/sardanioss/httpcloak/NativeCallbacks");
    if (g_string_class == NULL || charsets == NULL || g_callbacks_class == NULL) return JNI_ERR;

    jfieldID utf8 = (*env)->GetStaticFieldID(env, charsets, "UTF_8", "Ljava/nio/charset/Charset;");
    g_utf8 = (*env)->NewGlobalRef(env, (*env)->GetStaticObjectField(env, charsets, utf8));
    g_string_init = (*env)->GetMethodID(env, g_string_class, "<init>",
                                        "([BLjava/nio/charset/Charset;)V");
    g_string_get_bytes = (*env)->GetMethodID(env, g_string_class, "getBytes",
                                             "(Ljava/nio/charset/Charset;)[B");

    jclass cb = g_callbacks_class;
    g_on_async_result = (*env)->GetStaticMethodID(env, cb, "onAsyncResult",
                                                  "(JLjava/lang/String;Ljava/lang/String;)V");
    g_cache_get = (*env)->GetStaticMethodID(env, cb, "cacheGet",
                                            "(Ljava/lang/String;)Ljava/lang/String;");
    g_cache_put = (*env)->GetStaticMethodID(env, cb, "cachePut",
                                            "(Ljava/lang/String;Ljava/lang/String;J)Z");
    g_cache_delete = (*env)->GetStaticMethodID(env, cb, "cacheDelete", "(Ljava/lang/String;)Z");
    g_ech_get = (*env)->GetStaticMethodID(env, cb, "echGet",
                                          "(Ljava/lang/String;)Ljava/lang/String;");
    g_ech_put = (*env)->GetStaticMethodID(env, cb, "echPut",
                                          "(Ljava/lang/String;Ljava/lang/String;J)Z");
    g_cache_error = (*env)->GetStaticMethodID(
            env, cb, "cacheError", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");

    if ((*env)->ExceptionCheck(env)) return JNI_ERR; // a lookup above failed
    return JNI_VERSION_1_6;
}

// ---------------------------------------------------------------------------
// Library-wide
// ---------------------------------------------------------------------------

JNI(jstring, version)(JNIEnv *env, jclass cls) {
    return take_string(env, httpcloak_version());
}

JNI(jstring, availablePresets)(JNIEnv *env, jclass cls) {
    return take_string(env, httpcloak_available_presets());
}

JNI(jstring, setEchDnsServers)(JNIEnv *env, jclass cls, jstring servers_json) {
    char *servers = utf8_from_java(env, servers_json);
    jstring out = take_string(env, httpcloak_set_ech_dns_servers(servers));
    free(servers);
    return out;
}

JNI(jstring, getEchDnsServers)(JNIEnv *env, jclass cls) {
    return take_string(env, httpcloak_get_ech_dns_servers());
}

JNI(void, trimMemory)(JNIEnv *env, jclass cls) {
    httpcloak_trim_memory();
}

JNI(void, setSessionCacheCallbacks)(JNIEnv *env, jclass cls) {
    httpcloak_set_session_cache_callbacks(on_cache_get, on_cache_put, on_cache_delete,
                                          on_ech_get, on_ech_put, on_cache_error);
}

JNI(void, clearSessionCacheCallbacks)(JNIEnv *env, jclass cls) {
    httpcloak_clear_session_cache_callbacks();
}

// ---------------------------------------------------------------------------
// Custom presets and preset pools
// ---------------------------------------------------------------------------

JNI(jstring, presetLoadFile)(JNIEnv *env, jclass cls, jstring path) {
    char *p = utf8_from_java(env, path);
    jstring out = take_string(env, httpcloak_preset_load_file(p));
    free(p);
    return out;
}

JNI(jstring, presetLoadJson)(JNIEnv *env, jclass cls, jstring json) {
    char *j = utf8_from_java(env, json);
    jstring out = take_string(env, httpcloak_preset_load_json(j));
    free(j);
    return out;
}

JNI(void, presetUnregister)(JNIEnv *env, jclass cls, jstring name) {
    char *n = utf8_from_java(env, name);
    httpcloak_preset_unregister(n);
    free(n);
}

JNI(jstring, describePreset)(JNIEnv *env, jclass cls, jstring name) {
    char *n = utf8_from_java(env, name);
    jstring out = take_string(env, httpcloak_describe_preset(n));
    free(n);
    return out;
}

JNI(jstring, poolLoadFile)(JNIEnv *env, jclass cls, jstring path) {
    char *p = utf8_from_java(env, path);
    jstring out = take_string(env, httpcloak_pool_load_file(p));
    free(p);
    return out;
}

JNI(jstring, poolLoadJson)(JNIEnv *env, jclass cls, jstring json) {
    char *j = utf8_from_java(env, json);
    jstring out = take_string(env, httpcloak_pool_load_json(j));
    free(j);
    return out;
}

JNI(jstring, poolPick)(JNIEnv *env, jclass cls, jlong pool) {
    return take_string(env, httpcloak_pool_pick(pool));
}

JNI(jstring, poolRandom)(JNIEnv *env, jclass cls, jlong pool) {
    return take_string(env, httpcloak_pool_random(pool));
}

JNI(jstring, poolNext)(JNIEnv *env, jclass cls, jlong pool) {
    return take_string(env, httpcloak_pool_next(pool));
}

JNI(jstring, poolGet)(JNIEnv *env, jclass cls, jlong pool, jlong index) {
    return take_string(env, httpcloak_pool_get(pool, index));
}

JNI(jlong, poolSize)(JNIEnv *env, jclass cls, jlong pool) {
    return httpcloak_pool_size(pool);
}

JNI(jstring, poolName)(JNIEnv *env, jclass cls, jlong pool) {
    return take_string(env, httpcloak_pool_name(pool));
}

JNI(void, poolFree)(JNIEnv *env, jclass cls, jlong pool) {
    httpcloak_pool_free(pool);
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

JNI(jlong, sessionNew)(JNIEnv *env, jclass cls, jstring config_json) {
    char *config = utf8_from_java(env, config_json);
    jlong handle = httpcloak_session_new(config);
    free(config);
    return handle;
}

JNI(void, sessionFree)(JNIEnv *env, jclass cls, jlong session) {
    httpcloak_session_free(session);
}

JNI(jlong, sessionFork)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_fork(session);
}

JNI(void, sessionRefresh)(JNIEnv *env, jclass cls, jlong session) {
    httpcloak_session_refresh(session);
}

JNI(jstring, sessionRefreshProtocol)(JNIEnv *env, jclass cls, jlong session, jstring protocol) {
    char *p = utf8_from_java(env, protocol);
    jstring out = take_string(env, httpcloak_session_refresh_protocol(session, p));
    free(p);
    return out;
}

JNI(jstring, sessionWarmup)(JNIEnv *env, jclass cls, jlong session, jstring url, jlong timeout_ms) {
    char *u = utf8_from_java(env, url);
    jstring out = take_string(env, httpcloak_session_warmup(session, u, timeout_ms));
    free(u);
    return out;
}

JNI(jstring, sessionSave)(JNIEnv *env, jclass cls, jlong session, jstring path) {
    char *p = utf8_from_java(env, path);
    jstring out = take_string(env, httpcloak_session_save(session, p));
    free(p);
    return out;
}

JNI(jlong, sessionLoad)(JNIEnv *env, jclass cls, jstring path) {
    char *p = utf8_from_java(env, path);
    jlong handle = httpcloak_session_load(p);
    free(p);
    return handle;
}

JNI(jstring, sessionMarshal)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_session_marshal(session));
}

JNI(jlong, sessionUnmarshal)(JNIEnv *env, jclass cls, jstring data) {
    char *d = utf8_from_java(env, data);
    jlong handle = httpcloak_session_unmarshal(d);
    free(d);
    return handle;
}

JNI(jstring, lastError)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_last_error(session));
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

JNI(jlong, requestRaw)(JNIEnv *env, jclass cls, jlong session, jstring request_json,
                       jbyteArray body) {
    char *request = utf8_from_java(env, request_json);
    jint len = body != NULL ? (*env)->GetArrayLength(env, body) : 0;
    char *bytes = body != NULL ? copy_region(env, body, 0, len) : NULL;
    jlong response = httpcloak_request_raw(session, request, bytes, len);
    free(bytes);
    free(request);
    return response;
}

JNI(jstring, responseGetMetadata)(JNIEnv *env, jclass cls, jlong response) {
    return take_string(env, httpcloak_response_get_metadata(response));
}

JNI(jbyteArray, responseGetBody)(JNIEnv *env, jclass cls, jlong response) {
    int len = 0;
    // A malloc'd copy. (The zero-copy httpcloak_response_get_body_ptr returns
    // a Go pointer, which the cgo pointer checks reject with a panic.)
    void *body = httpcloak_response_get_body(response, &len);
    jbyteArray out = (*env)->NewByteArray(env, len);
    if (out != NULL && len > 0) (*env)->SetByteArrayRegion(env, out, 0, len, body);
    free(body);
    return out;
}

JNI(void, responseFree)(JNIEnv *env, jclass cls, jlong response) {
    httpcloak_response_free(response);
}

JNI(jlong, registerCallback)(JNIEnv *env, jclass cls) {
    return httpcloak_register_callback(on_async_result);
}

JNI(void, unregisterCallback)(JNIEnv *env, jclass cls, jlong callback_id) {
    httpcloak_unregister_callback(callback_id);
}

JNI(void, cancelRequest)(JNIEnv *env, jclass cls, jlong callback_id) {
    httpcloak_cancel_request(callback_id);
}

JNI(void, requestAsync)(JNIEnv *env, jclass cls, jlong session, jstring request_json,
                        jlong callback_id) {
    char *request = utf8_from_java(env, request_json);
    httpcloak_request_async(session, request, callback_id);
    free(request);
}

// ---------------------------------------------------------------------------
// Streaming responses and uploads
// ---------------------------------------------------------------------------

JNI(jlong, streamRequest)(JNIEnv *env, jclass cls, jlong session, jstring request_json) {
    char *request = utf8_from_java(env, request_json);
    jlong stream = httpcloak_stream_request(session, request);
    free(request);
    return stream;
}

JNI(void, streamRequestAsync)(JNIEnv *env, jclass cls, jlong session, jstring request_json,
                              jlong callback_id) {
    char *request = utf8_from_java(env, request_json);
    httpcloak_stream_request_async(session, request, callback_id);
    free(request);
}

JNI(jstring, streamGetMetadata)(JNIEnv *env, jclass cls, jlong stream) {
    return take_string(env, httpcloak_stream_get_metadata(stream));
}

JNI(jint, streamReadRaw)(JNIEnv *env, jclass cls, jlong stream, jbyteArray dst, jint off,
                         jint len) {
    void *buf = malloc(len > 0 ? (size_t) len : 1);
    if (buf == NULL) return -1;
    int n = httpcloak_stream_read_raw(stream, buf, len);
    if (n > 0) (*env)->SetByteArrayRegion(env, dst, off, n, buf);
    free(buf);
    return n;
}

JNI(jstring, streamTrailer)(JNIEnv *env, jclass cls, jlong stream) {
    return take_string(env, httpcloak_stream_trailer(stream));
}

JNI(void, streamClose)(JNIEnv *env, jclass cls, jlong stream) {
    httpcloak_stream_close(stream);
}

JNI(jlong, uploadStart)(JNIEnv *env, jclass cls, jlong session, jstring url,
                        jstring options_json) {
    char *u = utf8_from_java(env, url);
    char *options = utf8_from_java(env, options_json);
    jlong upload = httpcloak_upload_start(session, u, options);
    free(options);
    free(u);
    return upload;
}

JNI(jint, uploadWriteRaw)(JNIEnv *env, jclass cls, jlong upload, jbyteArray src, jint off,
                          jint len) {
    void *buf = copy_region(env, src, off, len);
    if (buf == NULL) return -1;
    int n = httpcloak_upload_write_raw(upload, buf, len);
    free(buf);
    return n;
}

JNI(jstring, uploadFinish)(JNIEnv *env, jclass cls, jlong upload) {
    return take_string(env, httpcloak_upload_finish(upload));
}

JNI(void, uploadCancel)(JNIEnv *env, jclass cls, jlong upload) {
    httpcloak_upload_cancel(upload);
}

// ---------------------------------------------------------------------------
// Session state: cookies, proxies, headers, flags
// ---------------------------------------------------------------------------

JNI(jstring, getCookies)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_get_cookies(session));
}

JNI(void, setCookie)(JNIEnv *env, jclass cls, jlong session, jstring cookie_json) {
    char *cookie = utf8_from_java(env, cookie_json);
    httpcloak_set_cookie(session, cookie);
    free(cookie);
}

JNI(void, deleteCookie)(JNIEnv *env, jclass cls, jlong session, jstring name, jstring domain) {
    char *n = utf8_from_java(env, name);
    char *d = utf8_from_java(env, domain);
    httpcloak_delete_cookie(session, n, d);
    free(d);
    free(n);
}

JNI(void, clearCookies)(JNIEnv *env, jclass cls, jlong session) {
    httpcloak_clear_cookies(session);
}

JNI(jstring, setProxy)(JNIEnv *env, jclass cls, jlong session, jstring url) {
    char *u = utf8_from_java(env, url);
    jstring out = take_string(env, httpcloak_session_set_proxy(session, u));
    free(u);
    return out;
}

JNI(jstring, setTcpProxy)(JNIEnv *env, jclass cls, jlong session, jstring url) {
    char *u = utf8_from_java(env, url);
    jstring out = take_string(env, httpcloak_session_set_tcp_proxy(session, u));
    free(u);
    return out;
}

JNI(jstring, setUdpProxy)(JNIEnv *env, jclass cls, jlong session, jstring url) {
    char *u = utf8_from_java(env, url);
    jstring out = take_string(env, httpcloak_session_set_udp_proxy(session, u));
    free(u);
    return out;
}

JNI(jstring, getProxy)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_session_get_proxy(session));
}

JNI(jstring, getTcpProxy)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_session_get_tcp_proxy(session));
}

JNI(jstring, getUdpProxy)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_session_get_udp_proxy(session));
}

JNI(jstring, setHeaderOrder)(JNIEnv *env, jclass cls, jlong session, jstring order_json) {
    char *order = utf8_from_java(env, order_json);
    jstring out = take_string(env, httpcloak_session_set_header_order(session, order));
    free(order);
    return out;
}

JNI(jstring, getHeaderOrder)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_session_get_header_order(session));
}

JNI(void, setIdentifier)(JNIEnv *env, jclass cls, jlong session, jstring id) {
    char *i = utf8_from_java(env, id);
    httpcloak_session_set_identifier(session, i);
    free(i);
}

JNI(void, clearCache)(JNIEnv *env, jclass cls, jlong session) {
    httpcloak_session_clear_cache(session);
}

JNI(jstring, stats)(JNIEnv *env, jclass cls, jlong session) {
    return take_string(env, httpcloak_session_stats(session));
}

JNI(jlong, idleTimeNanos)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_idle_time(session);
}

JNI(jboolean, isActive)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_is_active(session) != 0;
}

JNI(void, touch)(JNIEnv *env, jclass cls, jlong session) {
    httpcloak_session_touch(session);
}

JNI(void, setConditionalCache)(JNIEnv *env, jclass cls, jlong session, jboolean enabled) {
    httpcloak_session_set_conditional_cache(session, enabled);
}

JNI(jboolean, getConditionalCache)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_get_conditional_cache(session) != 0;
}

JNI(void, setClientHints)(JNIEnv *env, jclass cls, jlong session, jboolean enabled) {
    httpcloak_session_set_client_hints(session, enabled);
}

JNI(jboolean, getClientHints)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_get_client_hints(session) != 0;
}

JNI(void, setHighEntropyClientHints)(JNIEnv *env, jclass cls, jlong session, jboolean enabled) {
    httpcloak_session_set_high_entropy_client_hints(session, enabled);
}

JNI(jboolean, getHighEntropyClientHints)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_get_high_entropy_client_hints(session) != 0;
}

JNI(void, setFollowRedirects)(JNIEnv *env, jclass cls, jlong session, jboolean enabled) {
    httpcloak_session_set_follow_redirects(session, enabled);
}

JNI(jboolean, getFollowRedirects)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_get_follow_redirects(session) != 0;
}

JNI(void, setMaxRedirects)(JNIEnv *env, jclass cls, jlong session, jint max) {
    httpcloak_session_set_max_redirects(session, max);
}

JNI(jint, getMaxRedirects)(JNIEnv *env, jclass cls, jlong session) {
    return httpcloak_session_get_max_redirects(session);
}

// ---------------------------------------------------------------------------
// Local proxy
// ---------------------------------------------------------------------------

JNI(jlong, localProxyStart)(JNIEnv *env, jclass cls, jstring config_json) {
    char *config = utf8_from_java(env, config_json);
    jlong proxy = httpcloak_local_proxy_start(config);
    free(config);
    return proxy;
}

JNI(void, localProxyStop)(JNIEnv *env, jclass cls, jlong proxy) {
    httpcloak_local_proxy_stop(proxy);
}

JNI(jint, localProxyGetPort)(JNIEnv *env, jclass cls, jlong proxy) {
    return httpcloak_local_proxy_get_port(proxy);
}

JNI(jboolean, localProxyIsRunning)(JNIEnv *env, jclass cls, jlong proxy) {
    return httpcloak_local_proxy_is_running(proxy) != 0;
}

JNI(jstring, localProxyGetStats)(JNIEnv *env, jclass cls, jlong proxy) {
    return take_string(env, httpcloak_local_proxy_get_stats(proxy));
}

JNI(jstring, localProxyRegisterSession)(JNIEnv *env, jclass cls, jlong proxy, jstring id,
                                        jlong session) {
    char *i = utf8_from_java(env, id);
    jstring out = take_string(env, httpcloak_local_proxy_register_session(proxy, i, session));
    free(i);
    return out;
}

JNI(jboolean, localProxyUnregisterSession)(JNIEnv *env, jclass cls, jlong proxy, jstring id) {
    char *i = utf8_from_java(env, id);
    jboolean removed = httpcloak_local_proxy_unregister_session(proxy, i) != 0;
    free(i);
    return removed;
}

JNI(jstring, localProxyListSessions)(JNIEnv *env, jclass cls, jlong proxy) {
    return take_string(env, httpcloak_local_proxy_list_sessions(proxy));
}

JNI(jboolean, localProxyHasSession)(JNIEnv *env, jclass cls, jlong proxy, jstring id) {
    char *i = utf8_from_java(env, id);
    jboolean found = httpcloak_local_proxy_has_session(proxy, i) != 0;
    free(i);
    return found;
}
