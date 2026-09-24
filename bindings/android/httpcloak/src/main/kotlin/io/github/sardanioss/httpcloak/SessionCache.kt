package io.github.sardanioss.httpcloak

/**
 * External storage for TLS session tickets (and ECH configs), so resumption
 * survives process restarts or is shared between processes. Install one with
 * [HttpCloak.setSessionCache]; it applies to sessions created afterwards.
 *
 * Methods are called on the library's own threads and may block. A method
 * that throws is reported to the library as a failed operation.
 */
public interface SessionCache {
    /** The value stored under [key], or null when there is none. */
    public fun get(key: String): String?

    /** Stores [value] (JSON) under [key] for [ttlSeconds]. */
    public fun put(key: String, value: String, ttlSeconds: Long)

    public fun delete(key: String)

    /** The ECH config (base64) stored under [key], or null. Used for HTTP/3. */
    public fun getEch(key: String): String? = null

    public fun putEch(key: String, value: String, ttlSeconds: Long) {}

    /** Called when an operation on this cache fails. */
    public fun onError(operation: String, key: String, error: String) {}
}
