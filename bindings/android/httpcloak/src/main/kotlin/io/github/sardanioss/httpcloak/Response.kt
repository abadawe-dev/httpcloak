package io.github.sardanioss.httpcloak

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.nio.charset.Charset

/** A fully read HTTP response. */
public class Response internal constructor(
    public val statusCode: Int,
    /** Response headers. Lookups ignore case. */
    public val headers: Map<String, List<String>>,
    public val body: ByteArray,
    /** The final URL, after any redirects. */
    public val url: String,
    /** "h1", "h2" or "h3". */
    public val protocol: String,
    /** Cookies set by this response. */
    public val cookies: List<Cookie>,
    /** The redirects followed to get here, oldest first. */
    public val history: List<RedirectInfo>,
    /** The order the server sent its headers in. Empty on HTTP/1.1. */
    public val headerOrder: List<String>,
    /** How the server spelled its header names. Empty on HTTP/1.1. */
    public val headerCasing: List<String>,
    /** Trailing headers sent after the body (gRPC status, for example). */
    public val trailer: Map<String, List<String>>,
    /** Wall time from sending the request to having the whole body. */
    public val elapsedMillis: Long,
) {
    /** True for any status below 400. */
    public val ok: Boolean get() = statusCode < 400

    /** The body decoded with the charset from Content-Type, UTF-8 by default. */
    public val text: String by lazy { String(body, charsetOf(header("Content-Type"))) }

    /** The first value of header [name], ignoring case. */
    public fun header(name: String): String? = headers.firstValue(name)

    /** The body parsed as JSON: a JSONObject, JSONArray, String, Number, Boolean or null. */
    public fun json(): Any? = JSONTokener(text).nextValue().takeUnless { it == JSONObject.NULL }

    /** Throws [HttpCloakException] for a 4xx or 5xx status; returns this otherwise. */
    public fun raiseForStatus(): Response {
        if (statusCode >= 400) throw HttpCloakException("HTTP $statusCode for $url", this)
        return this
    }

    override fun toString(): String = "Response($statusCode $protocol $url)"

    internal companion object {
        /**
         * Builds a response from the library's response JSON. [body] is the raw
         * body when it came separately; otherwise it is read from the JSON.
         */
        fun fromJson(json: String, body: ByteArray?, elapsedMillis: Long): Response {
            val obj = checkedObject(json)
            return Response(
                statusCode = obj.getInt("status_code"),
                headers = obj.optJSONObject("headers").toHeaderMap(),
                body = body ?: inlineBody(obj),
                url = obj.optString("final_url"),
                protocol = obj.optString("protocol"),
                cookies = Cookie.listFromJson(obj.optJSONArray("cookies")),
                history = RedirectInfo.listFromJson(obj.optJSONArray("history")),
                headerOrder = obj.optJSONArray("header_order").toStringList(),
                headerCasing = obj.optJSONArray("header_casing").toStringList(),
                trailer = obj.optJSONObject("trailer").toHeaderMap(),
                elapsedMillis = elapsedMillis,
            )
        }

        private fun inlineBody(obj: JSONObject): ByteArray {
            val body = obj.optString("body")
            return if (obj.optString("body_encoding") == "base64") base64Decode(body) else body.toByteArray()
        }
    }
}

/** A redirect hop recorded in [Response.history]. */
public data class RedirectInfo(
    public val statusCode: Int,
    public val url: String,
    public val headers: Map<String, List<String>>,
) {
    internal companion object {
        fun listFromJson(array: JSONArray?): List<RedirectInfo> =
            if (array == null) emptyList() else List(array.length()) {
                val hop = array.getJSONObject(it)
                RedirectInfo(hop.getInt("status_code"), hop.optString("url"), hop.optJSONObject("headers").toHeaderMap())
            }
    }
}

/** A cookie, as held in the session jar or set by a response. */
public data class Cookie @JvmOverloads constructor(
    public val name: String,
    public val value: String,
    public val domain: String = "",
    public val path: String = "",
    /** Expiry in RFC 1123 form ("Mon, 02 Jan 2006 15:04:05 GMT"), or null for a session cookie. */
    public val expires: String? = null,
    /** Max-Age in seconds; 0 when not set. */
    public val maxAge: Int = 0,
    public val secure: Boolean = false,
    public val httpOnly: Boolean = false,
    /** "Strict", "Lax", "None" or null. */
    public val sameSite: String? = null,
) {
    internal fun toJson(): String = JSONObject()
        .put("name", name)
        .put("value", value)
        .put("domain", domain)
        .put("path", path)
        .put("expires", expires ?: "")
        .put("max_age", maxAge)
        .put("secure", secure)
        .put("http_only", httpOnly)
        .put("same_site", sameSite ?: "")
        .toString()

    internal companion object {
        fun listFromJson(array: JSONArray?): List<Cookie> =
            if (array == null) emptyList() else List(array.length()) {
                val c = array.getJSONObject(it)
                Cookie(
                    name = c.getString("name"),
                    value = c.optString("value"),
                    domain = c.optString("domain"),
                    path = c.optString("path"),
                    expires = c.optString("expires").ifEmpty { null },
                    maxAge = c.optInt("max_age"),
                    secure = c.optBoolean("secure"),
                    httpOnly = c.optBoolean("http_only"),
                    sameSite = c.optString("same_site").ifEmpty { null },
                )
            }
    }
}

/** The charset named in a Content-Type value, or UTF-8. */
internal fun charsetOf(contentType: String?): Charset {
    val name = contentType?.split(';')
        ?.map { it.trim() }
        ?.firstOrNull { it.startsWith("charset=", ignoreCase = true) }
        ?.substringAfter('=')?.trim('"', ' ')
    return name?.let { runCatching { Charset.forName(it) }.getOrNull() } ?: Charsets.UTF_8
}
