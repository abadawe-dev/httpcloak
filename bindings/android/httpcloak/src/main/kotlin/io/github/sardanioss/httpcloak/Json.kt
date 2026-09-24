package io.github.sardanioss.httpcloak

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.util.TreeMap

// Helpers for the JSON the C API speaks. Kept free of any public types so the
// wire format stays an implementation detail.

/** The message in a library error result, or null if [result] is not one. */
internal fun errorIn(result: String?): String? {
    if (result == null || !result.startsWith("{")) return null
    val obj = runCatching { JSONObject(result) }.getOrNull() ?: return null
    return if (obj.has("error")) obj.optString("error") else null
}

/** Returns [result], or throws if the library reported an error instead. */
internal fun checked(result: String?): String {
    errorIn(result)?.let { throw HttpCloakException(it) }
    return result ?: throw HttpCloakException("httpcloak returned no result")
}

/** An async error is either a JSON error object or a bare message. */
internal fun asyncErrorMessage(error: String?): String =
    errorIn(error) ?: error?.takeIf { it.isNotEmpty() } ?: "request failed"

/** Header names are case-insensitive, and HTTP/2 and HTTP/3 lowercase them. */
internal fun JSONObject?.toHeaderMap(): Map<String, List<String>> {
    val map = TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER)
    this?.keys()?.forEach { name -> map[name] = optJSONArray(name).toStringList() }
    return map
}

internal fun JSONArray?.toStringList(): List<String> =
    if (this == null) emptyList() else List(length()) { getString(it) }

internal fun Map<String, List<String>>.firstValue(name: String): String? = this[name]?.firstOrNull()

/** Plain Kotlin maps and lists for JSON whose shape is not fixed. */
internal fun JSONObject.toMap(): Map<String, Any?> = keys().asSequence().associateWith { plain(opt(it)) }

private fun plain(value: Any?): Any? = when (value) {
    is JSONObject -> value.toMap()
    is JSONArray -> List(value.length()) { plain(value.opt(it)) }
    JSONObject.NULL -> null
    else -> value
}

internal fun base64Encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

internal fun base64Decode(text: String): ByteArray = Base64.decode(text, Base64.DEFAULT)
