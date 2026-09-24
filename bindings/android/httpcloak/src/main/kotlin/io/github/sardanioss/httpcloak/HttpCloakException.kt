package io.github.sardanioss.httpcloak

import java.io.IOException

/**
 * A request or library call that failed. [response] is set when the failure is
 * an HTTP error status raised by [Response.raiseForStatus].
 */
public class HttpCloakException @JvmOverloads constructor(
    message: String,
    public val response: Response? = null,
) : IOException(message)
