@file:Suppress("unused")

package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.MediaType
import info.jdavid.asynk.http.Method
import info.jdavid.asynk.http.internal.SocketAccess
import java.io.File
import java.lang.RuntimeException
import java.nio.ByteBuffer

object Request {

  open class Response(val status: Int, val headers: Headers, val body: ByteBuffer)

  internal interface Requester {
    suspend fun <T: Body>request(method: info.jdavid.asynk.http.Method, host: String, port: Int,
                                 pathWithQueryAndFragment: String,
                                 headers: Headers, body: T?,
                                 timeoutMillis: Long,
                                 buffer: ByteBuffer): Request.Response
  }

  internal suspend fun <T: Body>request(method: Method, url: String, headers: Headers, body: T?,
                                        followRedirect: Boolean,
                                        timeoutMillis: Long,
                                        buffer: ByteBuffer,
                                        insecureRequester: Requester = InsecureRequest,
                                        secureRequester: Requester = SecureRequest): Response {
    if (followRedirect) {
      var location: String = url
      while (true) {
        val response =
          request(method, location, headers, body, timeoutMillis, buffer, insecureRequester, secureRequester)
        location = when(response.status) {
          301, 302, 303, 307, 308 -> absolute(location, response.headers.value(Headers.LOCATION))
          else -> null
        } ?: return response
      }
    }
    else {
      return request(method, url, headers, body, timeoutMillis, buffer, insecureRequester, secureRequester)
    }
  }

  private fun absolute(base: String?, redirect: String?): String? {
    if (base == null || redirect == null) return null
    if (redirect.startsWith("http://") || redirect.startsWith("https://")) return redirect
    if (redirect.startsWith("//")) return base.substring(0, base.indexOf("/")) + redirect
    val pathEndIndex = base.indexOf('?', 8).let {
      if (it != -1) it else base.indexOf('#', 8).let {
        if (it != -1) it else base.length
      }
    }
    if (redirect.startsWith("/")) {
      val authorityEndIndex = base.indexOf('/', 8).let {
        if (it == -1 || it > pathEndIndex) pathEndIndex else it
      }
      return base.substring(0, authorityEndIndex) + redirect
    }
    val urlNoQueryOrSegment = base.substring(0, pathEndIndex)
    if (urlNoQueryOrSegment.endsWith("/")) return urlNoQueryOrSegment + redirect
    val authorityEndIndex = base.indexOf('/', 8).let {
      if (it == -1 || it > pathEndIndex) pathEndIndex else it
    }
    val parent = urlNoQueryOrSegment.lastIndexOf("/").let {
      if (it == -1 || it < authorityEndIndex) {
        urlNoQueryOrSegment.substring(authorityEndIndex) + "/"
      }
      else {
        urlNoQueryOrSegment.substring(0, it + 1)
      }
    }
    return parent + redirect
  }

  internal suspend fun <T: Body>request(method: info.jdavid.asynk.http.Method, url: String, headers: Headers, body: T?,
                                        timeoutMillis: Long,
                                        buffer: ByteBuffer,
                                        insecureRequester: Requester = InsecureRequest,
                                        secureRequester: Requester = SecureRequest): Response {
    buffer.clear()
    if (url.length < 10) throw RuntimeException()
    if (url[0] != 'h' || url[1] != 't' || url[2] != 't' || url[3] != 'p') throw RuntimeException()
    return if (url[4] == 's') {
      if (url[5] != ':' || url[6] != '/' || url[7] != '/') throw RuntimeException()
      val pathEndIndex = url.indexOf('?', 8).let {
        if (it != -1) it else url.indexOf('#', 8).let {
          if (it != -1) it else url.length
        }
      }
      val authorityEndIndex = url.indexOf('/', 8).let {
        if (it == -1 || it > pathEndIndex) pathEndIndex else it
      }
      val portStartIndex = url.lastIndexOf(':', authorityEndIndex).let {
        if (it < 8) authorityEndIndex else it
      }
      val port = if (portStartIndex == authorityEndIndex) {
        443
      } else {
        url.substring(portStartIndex + 1, authorityEndIndex).toInt()
      }
      val host = url.substring(8, portStartIndex)
      val pathWithQueryAndFragment = if (authorityEndIndex == url.length) {
        "/"
      } else if (authorityEndIndex == pathEndIndex) {
        "/" + url.substring(pathEndIndex)
      }
      else {
        url.substring(authorityEndIndex)
      }
      secureRequester.request(
        method, host, port, pathWithQueryAndFragment, headers, body, timeoutMillis, buffer
      )
    }
    else {
      if (url[4] != ':' || url[5] != '/' || url[6] != '/') throw RuntimeException()
      val pathEndIndex = url.indexOf('?', 7).let {
        if (it != -1) it else url.indexOf('#', 7).let {
          if (it != -1) it else url.length
        }
      }
      val authorityEndIndex = url.indexOf('/', 7).let {
        if (it == -1 || it > pathEndIndex) pathEndIndex else it
      }
      val portStartIndex = url.lastIndexOf(':', authorityEndIndex).let {
        if (it < 7) authorityEndIndex else it
      }
      val port = if (portStartIndex == authorityEndIndex) {
        80
      } else {
        url.substring(portStartIndex + 1, authorityEndIndex).toInt()
      }
      val host = url.substring(7, portStartIndex)
      val pathWithQueryAndFragment = if (authorityEndIndex == url.length) {
        "/"
      } else if (authorityEndIndex == pathEndIndex) {
        "/" + url.substring(pathEndIndex)
      }
      else {
        url.substring(authorityEndIndex)
      }
      insecureRequester.request(
        method, host, port, pathWithQueryAndFragment, headers, body, timeoutMillis, buffer
      )
    }
  }

  class InvalidUrlException: RuntimeException()

}

interface RequestDefinition<T: Body> {
  suspend fun send(timeoutMillis: Long = 10000L,
                   buffer: ByteBuffer = ByteBuffer.allocateDirect(16384)): Request.Response
  suspend fun send(followRedirect: Boolean,
                   timeoutMillis: Long = 10000L,
                   buffer: ByteBuffer = ByteBuffer.allocateDirect(16384)): Request.Response
}

class RequestDefinitionWithBody<T: Body> internal constructor(
  private val method: Method, private val url: String, private val headers: Headers, private val body: T?
): RequestDefinition<T> {
  override suspend fun send(timeoutMillis: Long, buffer: ByteBuffer) =
    Request.request(method, url, headers, body, true, timeoutMillis, buffer)
  override suspend fun send(followRedirect: Boolean, timeoutMillis: Long, buffer: ByteBuffer) =
    Request.request(method, url, headers, body, followRedirect, timeoutMillis, buffer)
}


abstract class HeadersDefinition<T: HeadersDefinition<T>> internal constructor(
  internal val headers: Headers = Headers()
) {
  internal abstract fun that(): T
  fun headers(headers: Headers): T {
    this.headers.lines.clear()
    this.headers.lines.addAll(headers.lines)
    return that()
  }
  fun header(name: String, values: Array<String>): T {
    values.forEach { headers.add(name, it) }
    return that()
  }
  fun header(name: String, values: Iterable<String>): T {
    values.forEach { headers.add(name, it) }
    return that()
  }
  fun header(name: String, value: String): T {
    headers.set(name, value)
    return that()
  }
  fun headerKeys() = headers.keys()
  fun hasHeader(name: String) = headers.has(name)
  fun headerValue(name: String) = headers.value(name)
  fun headerValues(name: String) = headers.values(name)
}

sealed class MethodDefinition(internal val method: Method)
abstract class MethodDefinitionBodyRequired internal constructor(method: Method): MethodDefinition(method) {
  fun url(url: String) = UrlDefinitionBodyRequired(method, url)
}
abstract class MethodDefinitionBodyAllowed internal constructor(method: Method): MethodDefinition(method) {
  fun url(url: String) = UrlDefinitionBodyAllowed(method, url)
}
abstract class MethodDefinitionBodyForbidden internal constructor(method: Method): MethodDefinition(method) {
  fun url(url: String) = UrlDefinitionBodyForbidden(method, url)
}

object Options: MethodDefinitionBodyForbidden(Method.OPTIONS)
object Head: MethodDefinitionBodyForbidden(Method.HEAD)
object Get: MethodDefinitionBodyForbidden(Method.GET)
object Delete: MethodDefinitionBodyAllowed(Method.DELETE)
object Post: MethodDefinitionBodyRequired(Method.POST)
object Put: MethodDefinitionBodyRequired(Method.PUT)
object Patch: MethodDefinitionBodyRequired(Method.PATCH)
class Method(name: String): MethodDefinitionBodyAllowed(Method.from(name))

sealed class UrlDefinition<T: HeadersDefinition<T>>(
  internal val method: Method,
  internal val url: String
): HeadersDefinition<T>()

class UrlDefinitionBodyRequired internal constructor(
  method: Method, url: String
): UrlDefinition<UrlDefinitionBodyRequired>(method, url) {
  override fun that() = this
  fun body(file: File) =
    RequestDefinitionWithBody(method, url, headers, Body.from(file))
  fun body(file: File, mediaType: String) =
    RequestDefinitionWithBody(method, url, headers, Body.from(file, mediaType))
  fun body(bytes: ByteArray, mediaType: String = MediaType.OCTET_STREAM) =
    RequestDefinitionWithBody(method, url, headers, Body.from(bytes, mediaType))
  fun body(text: String, mediaType: String = MediaType.TEXT) =
    RequestDefinitionWithBody(method, url, headers, Body.from(text, mediaType))
  fun <T: Body>body(body: T) = RequestDefinitionWithBody(method, url, headers, body)
}
class UrlDefinitionBodyAllowed internal constructor(
  method: Method, url: String
): UrlDefinition<UrlDefinitionBodyAllowed>(method, url), RequestDefinition<Nothing> {
  override fun that() = this
  fun body(file: File) =
    RequestDefinitionWithBody(method, url, headers, Body.from(file))
  fun body(file: File, mediaType: String) =
    RequestDefinitionWithBody(method, url, headers, Body.from(file, mediaType))
  fun body(bytes: ByteArray, mediaType: String = MediaType.OCTET_STREAM) =
    RequestDefinitionWithBody(method, url, headers, Body.from(bytes, mediaType))
  fun body(text: String, mediaType: String = MediaType.TEXT) =
    RequestDefinitionWithBody(method, url, headers, Body.from(text, mediaType))
  fun <T: Body>body(body: T) = RequestDefinitionWithBody(method, url, headers, body)
  override suspend fun send(timeoutMillis: Long, buffer: ByteBuffer) =
    Request.request(method, url, headers, null, true, timeoutMillis, buffer)
  override suspend fun send(followRedirect: Boolean, timeoutMillis: Long, buffer: ByteBuffer) =
    Request.request(method, url, headers, null, followRedirect, timeoutMillis, buffer)
}
class UrlDefinitionBodyForbidden internal constructor(
  method: Method, url: String
): UrlDefinition<UrlDefinitionBodyForbidden>(method, url), RequestDefinition<Nothing> {
  override fun that() = this
  override suspend fun send(timeoutMillis: Long, buffer: ByteBuffer) =
    Request.request(method, url, headers, null, true, timeoutMillis, buffer)
  override suspend fun send(followRedirect: Boolean, timeoutMillis: Long, buffer: ByteBuffer) =
    Request.request(method, url, headers, null, followRedirect, timeoutMillis, buffer)
}
