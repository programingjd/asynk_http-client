@file:Suppress("unused")

package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method
import java.lang.RuntimeException
import java.nio.ByteBuffer

object Request {

  open class Response(val status: Int, val headers: Headers, val body: ByteBuffer)

  internal interface Requester {
    suspend fun <T: Body>request(method: info.jdavid.asynk.http.Method, host: String, port: Int,
                                 pathWithQueryAndFragment: String,
                                 headers: Headers, body: T?, buffer: ByteBuffer): Request.Response
  }

  internal suspend fun <T: Body>request(method: Method, url: String, headers: Headers, body: T?,
                                        buffer: ByteBuffer,
                                        insecureRequester: Requester = InsecureRequest,
                                        secureRequester: Requester = SecureRequest): Response {
    buffer.clear()
    if (url.length < 8) throw RuntimeException()
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
      secureRequester.request(method, host, port, pathWithQueryAndFragment, headers, body, buffer)
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
      insecureRequester.request(method, host, port, pathWithQueryAndFragment, headers, body, buffer)
    }
  }

  class InvalidUrlException: RuntimeException()

}

interface RequestDefinition<T: Body> {
  suspend fun send(buffer: ByteBuffer = ByteBuffer.allocateDirect(16384)): Request.Response
}

class RequestDefinitionWithBody<T: Body> internal constructor(
  private val method: Method, private val url: String, private val headers: Headers, private val body: T?
): RequestDefinition<T> {
  override suspend fun send(buffer: ByteBuffer) = Request.request(method, url, headers, body, buffer)
}


abstract class HeadersDefinition<T: HeadersDefinition<T>> internal constructor(
  internal val headers: Headers = Headers()
) {
  internal abstract fun that(): T
  fun setHeaders(headers: Headers): T {
    this.headers.lines.clear()
    this.headers.lines.addAll(headers.lines)
    return that()
  }
  fun addHeader(name: String, value: String): T {
    headers.add(name, value)
    return that()
  }
  fun setHeader(name: String, value: String): T {
    headers.set(name, value)
    return that()
  }
  fun headerKeys() = headers.keys()
  fun headerHas(name: String) = headers.has(name)
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
  fun <T: Body>setBody(body: T) = RequestDefinitionWithBody(
    method, url, headers, body)
}
class UrlDefinitionBodyAllowed internal constructor(
  method: Method, url: String
): UrlDefinition<UrlDefinitionBodyAllowed>(method, url), RequestDefinition<Nothing> {
  override fun that() = this
  fun <T: Body>setBody(body: T) = RequestDefinitionWithBody(
    method, url, headers, body)
  override suspend fun send(buffer: ByteBuffer) = Request.request(method, url, headers, null, buffer)
}
class UrlDefinitionBodyForbidden internal constructor(
  method: Method, url: String
): UrlDefinition<UrlDefinitionBodyForbidden>(method, url), RequestDefinition<Nothing> {
  override fun that() = this
  override suspend fun send(buffer: ByteBuffer) = Request.request(method, url, headers, null, buffer)
}
