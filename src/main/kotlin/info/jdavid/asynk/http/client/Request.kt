@file:Suppress("unused")

package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method

class Request<T: Body> internal constructor(
  val method: Method, val url: String, val headers: Headers, val body: T?
)

interface RequestDefinition<T: Body> {
  fun build(): Request<T>
}

class RequestDefinitionWithBody<T: Body> internal constructor(
  private val method: Method, private val url: String, private val headers: Headers, private val body: T?
): RequestDefinition<T> {
  override fun build() = Request(method, url, headers, body)
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
  override fun build() = Request(method, url, headers, null)
}
class UrlDefinitionBodyForbidden internal constructor(
  method: Method, url: String
): UrlDefinition<UrlDefinitionBodyForbidden>(method, url), RequestDefinition<Nothing> {
  override fun that() = this
  override fun build() = Request(method, url, headers, null)
}
