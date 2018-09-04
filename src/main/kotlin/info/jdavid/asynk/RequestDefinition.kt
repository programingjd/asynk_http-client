package info.jdavid.asynk

import info.jdavid.asynk.http.Headers

abstract class RequestDefinition<T: RequestDefinition<T>>(internal val headers: Headers = Headers()) {
  fun setHeaders(headers: Headers): RequestDefinition<T> {
    this.headers.lines.clear()
    this.headers.lines.addAll(headers.lines)
    return this
  }
  fun addHeader(name: String, value: String): RequestDefinition<T> {
    headers.add(name, value)
    return this
  }
  fun setHeader(name: String, value: String): RequestDefinition<T> {
    headers.set(name, value)
    return this
  }
  fun headerKeys() = headers.keys()
  fun headerHas(name: String) = headers.has(name)
  fun headerValue(name: String) = headers.value(name)
  fun headerValues(name: String) = headers.values(name)
}
