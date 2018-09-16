package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method
import info.jdavid.asynk.http.internal.Http
import kotlinx.coroutines.experimental.nio.aConnect
import kotlinx.coroutines.experimental.nio.aRead
import kotlinx.coroutines.experimental.nio.aWrite
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel
import java.util.concurrent.TimeUnit

internal object InsecureRequest: Request.Requester {

  override suspend fun <T: Body>request(method: Method, host: String, port: Int,
                                        pathWithQueryAndFragment: String,
                                        headers: Headers, body: T?,
                                        buffer: ByteBuffer): Request.Response {
    if (body != null) {
      headers.set(Headers.CONTENT_TYPE, body.contentType())
      headers.set(Headers.CONTENT_LENGTH, "${body.byteLength()}")
    }
    headers.set(Headers.HOST, if (port == 80) host else "${host}:${port}")
    if (!headers.has(Headers.CONNECTION)) headers.set(Headers.CONNECTION, "close")
    if (!headers.has(Headers.USER_AGENT)) headers.set(Headers.USER_AGENT, "asynk/0.0.0.12")
    if (!headers.has(Headers.ACCEPT)) headers.set(Headers.ACCEPT, "*/*")
    if (!headers.has(Headers.ACCEPT_CHARSET)) headers.set(Headers.ACCEPT_CHARSET, "utf-8, *;q=0.1")
    headers.set(Headers.ACCEPT_ENCODING, "identity")
    return AsynchronousSocketChannel.open().use { socket ->
      socket.aConnect(InetSocketAddress(host, port))

      buffer.put("${method} ${pathWithQueryAndFragment} HTTP/1.1".toByteArray(Charsets.ISO_8859_1))
      buffer.put(CRLF)
      for (line in headers.lines) {
        buffer.put(line.toByteArray(Charsets.ISO_8859_1))
        buffer.put(CRLF)
      }
      buffer.put(CRLF)
      debug(buffer)
      buffer.flip()
      while (buffer.remaining() > 0) socket.aWrite(buffer)
      body?.writeTo(socket, buffer)

      buffer.clear()
      if (socket.aRead(buffer, 20000L, TimeUnit.MILLISECONDS) < 16) throw IncompleteResponseException()
      buffer.flip()
      val httpVersion = Http.httpVersion(buffer)
      val status = Http.status(buffer)
      if (buffer.remaining() < 4) {
        buffer.compact()
        if (socket.aRead(buffer, 20000L, TimeUnit.MILLISECONDS) < 4) throw IncompleteResponseException()
        buffer.flip()
      }
      val responseHeaders = Headers()
      Http.headers(socket, buffer, responseHeaders)
      Http.body(socket, httpVersion, buffer, true, false, responseHeaders, null)
      Request.Response(status, responseHeaders, buffer)
    }
  }

  private fun debug(buffer: ByteBuffer) {
    buffer.flip()
    val bytes = ByteArray(buffer.remaining())
    buffer.get(bytes)
    buffer.limit(buffer.capacity())
    println(String(bytes))
  }

  private val CRLF = "\r\n".toByteArray()

  class IncompleteResponseException: Exception()

}
