package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method
import info.jdavid.asynk.http.internal.Context
import info.jdavid.asynk.http.internal.Http
import java.lang.RuntimeException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

abstract class AbstractRequest<C: AsynchronousSocketChannel, H: Any>
         internal constructor(): Request.Requester {

  override suspend fun <T: Body>request(method: Method, host: String, port: Int,
                                        pathWithQueryAndFragment: String,
                                        headers: Headers, body: T?,
                                        timeoutMillis: Long,
                                        buffer: ByteBuffer): Request.Response {
    if (body != null) {
      headers.set(Headers.CONTENT_TYPE, body.contentType())
      headers.set(Headers.CONTENT_LENGTH, "${body.byteLength()}")
    }
    headers.set(Headers.HOST, if (port == 80) host else "${host}:${port}")
    if (!headers.has(Headers.CONNECTION)) headers.set(Headers.CONNECTION, "close")
    if (!headers.has(Headers.USER_AGENT)) headers.set(Headers.USER_AGENT, "asynk/0.0.0.18")
    if (!headers.has(Headers.ACCEPT)) headers.set(Headers.ACCEPT, "*/*")
    if (!headers.has(Headers.ACCEPT_CHARSET)) headers.set(Headers.ACCEPT_CHARSET, "utf-8, *;q=0.1")
    headers.set(Headers.ACCEPT_ENCODING, "identity")
    return open().use { socket ->
      connect(socket, InetSocketAddress(host, port))
      val handshake = handshake(host, socket, timeoutMillis, buffer)
      buffer.put("${method} ${pathWithQueryAndFragment} HTTP/1.1".toByteArray(Charsets.ISO_8859_1))
      buffer.put(CRLF)
      for (line in headers.lines) {
        buffer.put(line.toByteArray(Charsets.ISO_8859_1))
        buffer.put(CRLF)
      }
      buffer.put(CRLF)
      //debug(buffer)
      buffer.flip()
      while (buffer.remaining() > 0) write(socket, handshake, timeoutMillis, buffer)
      body?.writeTo(socket, buffer) // TODO: replace socket with request

      buffer.clear()
      if (read(socket, handshake, timeoutMillis, buffer) < 16) throw IncompleteResponseException()
      buffer.flip()
      val httpVersion = Http.httpVersion(buffer)
      val status = Http.status(buffer)
      if (buffer.remaining() < 4) {
        buffer.compact()
        if (read(socket, handshake, timeoutMillis, buffer) < 4) throw IncompleteResponseException()
        buffer.flip()
      }
      val responseHeaders = Headers()
      Http.headers(socket, buffer, responseHeaders)
      val context = object: Context {
        override var buffer: ByteBuffer? = null
        override val maxRequestSize = 65536
      }
      val code = Http.body(
        socket, // TODO: replace socket with request
        httpVersion,
        buffer,
        context,
        true,
        false,
        responseHeaders,
        null
      )
      if (code > 1) throw RuntimeException()
      terminate(socket, handshake, buffer)
      Request.Response(
        status,
        responseHeaders,
        if (code == 0) buffer else context.buffer ?: throw RuntimeException()
      )
    }
  }

  protected abstract suspend fun open(): C

  protected abstract suspend fun terminate(channel: C, handshake: H, buffer: ByteBuffer)

  protected abstract suspend fun connect(channel: C, address: InetSocketAddress)

  protected abstract suspend fun handshake(host: String, channel: C,
                                           timeoutMillis: Long, buffer: ByteBuffer): H

  protected abstract suspend fun read(channel: C, handshake: H, timeoutMillis: Long, buffer: ByteBuffer): Long

  protected abstract suspend fun write(channel: C, handshake: H, timeoutMillis: Long, buffer: ByteBuffer): Long

//  private fun debug(buffer: ByteBuffer) {
//    buffer.flip()
//    val bytes = ByteArray(buffer.remaining())
//    buffer.get(bytes)
//    buffer.limit(buffer.capacity())
//    println(String(bytes))
//  }

  private val CRLF = "\r\n".toByteArray()

  class IncompleteResponseException: Exception()

}
