package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method
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
    headers.set(Headers.CONNECTION, "close")
    headers.set(Headers.USER_AGENT, "asynk")
    headers.set(Headers.ACCEPT, "*/*")
    headers.set(Headers.ACCEPT_CHARSET, "utf-8, *;q=0.1")
    headers.set(Headers.ACCEPT_ENCODING, "identity")
    val socket = AsynchronousSocketChannel.open()
    socket.aConnect(InetSocketAddress(host, port))

    buffer.put("${method} ${pathWithQueryAndFragment} HTTP/1.1".toByteArray(Charsets.ISO_8859_1))
    buffer.put(CRLF)
    for (line in headers.lines) {
      buffer.put(line.toByteArray(Charsets.ISO_8859_1))
      buffer.put(CRLF)
    }
    buffer.put(CRLF)
    while (buffer.remaining() > 0) socket.aWrite(buffer)
    body?.writeTo(socket, buffer)

    buffer.clear()

    val exhausted = buffer.remaining() > socket.aRead(buffer, 20000L, TimeUnit.MILLISECONDS)
    buffer.flip()
    val status = Http.status(buffer)
    val responseHeaders = Headers()
    Http.body(socket, Http.headers(socket, exhausted, buffer, responseHeaders), buffer, responseHeaders)

    return Request.Response(status, responseHeaders, buffer)
  }

  val CRLF = "\r\n".toByteArray()

}
