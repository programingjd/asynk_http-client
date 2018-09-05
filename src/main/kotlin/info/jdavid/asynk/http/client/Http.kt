package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import kotlinx.coroutines.experimental.nio.aRead
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel
import java.util.concurrent.TimeUnit

internal object Http {

  fun status(buffer: ByteBuffer): Int {
    // Status line: (ASCII)
    // HTTP/1.1 CODE MESSAGE\r\n

    // Shortest possible status line is 15 bytes long
    if (buffer.remaining() < 15) throw InvalidStatusLine()

    // It should start with HTTP/1.1 + space
    if (buffer.get() != H_UPPER ||
        buffer.get() != T_UPPER ||
        buffer.get() != T_UPPER ||
        buffer.get() != P_UPPER ||
        buffer.get() != SLASH ||
        buffer.get() != ONE ||
        buffer.get() != DOT ||
        buffer.get() != ONE ||
        buffer.get() != SPACE) throw InvalidStatusLine()

    val codeBytes = ByteArray(3)
    buffer.get(codeBytes)
    val code = String(codeBytes).toInt()

    while (true) {
      if (buffer.remaining() < 1) throw InvalidStatusLine()
      if (buffer.get() == CR) break
    }
    if (buffer.get() != LF) throw InvalidStatusLine()
    return code
  }

  suspend fun headers(socket: AsynchronousSocketChannel,
                      alreadyExhausted: Boolean,
                      buffer: ByteBuffer,
                      headers: Headers,
                      maxSize: Int = 8192): Boolean {
    // Headers
    // FIELD_NAME_1: FIELD_VALUE_1\r\n
    // ...
    // FIELD_NAME_N: FIELD_VALUE_N\r\n
    // \r\n
    // Add content between \r\n as header lines until an empty line signifying the end of the headers.

    var exhausted = alreadyExhausted
    var i = buffer.position()
    var size = 0
    var j = i
    while (true) {
      if (++size > maxSize) throw HeadersTooLarge()
      if (when (buffer[i++]) {
          LF -> {
            if (buffer[i - 2] != CR) throw InvalidHeaders()
            if (i - 2 == j){
              buffer.get()
              buffer.get()
              true
            }
            else {
              val headerBytes = ByteArray(i - j - 2)
              buffer.get(headerBytes)
              headers.lines.add(String(headerBytes, Charsets.ISO_8859_1))
              buffer.get()
              buffer.get()
              j = i
              false
            }
          }
          else -> false
        }) break
      if (i == buffer.limit()) {
        if (exhausted) throw InvalidHeaders()
        buffer.compact()
        if (buffer.position() == buffer.capacity()) throw HeadersTooLarge()
        exhausted = buffer.remaining() > socket.aRead(buffer, 3000L, TimeUnit.MILLISECONDS)
        buffer.flip()
        i -= j
        j = 0
      }
    }
    return exhausted
  }

  suspend fun body(socket: AsynchronousSocketChannel,
                   alreadyExhausted: Boolean,
                   buffer: ByteBuffer,
                   headers: Headers) {
    var exhausted = alreadyExhausted
    buffer.compact().flip()
    val encoding = headers.value(Headers.TRANSFER_ENCODING)
    if (encoding == null || encoding == IDENTITY) {
      val contentLength = headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: 0
      if (buffer.limit() > contentLength) throw InvalidResponse()
      if (contentLength > 0) {
        val compression = headers.value(Headers.CONTENT_ENCODING)
        if (compression != null && compression != IDENTITY) throw UnsupportedContentEncoding()
        if (contentLength > buffer.capacity()) throw BodyTooLarge()
        if (!exhausted && contentLength > buffer.limit()) {
          val limit = buffer.limit()
          buffer.position(limit).limit(buffer.capacity())
          socket.aRead(buffer, 5000L, TimeUnit.MILLISECONDS)
          buffer.limit(buffer.position()).position(limit)
          if (buffer.limit() > contentLength) throw InvalidResponse()
        }
      }
    }
    else if (encoding == CHUNKED) {
      // Body with chunked encoding
      // CHUNK_1_LENGTH_HEX\r\n
      // CHUNK_1_BYTES\r\n
      // ...
      // CHUNK_N_LENGTH_HEX\r\n
      // CHUNK_N_BYTES\r\n
      // 0\r\n
      // FIELD_NAME_1: FIELD_VALUE_1\r\n
      // ...
      // FIELD_NAME_N: FIELD_VALUE_N\r\n
      // \r\n
      // Trailing header fields are ignored.
      val sb = StringBuilder(12)
      var start = buffer.position()
      chunks@ while (true) { // for each chunk
        // Look for \r\n to extract the chunk length
        bytes@ while (true) {
          if (buffer.remaining() == 0) {
            if (exhausted) throw InvalidResponse()
            val limit = buffer.limit()
            if (buffer.capacity() == limit) throw BodyTooLarge()
            exhausted = buffer.remaining() > socket.aRead(buffer, 3000L, TimeUnit.MILLISECONDS)
            buffer.limit(buffer.position()).position(limit)
            if (buffer.remaining() == 0) throw InvalidResponse()
          }
          val b = buffer.get()
          if (b == LF) { // End of chunk size line
            if (sb.last().toByte() != CR) throw InvalidResponse()
            val index = sb.indexOf(';') // ignore chunk extensions
            val chunkSize = Integer.parseInt(
              if (index == -1) sb.trim().toString() else sb.substring(0, index).trim(),
              16
            )
            // remove chunk size line bytes from the buffer, and skip the chunk bytes
            sb.delete(0, sb.length)
            val end = buffer.position()
            val limit = buffer.limit()
            buffer.position(start)
            (buffer.slice().position(end - start) as ByteBuffer).compact()
            buffer.limit(limit - end + start)
            if (buffer.capacity() - start < chunkSize + 2) throw BodyTooLarge()
            if (buffer.limit() < start + chunkSize + 2) {
              if (exhausted) throw InvalidResponse()
              buffer.position(buffer.limit())
              exhausted = buffer.remaining() > socket.aRead(buffer, 3000L, TimeUnit.MILLISECONDS)
              buffer.limit(buffer.position())
              if (buffer.limit() < start + chunkSize + 2) throw InvalidResponse()
            }
            buffer.position(start + chunkSize)
            // chunk bytes should be followed by \r\n
            if (buffer.get() != CR || buffer.get() != LF) throw InvalidResponse()
            if (chunkSize == 0) {
              // zero length chunk marks the end of the chunk list
              // skip trailing fields (look for \r\n\r\n sequence)
              val last = buffer.position() - 2
              if (last > buffer.capacity() - 4) throw BodyTooLarge()
              while (true) {
                if (buffer.remaining() == 0) {
                  if (exhausted) break
                  buffer.position(last + 2)
                  exhausted = buffer.remaining() > socket.aRead(buffer, 3000L, TimeUnit.MILLISECONDS)
                  buffer.limit(buffer.position()).position(last + 2)
                }
                if (b == LF) {
                  val position = buffer.position()
                  if (buffer[position - 1] == CR && buffer[position - 2] == LF) break
                }
              }
              buffer.limit(last).position(0)
              break@chunks
            }
            start = buffer.position() - 2
            break@bytes
          }
          sb.append(b.toChar())
        }
      }
    }
  }

  private const val CR: Byte = 0x0d
  private const val LF: Byte = 0x0a
  private const val SPACE: Byte = 0x20
  private const val H_UPPER: Byte = 0x48
  private const val T_UPPER: Byte = 0x54
  private const val P_UPPER: Byte = 0x50
  private const val SLASH: Byte = 0x2f
  private const val ONE: Byte = 0x31
  private const val DOT: Byte = 0x2e

  private const val IDENTITY = "identity"
  private const val CHUNKED = "chunked"

  class InvalidStatusLine: Exception()
  class InvalidHeaders(): Exception()
  class HeadersTooLarge : Exception()
  class InvalidResponse: Exception()
  class BodyTooLarge : Exception()
  class UnsupportedContentEncoding: Exception()

}
