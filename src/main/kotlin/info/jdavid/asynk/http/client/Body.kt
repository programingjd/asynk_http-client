package info.jdavid.asynk.http.client

import info.jdavid.asynk.core.asyncRead
import info.jdavid.asynk.core.asyncWrite
import info.jdavid.asynk.http.MediaType
import info.jdavid.asynk.http.internal.SocketAccess
import kotlinx.coroutines.withTimeout
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousFileChannel
import java.nio.channels.AsynchronousSocketChannel
import java.nio.file.StandardOpenOption

interface Body {

  suspend fun writeTo(socket: AsynchronousSocketChannel, socketAccess: SocketAccess, buffer: ByteBuffer)
  suspend fun byteLength(): Long
  fun contentType(): String

  class FileBody(private val file: File, private val mediaType: String): Body {
    override suspend fun byteLength() = file.length()
    override fun contentType() = mediaType
    override suspend fun writeTo(socket: AsynchronousSocketChannel,
                                 socketAccess: SocketAccess,
                                 buffer: ByteBuffer) {
      file.let {
        val channel = AsynchronousFileChannel.open(it.toPath(), StandardOpenOption.READ)
        var position = 0L
        while (true) {
          buffer.clear()
          val read = channel.asyncRead(buffer, position)
          if (read == -1L) break
          position += read
          buffer.flip()
          withTimeout(5000L) {
            while (buffer.hasRemaining()) {
              socketAccess.asyncWrite(socket, buffer)
            }
          }
        }
      }
    }
  }

  class StringBody(text: String, private val mediaType: String): Body {
    private val bytes = text.toByteArray()
    override suspend fun byteLength() = bytes.size.toLong()
    override fun contentType() = mediaType
    override suspend fun writeTo(socket: AsynchronousSocketChannel,
                                 socketAccess: SocketAccess,
                                 buffer: ByteBuffer) {
      withTimeout(5000L) {
        val buf = ByteBuffer.wrap(bytes)
        while (buf.hasRemaining()) {
          socketAccess.asyncWrite(socket, buf)
        }
      }
    }
  }

  class ByteBody(private val bytes: ByteArray, private val mediaType: String): Body {
    override suspend fun byteLength() = bytes.size.toLong()
    override fun contentType() = mediaType
    override suspend fun writeTo(socket: AsynchronousSocketChannel,
                                 socketAccess: SocketAccess,
                                 buffer: ByteBuffer) {
      withTimeout(5000L) {
        val buf = ByteBuffer.wrap(bytes)
        while (buf.hasRemaining()) {
          socketAccess.asyncWrite(socket, buf)
        }
      }
    }
  }

  companion object {
    fun from(file: File) = from(file, MediaType.fromFile(file) ?: MediaType.OCTET_STREAM)
    fun from(file: File, mediaType: String) = FileBody(file, mediaType)
    fun from(text: String, mediaType: String = MediaType.TEXT) = StringBody(
      text, mediaType)
    fun from(bytes: ByteArray, mediaType: String = MediaType.OCTET_STREAM) = ByteBody(
      bytes, mediaType)
  }

}
