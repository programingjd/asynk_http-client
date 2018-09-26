package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.MediaType
import kotlinx.coroutines.experimental.nio.aRead
import kotlinx.coroutines.experimental.nio.aWrite
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousFileChannel
import java.nio.channels.AsynchronousSocketChannel
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit

interface Body {

  suspend fun writeTo(socket: AsynchronousSocketChannel, buffer: ByteBuffer)
  suspend fun byteLength(): Long
  fun contentType(): String

  class FileBody(private val file: File, private val mediaType: String): Body {
    override suspend fun byteLength() = file.length()
    override fun contentType() = mediaType
    override suspend fun writeTo(socket: AsynchronousSocketChannel, buffer: ByteBuffer) {
      file.let {
        val channel = AsynchronousFileChannel.open(it.toPath(), StandardOpenOption.READ)
        var position = 0L
        while (true) {
          buffer.clear()
          val read = channel.aRead(buffer, position)
          if (read == -1) break
          position += read
          socket.aWrite(buffer.flip() as ByteBuffer, 5000, TimeUnit.MILLISECONDS)
        }
      }
    }
  }

  class StringBody(text: String, private val mediaType: String): Body {
    private val bytes = text.toByteArray()
    override suspend fun byteLength() = bytes.size.toLong()
    override fun contentType() = mediaType
    override suspend fun writeTo(socket: AsynchronousSocketChannel, buffer: ByteBuffer) {
      socket.aWrite(ByteBuffer.wrap(bytes), 5000, TimeUnit.MILLISECONDS)
    }
  }

  class ByteBody(private val bytes: ByteArray, private val mediaType: String): Body {
    override suspend fun byteLength() = bytes.size.toLong()
    override fun contentType() = mediaType
    override suspend fun writeTo(socket: AsynchronousSocketChannel, buffer: ByteBuffer) {
      socket.aWrite(ByteBuffer.wrap(bytes), 5000, TimeUnit.MILLISECONDS)
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
