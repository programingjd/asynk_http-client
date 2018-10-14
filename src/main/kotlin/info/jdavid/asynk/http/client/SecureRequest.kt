package info.jdavid.asynk.http.client

import info.jdavid.asynk.core.asyncConnect
import info.jdavid.asynk.core.asyncRead
import info.jdavid.asynk.core.asyncWrite
import info.jdavid.asynk.http.Crypto
import kotlinx.coroutines.withTimeout
import java.lang.RuntimeException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

internal object SecureRequest: AbstractRequest<AsynchronousSocketChannel, SecureRequest.Handshake>() {

//  override suspend fun <T: Body>request(method: Method, host: String, port: Int,
//                                        pathWithQueryAndFragment: String,
//                                        headers: Headers, body: T?,
//                                        timeoutMillis: Long,
//                                        buffer: ByteBuffer): Request.Response {
//    println(host)
//    println(port)
//    println(method)
//    println(pathWithQueryAndFragment)
//    return Request.Response(Status.OK, Headers(), buffer)
//  }

  override suspend fun open() = AsynchronousSocketChannel.open()

  override suspend fun terminate(channel: AsynchronousSocketChannel, handshake: Handshake,
                                 buffer: ByteBuffer) = TODO()

  override suspend fun connect(channel: AsynchronousSocketChannel, address: InetSocketAddress) =
    channel.asyncConnect(address)

  override suspend fun handshake(host: String,
                                 channel: AsynchronousSocketChannel,
                                 timeoutMillis: Long, buffer: ByteBuffer): Handshake {
    return withTimeout(30000L /*timeoutMillis*/) {
//      val sessionId = UUID.randomUUID().let {
//        buffer.putLong(it.mostSignificantBits)
//        buffer.putLong(it.leastSignificantBits)
//        buffer.flip()
//        ByteArray(16).apply {
//          buffer.get(this)
//          buffer.clear()
//        }
//      }
      buffer.clear()
      TLS.Handshake.clientHello(host, buffer)
      buffer.flip()
      println("ClientHello")
      println(Crypto.hex(ByteArray(buffer.remaining()).apply { buffer.get(this); buffer.flip() }))
      channel.asyncWrite(buffer, true)

      buffer.clear()
      channel.asyncRead(buffer)
      buffer.flip()
      println(Crypto.hex(ByteArray(buffer.remaining()).apply { buffer.get(this); buffer.flip() }))


      val serverHello = nextRecord(channel, buffer) as TLS.Handshake.ServerHello.Fragment
      val certificate = nextRecord(channel, buffer)

      Handshake()
    }
  }

  private suspend fun nextRecord(channel: AsynchronousSocketChannel, buffer: ByteBuffer): TLS.Fragment {
    return TLS.record(buffer).let {
      if (it is TLS.Alert.Fragment) {
        if (it.level == TLS.Alert.Level.FATAL) throw RuntimeException(it.description.toString())
        if (buffer.remaining() == 0) {
          buffer.flip()
          channel.asyncRead(buffer)
          buffer.flip()
        }
        nextRecord(channel, buffer)
      }
      else it
    }
  }

  override suspend fun read(channel: AsynchronousSocketChannel, handshake: Handshake,
                            timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  override suspend fun write(channel: AsynchronousSocketChannel, handshake: Handshake,
                             timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  class Handshake()

}
