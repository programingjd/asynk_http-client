package info.jdavid.asynk.http.client

import info.jdavid.asynk.core.asyncConnect
import info.jdavid.asynk.core.asyncRead
import info.jdavid.asynk.core.asyncWrite
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory
import java.lang.RuntimeException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

internal object SecureRequest: AbstractRequest<AsynchronousSocketChannel, SecureRequest.Handshake>() {

  private val logger = LoggerFactory.getLogger(SecureRequest::class.java)


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
      val buffer1 = ByteBuffer.allocateDirect(16384)

      TLS.Handshake.clientHello(host, buffer, buffer1)
      channel.asyncWrite(buffer, true)

      val serverHello = nextRecord(channel, buffer, buffer1) as TLS.Handshake.ServerHello.Fragment
      var serverCertificate: TLS.Handshake.ServerCertificate.Fragment? = null
      var serverKeyExchange: TLS.Handshake.ServerKeyExchange.Fragment? = null
      var certificateRequest: TLS.Handshake.CertificateRequest.Fragment? = null
      loop@ while (true) {
        when (val record = nextRecord(channel, buffer, buffer1)) {
          is TLS.Handshake.ServerCertificate.Fragment -> serverCertificate = record
          is TLS.Handshake.ServerKeyExchange.Fragment -> serverKeyExchange = record
          is TLS.Handshake.CertificateRequest.Fragment -> certificateRequest = record
          is TLS.Handshake.ServerHelloDone.Fragment -> break@loop
        }
      }

      val cipherSuite = serverHello.cipherSuite

      if (certificateRequest != null) {
        TLS.Handshake.certificate(cipherSuite, buffer, buffer1)
      }

      if (serverKeyExchange != null) {
        TLS.Handshake.keyExchange(
          cipherSuite, serverKeyExchange.curve, serverKeyExchange.pubKey, buffer, buffer1
        )
      }

      TLS.Handshake.changeCipherSpec(buffer, buffer1)
      channel.asyncWrite(buffer, true)

      TLS.Handshake.finished(cipherSuite, buffer, buffer1)
      channel.asyncWrite(buffer, true)

      println("ok")
      Handshake(cipherSuite, buffer1, ByteBuffer.allocateDirect(16384))
    }
  }

  private suspend fun nextRecord(channel: AsynchronousSocketChannel, buffer: ByteBuffer,
                                 buffer1: ByteBuffer? = null): TLS.Fragment {
    buffer.compact()
    if (buffer.position() == 0) {
      channel.asyncRead(buffer)
    }
    buffer.flip()
    return TLS.record(buffer, buffer1).let {
      if (it is TLS.Alert.Fragment) {
        if (it.level == TLS.Alert.Level.FATAL) throw RuntimeException(it.description.toString())
        logger.info(it.description.toString())
        nextRecord(channel, buffer, buffer1)
      }
      else it
    }
  }

  override suspend fun read(channel: AsynchronousSocketChannel, handshake: Handshake,
                            timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  override suspend fun write(channel: AsynchronousSocketChannel, handshake: Handshake,
                             timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  class Handshake(private val cipherSuite: TLS.CipherSuite,
                  private val buffer1: ByteBuffer, private val buffer2: ByteBuffer)

}
