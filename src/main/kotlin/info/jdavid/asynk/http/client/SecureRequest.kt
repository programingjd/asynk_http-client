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
import java.util.LinkedList

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

      val clientHelloRandom = TLS.Handshake.clientHello(host, buffer, buffer1)
      channel.asyncWrite(buffer, true)

      val fragments = LinkedList<TLS.Fragment>()
      fragments.addAll(nextRecord(channel, buffer, buffer1))
      val serverHello = fragments.first() as TLS.Handshake.ServerHello.Fragment

      if (fragments.find { it is TLS.Handshake.ServerHelloDone.Fragment } == null) {
        while (true) {
          val record = nextRecord(channel, buffer, buffer1)
          fragments.addAll(record)
          if (
            record.fold(false) { done: Boolean, fragment: TLS.Fragment ->
              fragment is TLS.Handshake.ServerHelloDone.Fragment
            }
          ) break
        }
      }

      val cipherSuite = serverHello.cipherSuite

      val serverCertificate =
        fragments.find {
          it is TLS.Handshake.ServerCertificate.Fragment
        } as TLS.Handshake.ServerCertificate.Fragment

      if (fragments.find { it is TLS.Handshake.CertificateRequest.Fragment } != null) {
        TLS.Handshake.certificate(buffer, buffer1)
      }

      val serverHelloRandom = serverHello.random
      val preMasterSecret = //if (serverKeyExchange == null) {
        TLS.Handshake.rsaKeyExchange(
          cipherSuite, serverCertificate.certificates.first(),
          buffer, buffer1
        )
      //}
      channel.asyncWrite(buffer, true)

      TLS.Handshake.changeCipherSpec(buffer, buffer1)
      channel.asyncWrite(buffer, true)

      val masterSecret =
        TLS.masterSecret(cipherSuite, preMasterSecret, clientHelloRandom, serverHelloRandom)

      val encryptionKeys = cipherSuite.encryptionKeys(masterSecret, serverHelloRandom, clientHelloRandom)

      TLS.Handshake.finished(cipherSuite, masterSecret, encryptionKeys, buffer, buffer1)
      channel.asyncWrite(buffer, true)

      if (fragments.find { it is TLS.Handshake.ServerChangeCipherSpec.Fragment } == null) {
        fragments.addAll(nextRecord(channel, buffer, null))
        fragments.find {
          it is TLS.Handshake.ServerChangeCipherSpec.Fragment
        } as TLS.Handshake.ServerChangeCipherSpec.Fragment
      }

      println("ok")
      Handshake(cipherSuite, buffer1, ByteBuffer.allocateDirect(16384))
    }
  }

  private suspend fun nextRecord(channel: AsynchronousSocketChannel, buffer: ByteBuffer,
                                 buffer1: ByteBuffer? = null): List<TLS.Fragment> {
    buffer.compact()
    if (buffer.position() == 0) {
      channel.asyncRead(buffer)
    }
    buffer.flip()
    return TLS.record(buffer, buffer1).let {
      if (it.isEmpty()) throw RuntimeException()
      val result = it.filter {
        if (it is TLS.Alert.Fragment) {
          if (it == TLS.Alert.Level.FATAL) throw RuntimeException(it.description.toString())
          logger.info(it.description.toString())
          false
        }
        else true
      }
      if (result.isEmpty()) nextRecord(channel, buffer, buffer1) else result
    }
  }

  override suspend fun read(channel: AsynchronousSocketChannel, handshake: Handshake,
                            timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  override suspend fun write(channel: AsynchronousSocketChannel, handshake: Handshake,
                             timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  class Handshake(private val cipherSuite: TLS.CipherSuite,
                  private val buffer1: ByteBuffer, private val buffer2: ByteBuffer)

}
