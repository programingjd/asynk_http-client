package info.jdavid.asynk.http.client

import info.jdavid.asynk.core.asyncConnect
import info.jdavid.asynk.core.asyncRead
import info.jdavid.asynk.core.asyncWrite
import info.jdavid.asynk.http.Crypto
import kotlinx.coroutines.withTimeout
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel
import java.security.SecureRandom
import java.util.UUID

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
      val sessionId = UUID.randomUUID().let {
        buffer.putLong(it.mostSignificantBits)
        buffer.putLong(it.leastSignificantBits)
        buffer.flip()
        ByteArray(16).apply {
          buffer.get(this)
          buffer.clear()
        }
      }
      // TLS ContentType: Handshake (0x16)
      buffer.put(0x16)
      // TLS Version: Major + Minor (0x0301 for TLS 1.0; not TLS 1.2 for compatibility)
      buffer.put(0x03)
      buffer.put(0x01)

      // Record Length uint16
      /// Will be updated at the end
      val position = buffer.position()
      buffer.putShort(0)

      // Fragment
      val random = ClientHello(host, sessionId, buffer)

      // Update record length
      val length = (buffer.position() - position - 2).toShort()
      buffer.putShort(position, length)

      println("writing")

      buffer.flip()
      println(Crypto.hex(ByteArray(buffer.remaining()).apply { buffer.get(this); buffer.flip() }))
      channel.asyncWrite(buffer, true)

      println("reading")

      buffer.clear()
      channel.asyncRead(buffer)

      println(Crypto.hex(ByteArray(buffer.remaining()).apply { buffer.get(this) }))

      Handshake(sessionId)
    }
  }

  override suspend fun read(channel: AsynchronousSocketChannel, handshake: Handshake,
                            timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  override suspend fun write(channel: AsynchronousSocketChannel, handshake: Handshake,
                             timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  class Handshake(sessionId: ByteArray)



  object ClientHello {

    private val handshakeType: Byte = 0x01

    operator fun invoke(host: String,
                        sessionId: ByteArray,
                        buffer: ByteBuffer): ByteArray {
      // HandshakeType + uint24 length will be updated at the end
      val position = buffer.position()
      buffer.putInt(0)

      // Version major + minor (TLS 1.2 is ok here).
      buffer.put(0x03)
      buffer.put(0x03)

      // Random: uint32 gmt_unix_time + opaque byte[28]
      val random = SecureRandom.getSeed(32)
      //ByteBuffer.wrap(random).putInt(0, (System.currentTimeMillis() / 1000).toInt())
      buffer.put(random)

      // SessionID: opaque byte[0..32]
      //buffer.put(sessionId)
      buffer.put(0x00)

      // CipherSuite byte[2]
      buffer.putShort((cyperSuites.size * 2).toShort())
      for (suite in cyperSuites) {
        buffer.put(suite.value)
      }

      // Compression byte[2]
      buffer.put(0x01.toByte())
      buffer.put(0x00)

      Extensions(host, buffer)

      // update handshake type + length
      val size = buffer.position() - position - 4
      buffer.putInt(position, size)
      buffer.put(position, handshakeType)

      return random
    }

  }

  object Extensions {

    operator fun invoke(host: String, buffer: ByteBuffer) {
      // Length will be updated at the end
      val position = buffer.position()
      buffer.putShort(0x0000)

      serverName(host, buffer)
      statusRequest(buffer)
      supportedGroups(buffer)
      ecPointFormats(buffer)
      renegotiationInfo(buffer)
      //signedCertificateTimestamp(buffer)

      val size = (buffer.position() - position - 2).toShort()
      buffer.putShort(position, size)
    }

    fun serverName(host: String, buffer: ByteBuffer) {
      // Extension type = ServerName 0x0000
      buffer.putShort(0x0000)

      // lengths, updated at the end
      val position = buffer.position()
      buffer.putShort(0)
      buffer.putShort(0)

      // list entry type DNS hostname
      buffer.put(0x00)

      // length, updated at the end
      buffer.putShort(0)

      buffer.put(host.toByteArray())

      val size = (buffer.position() - position).toShort()
      buffer.putShort(position, size)
      buffer.putShort(position + 2, (size - 2).toShort())
      buffer.putShort(position + 5, (size - 7).toShort())
    }

    fun statusRequest(buffer: ByteBuffer) {
      // Extension type = StatusRequest 0x0005
      buffer.putShort(0x0005)

      // length
      buffer.putShort(5)

      buffer.put(0x01)
      buffer.putShort(0)
      buffer.putShort(0)
    }

    fun supportedGroups(buffer: ByteBuffer) {
      // Extension type = SupportedGroups 0x000a
      buffer.putShort(0x000a)

      // lengths
      buffer.putShort((curves.size * 2 + 2).toShort())
      buffer.putShort((curves.size * 2).toShort())

      for (group in curves) {
        buffer.putShort(group.value)
      }
    }

    fun ecPointFormats(buffer: ByteBuffer) {
      // Extension type = ECPointFormats 0x000b
      buffer.putShort(0x000b)

      // length
      buffer.putShort(2)

      buffer.put(0x01)
      buffer.put(0x00)
    }

    fun renegotiationInfo(buffer: ByteBuffer) {
      // Extension type = SignatureAlgorithms 0xff01
      buffer.putShort(0xff01.toShort())

      // length
      buffer.putShort(1)

      buffer.put(0x00)
    }

    fun signedCertificateTimestamp(buffer: ByteBuffer) {
      // Extension type = SCT 0x0012
      buffer.putShort(0x0012)

      // length
      buffer.putShort(0)
    }

  }

  val cyperSuites = mapOf(
//    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" to byteArrayOf(0xc0.toByte(), 0x2b.toByte()),
//    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" to byteArrayOf(0xc0.toByte(), 0x09.toByte()),
//    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" to byteArrayOf(0xc0.toByte(), 0x0a.toByte()),
//    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" to byteArrayOf(0xc0.toByte(), 0x2f.toByte()),
//    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" to byteArrayOf(0xc0.toByte(), 0x13.toByte()),
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" to byteArrayOf(0x00.toByte(), 0x9e.toByte()),
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" to byteArrayOf(0xc0.toByte(), 0x33.toByte())
  )

  val curves = mapOf(
    "secp256r1" to 0x0023.toShort(),
    "secp384r1" to 0x0024.toShort(),
    "secp521r1" to 0x0025.toShort()
  )

}
