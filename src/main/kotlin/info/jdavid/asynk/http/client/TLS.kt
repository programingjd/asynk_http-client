package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Crypto
import java.lang.RuntimeException
import java.nio.ByteBuffer
import java.security.SecureRandom

object TLS {

  interface Fragment

  object Alert {

    operator fun invoke(buffer: ByteBuffer): Message {
      // length should be 2
      @Suppress("UsePropertyAccessSyntax")
      if (buffer.getShort() != 0x02.toShort()) throw RuntimeException("Unexpected Alert record length.")

      val level = Level.valueOf(buffer.get())
      val description = Description.valueOf(buffer.get())
      return Message(level, description)
    }

    data class Message(val level: Level, val description: Description): Fragment

    enum class Level(private val id: Byte) {
      WARNING(0x01.toByte()),
      FATAL(0x02.toByte()),
      UNSPECIFIED(0xff.toByte());

      companion object {
        private val values = Level.values().associate { it.id to it }
        fun valueOf(id: Byte) = values[id] ?: throw RuntimeException("Unexpected Alert level.")
      }
    }

    enum class Description(private val id: Byte) {
      CLOSE_NOTIFY(0x00.toByte()),
      UNEXPECTED_MESSAGE(0x0a.toByte()),
      BAD_RECORD_MAC(0x14.toByte()),
      DECRYPTION_FAILED(0x15),
      RECORD_OVERFLOW(0x16),
      DECOMPRESSION_FAILURE(0x1e),
      HANDSHAKE_FAILURE(0x28),
      NO_CERTIFICATE(0x29),
      BAD_CERTIFICATE(0x2a),
      UNSUPPORTED_CERTIFICATE(0x2b),
      CERTIFICATE_REVOKED(0x2c),
      CERTIFICATE_EXPIRED(0x2d),
      CERTIFICATE_UNKNOWN(0x2e),
      ILLEGAL_PARAMETER(0x2f),
      UNKNOWN_CA(0x30),
      ACCESS_DENIED(0x31),
      DECODE_ERROR(0x32),
      DECRYPT_ERROR(0x33),
      EXPORT_RESTRICTION(0x3c),
      PROTOCOL_VERSION(0x46),
      INSUFFICIENT_SECURITY(0x47),
      INTERNAL_ERROR(0x50),
      USER_CANCELED(0x5a),
      NO_RENEGOTIATION(0x64),
      UNSUPPORTED_EXTENSION(0x6e),
      UNSPECIFIED(0xff.toByte());

      companion object {
        private val values = Description.values().associate { it.id to it }
        fun valueOf(id: Byte) = values[id] ?: throw RuntimeException("Unexpected Alert description.")
      }

    }

  }

  object Handshake {

    fun clientHello(host: String, buffer: ByteBuffer) {
      ContentType.HANDSHAKE.record(buffer) {
        ClientHello(host, it)
      }

    }

    fun read(buffer: ByteBuffer): Fragment {
      val length = buffer.getShort()
      return when (HandshakeType.valueOf(buffer.get(buffer.position()))) {
        HandshakeType.HELLO_REQUEST -> TODO()
        HandshakeType.SERVER_HELLO -> TODO()
        else -> throw RuntimeException("Unexpected record type.")
      }
    }

    object ClientHello {

      private val handshakeType: Byte = 0x01

      operator fun invoke(host: String,
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
          signedCertificateTimestamp(buffer)

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
          buffer.putShort(position, (size - 2).toShort())
          buffer.putShort(position + 2, (size - 4).toShort())
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

    }

  }

  fun record(buffer: ByteBuffer): Fragment {
    return when (version(buffer)) {
      ContentType.ALERT -> Alert(buffer)
      ContentType.HANDSHAKE -> Handshake.read(buffer)
      else -> throw RuntimeException("Unexpected record type.")
    }
  }

  fun version(buffer: ByteBuffer): ContentType {
    val recordType = buffer.get()
    val major = buffer.get()
    if (major != 0x03.toByte()) throw RuntimeException("Unexpected tls major version.")
    val minor = buffer.get() // should be 0x01
    if (major < 0x00 || major > 0x04) throw RuntimeException("Unexpected tls minor version.")
    return ContentType.valueOf(recordType)
  }

  val cyperSuites = mapOf(
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" to byteArrayOf(0xc0.toByte(), 0x2b.toByte()),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" to byteArrayOf(0xc0.toByte(), 0x23.toByte()),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" to byteArrayOf(0xc0.toByte(), 0x09.toByte()),
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" to byteArrayOf(0x00.toByte(), 0x9e.toByte()),
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" to byteArrayOf(0xc0.toByte(), 0x33.toByte()),
    "TLS_RSA_WITH_AES_128_CBC_SHA" to byteArrayOf(0x00.toByte(), 0x2f.toByte())
  )/*.filter {
    Cipher.getInstance()
  }*/

  val curves = mapOf(
    "secp256r1" to 0x0023.toShort(),
    "secp384r1" to 0x0024.toShort(),
    "secp521r1" to 0x0025.toShort()
  )

  enum class ContentType(private val id: Byte) {
    CHANGE_CIPHER_SPEC(0x14),
    ALERT(0x15),
    HANDSHAKE(0x16),
    APPLICATION_DATA(0x17);

    fun <T> record(buffer: ByteBuffer, f: (buffer: ByteBuffer) -> T) {
      // TLS ContentType
      buffer.put(id)
      // TLS Version: Major + Minor (0x0301 for TLS 1.0; not TLS 1.2 for compatibility)
      buffer.put(0x03)
      buffer.put(0x01)

      // Length (updated at the end)
      val position = buffer.position()
      buffer.putShort(0)

      f(buffer)

      // Update length
      val length = (buffer.position() - position - 2).toShort()
      buffer.putShort(position, length)
    }

    companion object {
      private val values = ContentType.values().associate { it.id to it }
      fun valueOf(id: Byte) =
        values[id] ?: throw RuntimeException("Unexpected record type 0x${Crypto.hex(byteArrayOf(id))}.")
    }
  }

  enum class HandshakeType(private val id: Byte) {
    HELLO_REQUEST(0x00),
    CLIENT_HELLO(0x01),
    SERVER_HELLO(0x02),
    CERTIFICATE(0x03),
    SERVER_KEY_EXCHANGE(0x04),
    CERTIFICATE_REQUEST(0x05),
    SERVER_HELLO_DONE(0x06),
    CERTIFICATE_VERIFY(0x07),
    CLIENT_KEY_EXCHANGE(0x08),
    FINISHED(0x09);

    companion object {
      private val values = HandshakeType.values().associate { it.id to it }
      fun valueOf(id: Byte) =
        values[id] ?: throw RuntimeException("Unexpected handshake type 0x${Crypto.hex(byteArrayOf(id))}.")
    }
  }

}
