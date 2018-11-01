package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Crypto
import java.lang.RuntimeException
import java.nio.ByteBuffer
import java.security.SecureRandom

object TLS {

  interface Fragment

  object Alert {

    operator fun invoke(buffer: ByteBuffer): Alert.Fragment {
      // length should be 2
      @Suppress("UsePropertyAccessSyntax")
      if (buffer.getShort() != 0x02.toShort()) throw RuntimeException("Unexpected Alert record length.")

      val level = Level.valueOf(buffer.get())
      val description = Description.valueOf(buffer.get())
      return Fragment(level, description)
    }

    data class Fragment(val level: Level, val description: Description): TLS.Fragment

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
        ClientHello(host, null, it)
      }
    }

    fun clientHello(host: String, sessionId: ByteArray, buffer: ByteBuffer) {
      ContentType.HANDSHAKE.record(buffer) {
        ClientHello(host, sessionId, it)
      }
    }

    fun read(buffer: ByteBuffer): Fragment {
      @Suppress("UsePropertyAccessSyntax") buffer.getShort() // record length
      return when (HandshakeType.valueOf(buffer.get(buffer.position()))) {
        HandshakeType.HELLO_REQUEST -> TODO()
        HandshakeType.SERVER_HELLO -> ServerHello(buffer)
        HandshakeType.CERTIFICATE -> ServerCertificate(buffer)
        HandshakeType.SERVER_KEY_EXCHANGE -> ServerKeyExchange(buffer)
        HandshakeType.SERVER_HELLO_DONE -> ServerHelloDone(buffer)
        else -> throw RuntimeException("Unexpected record type.")
      }
    }

    object ClientHello {

      operator fun invoke(host: String,
                          sessionId: ByteArray?,
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
        if (sessionId == null) {
          buffer.put(0x00)
        }
        else {
          buffer.put(sessionId.size.toByte())
          buffer.put(sessionId)
        }

        // CipherSuite byte[2]
        buffer.putShort((cipherSuites.size * 2).toShort())
        for (suite in cipherSuites) {
          buffer.putShort(suite.value)
        }

        // Compression byte[2]
        buffer.put(0x01.toByte())
        buffer.put(0x00)

        Extensions(host, buffer)

        // update handshake type + length
        val size = buffer.position() - position - 4
        buffer.putInt(position, size)
        buffer.put(position, HandshakeType.CLIENT_HELLO.id)

        return random
      }

      object Extensions {

        operator fun invoke(host: String, buffer: ByteBuffer) {
          // Length will be updated at the end
          val position = buffer.position()
          buffer.putShort(0x0000)

          serverName(host, buffer)
          statusRequest(buffer)
          //supportedGroups(buffer)
          //ecPointFormats(buffer)
          renegotiationInfo(buffer)

          val size = (buffer.position() - position - 2).toShort()
          buffer.putShort(position, size)
        }

        private fun serverName(host: String, buffer: ByteBuffer) {
          // Extension type = ServerName 0x0000
          buffer.putShort(ExtensionType.SERVER_NAME.id)

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

        private fun statusRequest(buffer: ByteBuffer) {
          // Extension type = StatusRequest 0x0005
          buffer.putShort(ExtensionType.STATUS_REQUEST.id)

          // length
          buffer.putShort(5)

          buffer.put(0x01)
          buffer.putShort(0)
          buffer.putShort(0)
        }

        private fun supportedGroups(buffer: ByteBuffer) {
          // Extension type = SupportedGroups 0x000a
          buffer.putShort(ExtensionType.SUPPORTED_GROUPS.id)

          // lengths
          buffer.putShort((curves.size * 2 + 2).toShort())
          buffer.putShort((curves.size * 2).toShort())

          for (group in curves) {
            buffer.putShort(group.value)
          }
        }

        private fun ecPointFormats(buffer: ByteBuffer) {
          // Extension type = ECPointFormats 0x000b
          buffer.putShort(ExtensionType.EC_POINT_FORMATS.id)

          // length
          buffer.putShort(2)

          buffer.put(0x01)
          buffer.put(0x00)
        }

        private fun renegotiationInfo(buffer: ByteBuffer) {
          // Extension type = SignatureAlgorithms 0xff01
          buffer.putShort(ExtensionType.RENEGOTIATION_INFO.id)

          // length
          buffer.putShort(1)

          buffer.put(0x00)
        }

      }

    }

    object ServerHello {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): ServerHello.Fragment {
        println("server hello")
        buffer.getInt() // 0x02 + 3-byte length
        // Version major + minor (TLS 1.2 is ok here).
        val major = buffer.get()
        if (major != 0x03.toByte()) throw RuntimeException("Unexpected tls major version.")
        val minor = buffer.get()
        if (minor < 0x00 || minor > 0x04) throw RuntimeException("Unexpected tls minor version.")

        val random = ByteArray(32).apply { buffer.get(this) }

        val sessionId = buffer.get().let {
          if (it == 0x00.toByte()) null else ByteArray(it.toInt()).apply { buffer.get(this) }
        }

        val cipherId = buffer.getShort()
        val cipherSuite =
          cipherSuites.entries.find { it.value == cipherId }?.key ?: throw RuntimeException()

        val compression = buffer.get()
        if (compression != 0x00.toByte()) throw RuntimeException()

        val extensionsLength = buffer.getShort()
        buffer.position(buffer.position() + extensionsLength)

        return Fragment(sessionId, random, cipherSuite)
      }

      class Fragment(
        val sessionId: ByteArray?,
        val random: ByteArray,
        val cipherSuite: String
      ): TLS.Fragment {
        override fun toString() = "ServerHello.Fragment(sessionId=${Crypto.hex(sessionId ?: byteArrayOf())}},random=${Crypto.hex(random)}},cipherSuite=${cipherSuite})"
      }

    }

    object ServerCertificate {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): ServerCertificate.Fragment {
        buffer.getInt() // 0x0b + 3-byte length
        buffer.get() // ignore last (high) byte for the length
        var chainLength = buffer.getShort().toInt()
        val certs = ArrayList<ByteArray>(1)
        while (chainLength > 0) {
          buffer.get() // ignore last (high) byte for the length
          val certLength = buffer.getShort().toInt()
          certs.add(ByteArray(certLength).apply { buffer.get(this) })
          chainLength -= (certLength + 3)
        }

        return Fragment(certs.first())
      }

      class Fragment(
        val certificate: ByteArray
      ): TLS.Fragment {
        override fun toString() = "ServerCertificate.Fragment(certificate=${Crypto.hex(certificate)})"
      }

    }

    object ServerKeyExchange {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): ServerKeyExchange.Fragment {
        buffer.getInt() // 0x0c + 3-byte length

        if (buffer.get() != 0x03.toByte()) throw RuntimeException() // 0x03 for "named curve"
        val curveId = buffer.getShort()
        val curve = curves.entries.find { it.value == curveId }?.key ?: throw RuntimeException()

        val pubKeyLength = buffer.get().toInt()
        val pubKey = ByteArray(pubKeyLength).apply { buffer.get(this) }

        buffer.getShort() // signature type
        val signatureLength = buffer.getShort().toInt()
        ByteArray(signatureLength).apply { buffer.get(this) } // Signature

        return Fragment(curve, pubKey)
      }

      class Fragment(
        val curve: String,
        val pubKey: ByteArray
      ): TLS.Fragment {
        override fun toString() = "ServerKeyExchange.Fragment(curve=${curve},pubKey=${Crypto.hex(pubKey)})"
      }

    }

    object ServerHelloDone {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): ServerHelloDone.Fragment {
        buffer.getInt() // 0x0e + 3-byte length

        return Fragment()
      }

      class Fragment: TLS.Fragment {
        override fun toString() = "ServerHelloDone.Fragment()"
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

  private fun version(buffer: ByteBuffer): ContentType {
    val recordType = buffer.get()
    val major = buffer.get()
    if (major != 0x03.toByte()) throw RuntimeException("Unexpected tls major version.")
    val minor = buffer.get() // should be 0x01
    if (minor < 0x00 || minor > 0x04) throw RuntimeException("Unexpected tls minor version.")
    return ContentType.valueOf(recordType)
  }

  val cipherSuites = mapOf(
//    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" to 0xc02b.toShort(),
//    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" to 0xc023.toShort(),
//    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" to 0xc009.toShort(),
//    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" to 0x009e.toShort(),
//    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" to 0xc033.toShort(),
    "TLS_RSA_WITH_AES_128_CBC_SHA" to 0x002f.toShort()
  )

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

  enum class HandshakeType(internal val id: Byte) {
    HELLO_REQUEST(0x00),
    CLIENT_HELLO(0x01),
    SERVER_HELLO(0x02),
    HELLO_VERIFY_REQUEST(0x03),
    NEW_SESSION_TICKET(0x04),
    END_OF_EARLY_DATA(0x05),
    HELLO_RETRY_REQUEST(0x06),
    ENCRYPTED_EXTENSIONS(0x08),
    CERTIFICATE(0x0b),
    SERVER_KEY_EXCHANGE(0x0c),
    CERTIFICATE_REQUEST(0x0d),
    SERVER_HELLO_DONE(0x0e),
    CERTIFICATE_VERIFY(0x0f),
    CLIENT_KEY_EXCHANGE(0x10),
    FINISHED(0x14),
    CERTIFICATE_URL(0x15),
    CERTIFICATE_STATUS(0x16),
    SUPPLEMENTAL_DATA(0x17),
    KEY_UPDATE(0x18),
    MESSAGE_HASH(0xfe.toByte());

    companion object {
      private val values = HandshakeType.values().associate { it.id to it }
      fun valueOf(id: Byte) =
        values[id] ?: throw RuntimeException("Unexpected handshake type 0x${Crypto.hex(byteArrayOf(id))}.")
    }
  }

  enum class ExtensionType(internal val id: Short) {
    SERVER_NAME(0x0000),
    CLIENT_CERTIFICATE_URL(0x0002),
    TRUSTED_CA_KEYS(0x0003),
    STATUS_REQUEST(0x0005),
    USER_MAPPING(0x0006),
    CERT_TYPE(0x0009),
    SUPPORTED_GROUPS(0x000a),
    EC_POINT_FORMATS(0x000b),
    SIGNATURE_ALGORITHMS(0x000d),
    USE_SRTP(0x000e),
    HEARTBEAT(0x000f),
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION(0x0010),
    STATUS_REQUEST_V2(0x0011),
    CLIENT_CERTIFICATE_TYPE(0x0012),
    SERVER_CERTIFICATE_TYPE(0x0014),
    PADDING(0x0015),
    ENCRYPT_THEN_MAC(0x0016),
    EXTENDED_MASTER_SECRET(0x0017),
    TOKEN_BINDING(0x0018),
    CACHED_INFO(0x0019),
    RECORD_SIZE_LIMIT(0x001c),
    SESSION_TICKET(0x0023),
    PRE_SHARED_KEY(0x0029),
    EARLY_DATA(0x002a),
    SUPPORTED_VERSION(0x002b),
    COOKIE(0x002c),
    PSK_KEY_EXCHANGE_MODES(0x002d),
    CERTIFICATE_AUTHORITIES(0x002f),
    OID_FILTERS(0x0030),
    POST_HANDSHAKE_AUTH(0x0031),
    SIGNATURE_ALGORITHM_CERT(0x0032),
    KEY_SHARE(0x0033),
    RENEGOTIATION_INFO(0xff01.toShort());

    companion object {
      private val values = ExtensionType.values().associate { it.id to it }
      fun valueOf(id: Short) =
        values[id] ?: throw RuntimeException("Unexpected extension type.")
    }
  }

}
