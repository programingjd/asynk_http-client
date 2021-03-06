package info.jdavid.asynk.http.client

import info.jdavid.asynk.core.asyncRead
import info.jdavid.asynk.http.Crypto
import java.io.ByteArrayInputStream
import java.lang.RuntimeException
import java.lang.UnsupportedOperationException
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object TLS {

  interface Fragment

  object ApplicationData {

    operator fun invoke(handshake: SecureRequest.Handshake, buffer: ByteBuffer, length: Int): ByteArray {
      val iv = ByteArray(16).apply { buffer.get(this) }
      val payload = ByteArray(length - 16).apply { buffer.get(this) }
      return handshake.cipherSuite.decrypt(iv, handshake.encryptionKeys, payload)
    }

  }

  object Alert {

    fun closeNotify(buffer: ByteBuffer) {
      buffer.put(Level.WARNING.id)
    }

    operator fun invoke(buffer: ByteBuffer): Fragment {
      // length should be 2
      @Suppress("UsePropertyAccessSyntax")

      val level = Level.valueOf(buffer.get())
      val description = Description.valueOf(buffer.get())
      return Fragment(level, description)
    }

    data class Fragment(val level: Level, val description: Description): TLS.Fragment

    enum class Level(internal val id: Byte) {
      WARNING(0x01.toByte()),
      FATAL(0x02.toByte()),
      UNSPECIFIED(0xff.toByte());

      companion object {
        private val values = Level.values().associate { it.id to it }
        fun valueOf(id: Byte) = values[id] ?: throw RuntimeException("Unexpected Alert level.")
      }
    }

    enum class Description(internal val id: Byte) {
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

    fun clientHello(host: String, buffer: ByteBuffer, buffer1: ByteBuffer): ByteArray {
      return ContentType.HANDSHAKE.record(buffer, true, buffer1) {
        ClientHello(host, null, it)
      }
    }

    fun clientHello(host: String, sessionId: ByteArray,
                    buffer: ByteBuffer, buffer1: ByteBuffer): ByteArray {
      return ContentType.HANDSHAKE.record(buffer, buffer1) {
        ClientHello(host, sessionId, it)
      }
    }

    fun certificate(buffer: ByteBuffer, buffer1: ByteBuffer) {
      ContentType.HANDSHAKE.record(buffer, buffer1) {
        ClientCertificate(it)
      }
    }

    fun rsaKeyExchange(cipherSuite: CipherSuite, certificate: ByteArray,
                       buffer: ByteBuffer, buffer1: ByteBuffer): ByteArray {
      return ContentType.HANDSHAKE.record(buffer, buffer1) {
        RSAClientKeyExchange(cipherSuite, certificate, it)
      }
    }

    fun changeCipherSpec(buffer: ByteBuffer, buffer1: ByteBuffer) {
      ContentType.CHANGE_CIPHER_SPEC.record(buffer, null) {
        ClientChangeCipherSpec(it)
      }
    }

    fun finished(cipherSuite: CipherSuite,
                 masterSecret: ByteArray,
                 encryptionKeys: Array<ByteArray>,
                 buffer: ByteBuffer, buffer1: ByteBuffer) {
      ContentType.HANDSHAKE.encrypt(cipherSuite, encryptionKeys, 0L, buffer) {
        ClientFinished(cipherSuite, masterSecret, buffer1, it)
      }
    }

    operator fun invoke(buffer: ByteBuffer, buffer1: ByteBuffer?): Fragment {
      val position = buffer.position()
      val fragment =
        when (val type = HandshakeType.valueOf(buffer.get(buffer.position()))) {
          HandshakeType.HELLO_REQUEST -> TODO()
          HandshakeType.SERVER_HELLO -> ServerHello(buffer)
          HandshakeType.CERTIFICATE -> ServerCertificate(buffer)
          HandshakeType.SERVER_KEY_EXCHANGE -> ServerKeyExchange(buffer)
          HandshakeType.CERTIFICATE_REQUEST -> CertificateRequest(buffer)
          HandshakeType.SERVER_HELLO_DONE -> ServerHelloDone(buffer)
          else -> throw RuntimeException("Unexpected record type ${type}.")
        }
      if (buffer1 != null) {
        val p = buffer.position()
        val l = buffer.limit()
        buffer.position(position).limit(p)
        buffer1.put(buffer)
        buffer.position(p).limit(l)
      }
      return fragment
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
          //statusRequest(buffer)
          //supportedGroups(buffer)
          //ecPointFormats(buffer)
          renegotiationInfo(buffer)
          recordSizeLimit(buffer)

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
          // Extension type = RenegociationInfo 0xff01
          buffer.putShort(ExtensionType.RENEGOTIATION_INFO.id)

          // length
          buffer.putShort(1)

          buffer.put(0x00)
        }

        // RFC 8449
        private fun recordSizeLimit(buffer: ByteBuffer) {
          // Extension type = RecordSizeLimit 0x001c
          buffer.putShort(ExtensionType.RECORD_SIZE_LIMIT.id)

          // length
          buffer.putShort(4)

          // limit to 16kb
          buffer.putInt(16384)
        }

        // RFC 7627
        private fun extendedMasterSecret(buffer: ByteBuffer) {
          buffer.putShort(ExtensionType.EXTENDED_MASTER_SECRET.id)

          // length
          buffer.putShort(0)
        }

      }

    }

    object ClientCertificate {

      operator fun invoke(buffer: ByteBuffer) {
        // HandshakeType + uint24 length
        val position = buffer.position()
        buffer.putInt(0)
        buffer.put(position, HandshakeType.CERTIFICATE.id)
      }

    }

    object RSAClientKeyExchange {

      operator fun invoke(cipherSuite: CipherSuite,
                          certificate: ByteArray,
                          buffer: ByteBuffer): ByteArray {
        // HandshakeType + uint24 length will be updated at the end
        val position = buffer.position()
        buffer.putInt(0)

        val preMasterSecret = cipherSuite.preMasterSecret()
        val encryptedPreMasterSecret = cipherSuite.encrypt(certificate, preMasterSecret)

        buffer.putShort(encryptedPreMasterSecret.size.toShort())
        buffer.put(encryptedPreMasterSecret)

        // update handshake type + length
        val size = buffer.position() - position - 4
        buffer.putInt(position, size)
        buffer.put(position, HandshakeType.CLIENT_KEY_EXCHANGE.id)

        return preMasterSecret
      }

    }

    object DHClientKeyExchange {

      operator fun invoke(cipherSuite: CipherSuite,
                          certificate: ByteArray,
                          curve: String, serverPublicKey: ByteArray,
                          buffer: ByteBuffer): ByteArray {
        // HandshakeType + uint24 length will be updated at the end
        val position = buffer.position()
        buffer.putInt(0)

        // TODO
        // ecdhe key
        buffer.put(0x00) // length
        buffer.put(byteArrayOf()) // key

        // update handshake type + length
        val size = buffer.position() - position - 4
        buffer.putInt(position, size)
        buffer.put(position, HandshakeType.CLIENT_KEY_EXCHANGE.id)

        // val preMasterSecret = key.trimLeadingZeros()

        return TODO()
      }

    }

    object ServerHello {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): Fragment {
        buffer.get() // 0x02
        val length = buffer.getInt24()
        val position = buffer.position()

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

        assert(buffer.position() == position + length)
        return Fragment(sessionId, random, cipherSuite)
      }

      class Fragment(
        val sessionId: ByteArray?,
        val random: ByteArray,
        val cipherSuite: CipherSuite
      ): TLS.Fragment {
        private fun hex(a: ByteArray?) = Crypto.hex(a ?: byteArrayOf())
        override fun toString() =
          "ServerHello.Fragment(sessionId=${hex(sessionId)},random=${hex(random)},cipherSuite=${cipherSuite})"
      }

    }

    object ServerCertificate {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): Fragment {
        buffer.get()
        val length = buffer.getInt24()
        val position = buffer.position()

        // 0x0b + 3-byte length
        var chainLength = buffer.getInt24()
        val certs = ArrayList<ByteArray>(1)
        while (chainLength > 0) {
          val certLength = buffer.getInt24()
          certs.add(ByteArray(certLength).apply { buffer.get(this) })
          chainLength -= (certLength + 3)
        }

        assert(buffer.position() == position + length)
        return Fragment(certs)
      }

      class Fragment(
        val certificates: List<ByteArray>
      ): TLS.Fragment {
        private fun certsString() = certificates.map { Crypto.hex(it) }.joinToString(",")
        override fun toString() = "ServerCertificate.Fragment(certificates=[${certsString()}])"
      }

    }

    object ServerKeyExchange {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): Fragment {
        buffer.get() // 0x0c
        val length = buffer.getInt24()
        val position = buffer.position()

        if (buffer.get() != 0x03.toByte()) throw RuntimeException() // 0x03 for "named curve"
        val curveId = buffer.getShort()
        val curve = curves.entries.find { it.value == curveId }?.key ?: throw RuntimeException()

        val pubKeyLength = buffer.get().toInt()
        val pubKey = ByteArray(pubKeyLength).apply { buffer.get(this) }

        buffer.getShort() // signature type
        val signatureLength = buffer.getShort().toInt()
        ByteArray(signatureLength).apply { buffer.get(this) } // Signature

        assert(buffer.position() == position + length)
        return Fragment(curve, pubKey)
      }

      class Fragment(
        val curve: String,
        val pubKey: ByteArray
      ): TLS.Fragment {
        override fun toString() = "ServerKeyExchange.Fragment(curve=${curve},pubKey=${Crypto.hex(pubKey)})"
      }

    }

    object CertificateRequest {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): Fragment {
        buffer.get() // 0xd + 3-byte length
        val length = buffer.getInt24()

        // we are going to send an empty certificate list, so we don't care about the content.
        val bytes = ByteArray(length)
        buffer.get(bytes)

        return Fragment()
      }

      class Fragment: TLS.Fragment {
        override fun toString() = "CertificateRequest.Fragment()"
      }

    }

    object ServerHelloDone {

      @Suppress("UsePropertyAccessSyntax")
      operator fun invoke(buffer: ByteBuffer): Fragment {
        buffer.getInt() // 0x0e + 3-byte length

        return Fragment()
      }

      class Fragment: TLS.Fragment {
        override fun toString() = "ServerHelloDone.Fragment()"
      }

    }

    object ClientChangeCipherSpec {

      operator fun invoke(buffer: ByteBuffer) {
        buffer.put(0x01)
      }

    }

    object ServerChangeCipherSpec {

      operator fun invoke(buffer: ByteBuffer): Fragment {
        buffer.get() // 0x01

        return Fragment()
      }

      class Fragment: TLS.Fragment {
        override fun toString() = "ChangeCipherSpec.Fragment()"
      }

    }

    object ClientFinished {

      operator fun invoke(cipherSuite: CipherSuite,
                          masterSecret: ByteArray,
                          buffer1: ByteBuffer,
                          buffer: ByteBuffer) {
        // HandshakeType + uint24 length will be updated at the end
        val position = buffer.position()
        buffer.putInt(0)

        buffer1.flip()
        val handshakeHash = cipherSuite.hash(buffer1)

        val verifyData = cipherSuite.prf(
          cipherSuite.verifyDataLength(),
          masterSecret,
          "client finished",
          handshakeHash
        )
        buffer.put(verifyData)

        // update handshake type + length
        val size = buffer.position() - position - 4
        buffer.putInt(position, size)
        buffer.put(position, HandshakeType.FINISHED.id)
      }

    }

    object ServerFinished {

      operator fun invoke(): Fragment {
        return Fragment()
      }

      class Fragment: TLS.Fragment {
        override fun toString() = "Finished.Fragment()"
      }

    }

  }

  fun masterSecret(cipherSuite: CipherSuite, preMasterSecret: ByteArray,
                   clientRandom: ByteArray, serverRandom: ByteArray) =
    cipherSuite.prf(48, preMasterSecret, "master secret", clientRandom + serverRandom)

  private fun applicationData(handshake: SecureRequest.Handshake, buffer: ByteBuffer,
                              destination: ByteBuffer): Int {
    val version = version(buffer)
    return when (version) {
      ContentType.ALERT -> {
        @Suppress("UsePropertyAccessSyntax") val length = buffer.getShort()
        if (buffer.remaining() < length) -2
        else {
          val position = buffer.position()
          while (true) {
            val alert = Alert(buffer)
            when (alert.level) {
              Alert.Level.FATAL -> throw RuntimeException(alert.description.name)
              Alert.Level.WARNING -> println(alert.description.name)
              else -> throw RuntimeException()
            }
            if (buffer.position() == position + length) break
          }
          -1
        }
      }
      ContentType.APPLICATION_DATA -> {
        @Suppress("UsePropertyAccessSyntax") val length = buffer.getShort()
        if (buffer.remaining() < length) -2
        else {
          val bytes = ApplicationData(handshake, buffer, length.toInt())
          val n = bytes.size - bytes[bytes.size - 1] - 1 - 20
          destination.put(bytes, 0, n)
          n
        }
      }
      else -> throw RuntimeException()
    }
  }

  suspend fun applicationData(handshake: SecureRequest.Handshake,
                              channel: AsynchronousSocketChannel,
                              buffer: ByteBuffer, destination: ByteBuffer,
                              readMore: Boolean) {
    if (readMore) {
      val position = buffer.position()
      while (buffer.position() < 5) {
        channel.asyncRead(buffer)
      }
      buffer.limit(buffer.position())
      buffer.position(position)
    }
    val r = applicationData(handshake, buffer, destination)
    if (buffer.hasRemaining()) {
      buffer.compact()
    }
    else {
      buffer.clear()
    }
    when (r) {
      -2 -> applicationData(handshake, channel, buffer, destination, true)
      -1 -> applicationData(handshake, channel, buffer, destination, buffer.remaining() < 5)
    }
  }

  fun record(handshake: SecureRequest.Handshake?, buffer: ByteBuffer, buffer1: ByteBuffer?): List<Fragment> {
    return when (version(buffer)) {
      ContentType.ALERT -> {
        @Suppress("UsePropertyAccessSyntax") val length = buffer.getShort()
        val position = buffer.position()
        val list = ArrayList<Fragment>(4)
        while (true) {
          list.add(Alert(buffer))
          if (buffer.position() == position + length) break
        }
        list
      }
      ContentType.CHANGE_CIPHER_SPEC -> {
        @Suppress("UsePropertyAccessSyntax") val length = buffer.getShort()
        val position = buffer.position()
        val list = ArrayList<Fragment>(1)
        while (true) {
          list.add(Handshake.ServerChangeCipherSpec(buffer))
          if (buffer.position() == position + length) break
        }
        list
      }
      ContentType.HANDSHAKE -> {
        if (handshake == null) {
          @Suppress("UsePropertyAccessSyntax") val length = buffer.getShort()
          val position = buffer.position()
          val list = ArrayList<Fragment>(4)
          while (true) {
            list.add(Handshake(buffer, buffer1))
            if (buffer.position() == position + length) break
          }
          list
        }
        else {
          @Suppress("UsePropertyAccessSyntax") val length = buffer.getShort()
          buffer.position(buffer.position() + length)
          val list = ArrayList<Fragment>(1)
          list.add(Handshake.ServerFinished())
          list
        }
      }
      else -> throw RuntimeException("Unexpected record type.")
    }
  }

  private fun version(buffer: ByteBuffer): ContentType {
    val recordType = buffer.get()
    val major = buffer.get()
    if (major != 0x03.toByte()) throw RuntimeException("Unexpected tls major version ${major}.")
    val minor = buffer.get()
    if (minor < 0x00 || minor > 0x04) throw RuntimeException("Unexpected tls minor version ${minor}.")
    return ContentType.valueOf(recordType)
  }

  private fun ByteBuffer.getInt24(): Int {
    return (get().toInt() and 0xff shl 16) or (get().toInt() and 0xff shl 8) or (get().toInt() and 0xff)
  }

  private fun ByteBuffer.getInt24(position: Int): Int {
    return (get(position).toInt() and 0xff shl 16) or
           (get(position + 1).toInt() and 0xff shl 8) or
           (get(position + 2).toInt() and 0xff)
  }

  interface CipherSuite {
    fun blockLength(): Int
    fun verifyDataLength(): Int
    fun preMasterSecret(): ByteArray
    fun encryptionKeys(masterSecret: ByteArray,
                       serverRandom: ByteArray,
                       clientRandom: ByteArray): Array<ByteArray>
    fun hash(data: ByteBuffer): ByteArray
    fun prf(size: Int, secret: ByteArray, label: String, seed: ByteArray): ByteArray
    fun encrypt(certificate: ByteArray, payload: ByteArray): ByteArray
    fun encrypt(iv: ByteArray, keys: Array<ByteArray>, payload: ByteArray, macHeader: ByteArray): ByteArray
    fun decrypt(iv: ByteArray, keys: Array<ByteArray>, payload: ByteArray): ByteArray
  }

  object NULL_CIPHER: CipherSuite {
    override fun blockLength() = throw UnsupportedOperationException()
    override fun verifyDataLength() = throw UnsupportedOperationException()
    override fun preMasterSecret() = throw UnsupportedOperationException()
    override fun encryptionKeys(masterSecret: ByteArray, serverRandom: ByteArray,
                                clientRandom: ByteArray) = throw UnsupportedOperationException()
    override fun hash(data: ByteBuffer) = throw UnsupportedOperationException()
    override fun prf(size: Int, secret: ByteArray,
                     label: String, seed: ByteArray) = throw UnsupportedOperationException()
    override fun encrypt(certificate: ByteArray, payload: ByteArray) = throw UnsupportedOperationException()
    override fun encrypt(iv: ByteArray, keys: Array<ByteArray>, payload: ByteArray,
                         macHeader: ByteArray) = throw UnsupportedOperationException()
    override fun decrypt(iv: ByteArray, keys: Array<ByteArray>,
                         payload: ByteArray) = throw UnsupportedOperationException()
  }

  // This one is mandatory for tls 1.2
  object TLS_RSA_WITH_AES_128_CBC_SHA: CipherSuite {
    override fun blockLength() = 16
    override fun verifyDataLength() = 12

    fun serverPublicKey(certificate: ByteArray): RSAPublicKey {
      val x509 =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(certificate))
      return x509.publicKey as RSAPublicKey
    }

    override fun preMasterSecret(): ByteArray {
      val bytes = SecureRandom.getInstanceStrong().generateSeed(48)
      bytes[0] = 0x03
      bytes[1] = 0x03
      return bytes
    }

    override fun encryptionKeys(masterSecret: ByteArray,
                                serverRandom: ByteArray,
                                clientRandom: ByteArray): Array<ByteArray> {
      val size = 72
      val keyBlock = prf(size, masterSecret, "key expansion", serverRandom + clientRandom)

      return arrayOf(
        keyBlock.copyOfRange(0, 20),
        keyBlock.copyOfRange(20, 40),
        keyBlock.copyOfRange(40, 56),
        keyBlock.copyOfRange(56, 72)
      )
    }

    // TLS 1.2 version only
    override fun prf(size: Int, secret: ByteArray, label: String, seed: ByteArray) =
      pSHA256(size, secret, label.toByteArray(Charsets.US_ASCII) + seed)

    private fun pSHA256(size: Int, secret: ByteArray, seed: ByteArray): ByteArray {
      val mac = Mac.getInstance("HMACSHA256").apply {
        init(SecretKeySpec(secret, "HMACSHA256"))
      }
      var hmac = byteArrayOf()
      var a = seed
      while (true) {
        a = mac.doFinal(a)
        hmac += mac.doFinal(a + seed)
        if (hmac.size >= size) break
      }
      return hmac.copyOfRange(0, size)
    }

    override fun hash(data: ByteBuffer): ByteArray {
      return MessageDigest.getInstance("SHA-256").apply { update(data) }.digest()
    }

    override fun encrypt(certificate: ByteArray, payload: ByteArray): ByteArray {
      val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
      cipher.init(Cipher.WRAP_MODE, serverPublicKey(certificate))
      return cipher.wrap(SecretKeySpec(payload, "RSA"))
    }

    override fun encrypt(iv: ByteArray, keys: Array<ByteArray>,
                         payload: ByteArray,
                         macHeader: ByteArray): ByteArray {
      val hmac = Mac.getInstance("HMACSHA1").apply {
        init(SecretKeySpec(keys[0], "HMACSHA1"))
        update(macHeader)
      }
      val mac = hmac.doFinal(payload)

      val paddingSize = when(val k = (payload.size + mac.size) % 16) {
        0 -> 16
        else -> 16 - k
      }
      val paddingValue = (paddingSize - 1).toByte()
      val padding = ByteArray(paddingSize) { paddingValue }

      val encrypted = Cipher.getInstance("AES/CBC/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(keys[2], "AES"), IvParameterSpec(iv))
      }.doFinal(payload + mac + padding)

      return encrypted
    }

    override fun decrypt(iv: ByteArray, keys: Array<ByteArray>, payload: ByteArray): ByteArray {
      val decrypted = Cipher.getInstance("AES/CBC/NoPadding").apply {
        init(Cipher.DECRYPT_MODE, SecretKeySpec(keys[3], "AES"), IvParameterSpec(iv))
      }.doFinal(payload)

      return decrypted
    }

  }

  val cipherSuites = mapOf<CipherSuite, Short>(
//    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" to 0xc02b.toShort(),
//    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" to 0xc023.toShort(),
//    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" to 0xc009.toShort(),
//    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" to 0x009e.toShort(),
//    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" to 0xc033.toShort(),
//    "TLS_RSA_WITH_AES_128_CBC_SHA" to 0x002f.toShort(),
    TLS_RSA_WITH_AES_128_CBC_SHA to 0x002f.toShort()
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

    fun <T> encrypt(cipherSuite: CipherSuite, encryptionKeys: Array<ByteArray>, sequence: Long,
                    buffer: ByteBuffer, f: (buffer: ByteBuffer) -> T): T {
      buffer.clear()
      val result = f(buffer)
      buffer.flip()

      val data = ByteArray(buffer.remaining()).apply { buffer.get(this) }
      val iv = SecureRandom.getSeed(cipherSuite.blockLength())

      val macHeader = ByteArray(13)
      ByteBuffer.wrap(macHeader).apply {
        putLong(sequence) // sequence number
        put(id)      // type
        put(0x03) // version major
        put(0x03) // version minor
        putShort(data.size.toShort())
      }

      val encryptedData = cipherSuite.encrypt(iv, encryptionKeys, data, macHeader)

      buffer.clear()
      // TLS ContentType
      buffer.put(id)

      // TLS Version: Major + Minor
      buffer.put(0x03)
      buffer.put(0x03)

      // Length (updated at the end)
      val position = buffer.position()
      buffer.putShort(0)

      // IV
      buffer.put(iv)
      // Cipher
      buffer.put(encryptedData)

      // Update length
      val length = (buffer.position() - position - 2).toShort()
      buffer.putShort(position, length)
      buffer.flip()

      return result
    }

    fun <T> record(buffer: ByteBuffer, buffer1: ByteBuffer?, f: (buffer: ByteBuffer) -> T): T {
      return record(buffer, false, buffer1, f)
    }

    fun <T> record(buffer: ByteBuffer, initial: Boolean,
                   buffer1: ByteBuffer?, f: (buffer: ByteBuffer) -> T): T {
      buffer.clear()
      // TLS ContentType
      buffer.put(id)
      // TLS Version: Major + Minor
      // 0x0301 (TLS 1.0) on the first record for compatibility reason, 0x0303 (TLS 1.2) for the next records
      buffer.put(0x03)
      buffer.put(if (initial) 0x01.toByte() else 0x03.toByte())

      // Length (updated at the end)
      val position = buffer.position()
      buffer.putShort(0)

      val result = f(buffer)

      // Update length
      val length = (buffer.position() - position - 2).toShort()
      buffer.putShort(position, length)

      if (buffer1 != null) {
        val p = buffer.position()
        val l = buffer.limit()
        buffer.position(position + 2).limit(position + 2 + length)
        buffer1.put(buffer)
        buffer.position(p).limit(l)
      }
      buffer.flip()

      return result
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
