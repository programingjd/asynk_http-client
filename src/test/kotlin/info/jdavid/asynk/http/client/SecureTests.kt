package info.jdavid.asynk.http.client

import com.fasterxml.jackson.databind.ObjectMapper
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsParameters
import com.sun.net.httpserver.HttpsServer
import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.MediaType
import info.jdavid.ok.server.HttpServer
import info.jdavid.ok.server.Https
import info.jdavid.ok.server.RequestHandler
import info.jdavid.ok.server.RequestHandlerChain
import info.jdavid.ok.server.Response
import info.jdavid.ok.server.StatusLines
import info.jdavid.ok.server.handler.Handler
import info.jdavid.ok.server.handler.Request
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl
import okio.Buffer
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

@Disabled
class SecureTests {

  private val cert = """
    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
  """.trimIndent()

  fun server() {
    System.setProperty("javax.net.debug", "ssl")
    val context = SSLContext.getInstance("TLS").apply {
      init(
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
          init(
            KeyStore.getInstance("PKCS12").apply {
              load(ByteArrayInputStream(Base64.getMimeDecoder().decode(cert)), charArrayOf())
            },
            charArrayOf()
          )
        }.keyManagers,
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
          init(
            KeyStore.getInstance("JKS").apply {
              load(null, null)
            }
          )
        }.trustManagers,
        null
      )
    }

    HttpsServer.create(InetSocketAddress(8181), 0).apply {
      httpsConfigurator = object: HttpsConfigurator(context) {
        override fun configure(params: HttpsParameters) {
          params.setSSLParameters(context.defaultSSLParameters)
          params.protocols = arrayOf("TLSv1.2")
        }
      }
      createContext("/test") { exchange -> exchange.sendResponseHeaders(200, 0) }
      createContext("/test2") { exchange ->
        val bytes = "Test2".toByteArray()
        exchange.sendResponseHeaders(200, bytes.size.toLong())
        exchange.responseBody.write(bytes)
        exchange.responseBody.close()
      }
      createContext("/test3") { exchange ->
        exchange.responseHeaders.set(Headers.CONTENT_TYPE, MediaType.TEXT)
        exchange.sendResponseHeaders(200, BYTES.size.toLong())
        exchange.responseBody.write(BYTES)
        exchange.responseBody.close()
      }
      executor = null
    }.start()
  }

  fun server2() {
    System.setProperty("javax.net.debug", "ssl:data")
    HttpServer().
      requestHandler(RequestHandlerChain().
        add(object: Handler {
          override fun setup() = this
          override fun handle(request: Request, params: Array<out String>): Response.Builder {
            return Response.Builder().
              statusLine(StatusLines.OK).
              body("Test")
          }
          override fun matches(method: String, url: HttpUrl) =
            if ("get".equals(method.toLowerCase()) && url.encodedPath() == "/test") emptyArray<String>()
            else null
        }).
        add(object: Handler {
          override fun setup() = this
          override fun handle(request: Request, params: Array<out String>): Response.Builder {
            return Response.Builder().
              statusLine(StatusLines.OK).
              contentLength(BYTES.size.toLong()).
              body(okhttp3.MediaType.parse(MediaType.TEXT)!!, BYTES)
          }
          override fun matches(method: String, url: HttpUrl) =
            if ("get".equals(method.toLowerCase()) && url.encodedPath() == "/test2") emptyArray<String>()
            else null
        })
      ).
      ports(8080,8181).
      https(Https.Builder().certificate(Base64.getMimeDecoder().decode(cert), false).build()).
      start()
  }

  val BYTES = Base64.getMimeEncoder().encode(SecureRandom.getSeed(48000))

  @Test @Disabled
  fun testJDK() {
    server()

    System.setProperty("jdk.tls.client.cipherSuites","TLS_RSA_WITH_AES_128_CBC_SHA")
    SSLContext.setDefault(
      SSLContext.getInstance("TLS").apply {
        init(null, arrayOf(object: X509TrustManager {
          override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
          override fun getAcceptedIssuers(): Array<X509Certificate>? = null
        }), null)
        defaultSSLParameters.protocols = arrayOf("TLSv1.2")
        //defaultSSLParameters.cipherSuites = arrayOf("TLS_RSA_WITH_AES_128_CBC_SHA")
      }
    )
    (java.net.URL("https://localhost:8181").openConnection() as HttpsURLConnection).apply {
      hostnameVerifier = object: HostnameVerifier {
        override fun verify(hostname: String?, session: SSLSession?) = true
      }
    }.connect()
  }

  @Test
  fun testHeaders() {
    runBlocking {
      val response = Get.url("https://google.com").send(false)
      Assertions.assertEquals(301, response.status)
      Assertions.assertEquals("https://www.google.com/", response.headers.value(Headers.LOCATION))
      Assertions.assertEquals("close", response.headers.value(Headers.CONNECTION))
    }
  }

  @Test
  fun testRedirect() {
    runBlocking {
      val response = Get.url("https://www.google.com/").send()
      Assertions.assertEquals(200, response.status)
      Assertions.assertEquals("close", response.headers.value(Headers.CONNECTION))
    }
  }

  @Test
  fun testContent() {
    runBlocking {
      val data = SecureRandom.getSeed(9000)
      val response = Post.url("https://httpbin.org/anything").body(data, MediaType.OCTET_STREAM).send()
      Assertions.assertEquals(200, response.status)
      Assertions.assertEquals(MediaType.JSON, response.headers.value(Headers.CONTENT_TYPE))
      Assertions.assertEquals("close", response.headers.value(Headers.CONNECTION))
      val n = response.headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: throw RuntimeException()
      val bytes = ByteArray(n)
      response.body.get(bytes)
      Assertions.assertEquals(0, response.body.remaining())
      @Suppress("UNCHECKED_CAST")
      val map = ObjectMapper().readValue(bytes, Map::class.java) as Map<String, *>
      Assertions.assertEquals(
        "data:application/octet-stream;base64,${Base64.getEncoder().encodeToString(data)}", map["data"]
      )
    }
  }

  @Test
  fun testLargeContent() {
    runBlocking {
      val data = SecureRandom.getSeed(11728)  // 11727 works fine
      val response = Post.url("https://httpbin.org/anything").body(data, MediaType.OCTET_STREAM).send()
      Assertions.assertEquals(200, response.status)
      Assertions.assertEquals(MediaType.JSON, response.headers.value(Headers.CONTENT_TYPE))
      val n = response.headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: throw RuntimeException()
      val bytes = ByteArray(n)
      response.body.get(bytes)
      Assertions.assertEquals(0, response.body.remaining())
      @Suppress("UNCHECKED_CAST")
      val map = ObjectMapper().readValue(bytes, Map::class.java) as Map<String, *>
      Assertions.assertEquals(
        "data:application/octet-stream;base64,${Base64.getEncoder().encodeToString(data)}", map["data"]
      )
    }
  }

  @Test
  fun testS() {
    server2()
    runBlocking {
      val response = Get.url("https://localhost:8181/test").send()
      Assertions.assertEquals(200, response.status)
      Assertions.assertEquals(MediaType.TEXT, response.headers.value(Headers.CONTENT_TYPE))
      val n = response.headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: throw RuntimeException()
      Assertions.assertEquals(4, n)
      Assertions.assertEquals("Test", String(ByteArray(n).apply { response.body.get(this) }))
    }
  }

  @Test
  fun testL() {
    server2()
    runBlocking {
      val response = Get.url("https://localhost:8181/test2").send()
      Assertions.assertEquals(200, response.status)
      Assertions.assertEquals(MediaType.TEXT, response.headers.value(Headers.CONTENT_TYPE))
      val n = response.headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: throw RuntimeException()
      Assertions.assertEquals(BYTES.size, n)
    }
  }

  @Test
  fun test() {
    //server()
    runBlocking {
//      val response = Post.url("https://httpbin.org/post").body("abc").send()
      val response = Get.url("https://www.google.com/").send(false)
//      val response = Get.url("https://localhost:8181/test2").send()
      Assertions.assertEquals(200, response.status)
      Assertions.assertEquals(MediaType.HTML, response.headers.value(Headers.CONTENT_TYPE)?.replace(Regex(";.*$"), ""))
      Assertions.assertEquals("close", response.headers.value(Headers.CONNECTION))
      Assertions.assertTrue(response.headers.has(Headers.SERVER))
      Assertions.assertTrue(response.headers.has(Headers.DATE))
      Assertions.assertTrue(response.headers.has(Headers.CONTENT_LENGTH))
      val n = response.headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: throw RuntimeException()
      val bytes = ByteArray(n)
      response.body.get(bytes)
      Assertions.assertEquals(0, response.body.remaining())
      @Suppress("UNCHECKED_CAST")
      val map = ObjectMapper().readValue(bytes, Map::class.java) as Map<String, *>
      Assertions.assertEquals("abc", map["data"])
    }
  }

}
