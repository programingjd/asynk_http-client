package info.jdavid.asynk.http.client

import com.fasterxml.jackson.databind.ObjectMapper
import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.MediaType
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.X509TrustManager

class SecureTests {

  @Test @Disabled
  fun testJSK() {
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
    (java.net.URL("https://github.com").openConnection() as HttpsURLConnection).apply { hostnameVerifier = object: HostnameVerifier {
      override fun verify(hostname: String?, session: SSLSession?) = true
    } }.connect()
  }

  @Test
  fun test() {
    runBlocking {
//      val response = Post.url("https://httpbin.org/post").body("abc").send()
      val response = Get.url("https://google.com").send()
      Assertions.assertEquals(200, response.status)
      Assertions.assertEquals(MediaType.JSON, response.headers.value(Headers.CONTENT_TYPE))
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
