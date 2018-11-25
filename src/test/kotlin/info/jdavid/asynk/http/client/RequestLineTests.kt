package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method
import info.jdavid.asynk.http.Status
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

class RequestLineTests {

  companion object {
    private val emptyBuffer = ByteBuffer.allocate(0)
  }

  class TestResponse(
    val host: String, val port: Int, val pathWithQueryAndFragment: String, val secure: Boolean
  ): Request.Response(Status.OK, Headers(), emptyBuffer)

  object TestSecureRequester: Request.Requester {
    override suspend fun <T: Body> request(method: Method, host: String, port: Int,
                                           pathWithQueryAndFragment: String, headers: Headers,
                                           body: T?, timeoutMillis: Long, buffer: ByteBuffer) =
      TestResponse(host, port, pathWithQueryAndFragment, true)
  }

  object TestInsecureRequester: Request.Requester {
    override suspend fun <T: Body> request(method: Method, host: String, port: Int,
                                           pathWithQueryAndFragment: String, headers: Headers,
                                           body: T?, timeoutMillis: Long, buffer: ByteBuffer) =
      TestResponse(host, port, pathWithQueryAndFragment, false)
  }

  suspend fun request(url: String) = Request.request(
    Method.GET, url, Headers(), null, 30000L, emptyBuffer, TestInsecureRequester, TestSecureRequester
  ) as TestResponse

  @Test
  fun testHostAndPathWithDefaultPort() {
    runBlocking {
      request("http://example.com").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(80, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("https://example.com").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(443, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("http://a.example.com/").apply {
        assertFalse(secure)
        assertEquals("a.example.com", host)
        assertEquals(80, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("https://a.example.com/").apply {
        assertTrue(secure)
        assertEquals("a.example.com", host)
        assertEquals(443, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("http://a.example.com?a").apply {
        assertFalse(secure)
        assertEquals("a.example.com", host)
        assertEquals(80, port)
        assertEquals("/?a", pathWithQueryAndFragment)
      }
      request("https://a.example.com?a").apply {
        assertTrue(secure)
        assertEquals("a.example.com", host)
        assertEquals(443, port)
        assertEquals("/?a", pathWithQueryAndFragment)
      }
      request("http://a.b.example.com#c").apply {
        assertFalse(secure)
        assertEquals("a.b.example.com", host)
        assertEquals(80, port)
        assertEquals("/#c", pathWithQueryAndFragment)
      }
      request("https://a.b.example.com#c").apply {
        assertTrue(secure)
        assertEquals("a.b.example.com", host)
        assertEquals(443, port)
        assertEquals("/#c", pathWithQueryAndFragment)
      }
      request("http://example.com?a#b").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(80, port)
        assertEquals("/?a#b", pathWithQueryAndFragment)
      }
      request("https://example.com?a#b").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(443, port)
        assertEquals("/?a#b", pathWithQueryAndFragment)
      }
      request("http://abc.example.com/d/e").apply {
        assertFalse(secure)
        assertEquals("abc.example.com", host)
        assertEquals(80, port)
        assertEquals("/d/e", pathWithQueryAndFragment)
      }
      request("https://abc.example.com/d/e").apply {
        assertTrue(secure)
        assertEquals("abc.example.com", host)
        assertEquals(443, port)
        assertEquals("/d/e", pathWithQueryAndFragment)
      }
      request("http://example.com/a/b?c").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(80, port)
        assertEquals("/a/b?c", pathWithQueryAndFragment)
      }
      request("https://example.com/a/b?c").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(443, port)
        assertEquals("/a/b?c", pathWithQueryAndFragment)
      }
      request("http://example.com/a/b#c").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(80, port)
        assertEquals("/a/b#c", pathWithQueryAndFragment)
      }
      request("https://example.com/a/b#c").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(443, port)
        assertEquals("/a/b#c", pathWithQueryAndFragment)
      }
      request("http://example.com/a/b?c#d").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(80, port)
        assertEquals("/a/b?c#d", pathWithQueryAndFragment)
      }
      request("https://example.com/a/b?c#d").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(443, port)
        assertEquals("/a/b?c#d", pathWithQueryAndFragment)
      }
    }

  }

  @Test
  fun testHostAndPathWithCustomPort() {
    runBlocking {
      request("http://example.com:8080").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(8080, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("https://example.com:8081").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(8081, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("http://a.example.com:8080/").apply {
        assertFalse(secure)
        assertEquals("a.example.com", host)
        assertEquals(8080, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("https://a.example.com:8081/").apply {
        assertTrue(secure)
        assertEquals("a.example.com", host)
        assertEquals(8081, port)
        assertEquals("/", pathWithQueryAndFragment)
      }
      request("http://a.example.com:8080?a").apply {
        assertFalse(secure)
        assertEquals("a.example.com", host)
        assertEquals(8080, port)
        assertEquals("/?a", pathWithQueryAndFragment)
      }
      request("https://a.example.com:8081?a").apply {
        assertTrue(secure)
        assertEquals("a.example.com", host)
        assertEquals(8081, port)
        assertEquals("/?a", pathWithQueryAndFragment)
      }
      request("http://a.b.example.com:8080#c").apply {
        assertFalse(secure)
        assertEquals("a.b.example.com", host)
        assertEquals(8080, port)
        assertEquals("/#c", pathWithQueryAndFragment)
      }
      request("https://a.b.example.com:8081#c").apply {
        assertTrue(secure)
        assertEquals("a.b.example.com", host)
        assertEquals(8081, port)
        assertEquals("/#c", pathWithQueryAndFragment)
      }
      request("http://example.com:8080?a#b").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(8080, port)
        assertEquals("/?a#b", pathWithQueryAndFragment)
      }
      request("https://example.com:8081?a#b").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(8081, port)
        assertEquals("/?a#b", pathWithQueryAndFragment)
      }
      request("http://abc.example.com:8080/d/e").apply {
        assertFalse(secure)
        assertEquals("abc.example.com", host)
        assertEquals(8080, port)
        assertEquals("/d/e", pathWithQueryAndFragment)
      }
      request("https://abc.example.com:8081/d/e").apply {
        assertTrue(secure)
        assertEquals("abc.example.com", host)
        assertEquals(8081, port)
        assertEquals("/d/e", pathWithQueryAndFragment)
      }
      request("http://example.com:8080/a/b?c").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(8080, port)
        assertEquals("/a/b?c", pathWithQueryAndFragment)
      }
      request("https://example.com:8081/a/b?c").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(8081, port)
        assertEquals("/a/b?c", pathWithQueryAndFragment)
      }
      request("http://example.com:8080/a/b#c").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(8080, port)
        assertEquals("/a/b#c", pathWithQueryAndFragment)
      }
      request("https://example.com:8081/a/b#c").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(8081, port)
        assertEquals("/a/b#c", pathWithQueryAndFragment)
      }
      request("http://example.com:8080/a/b?c#d").apply {
        assertFalse(secure)
        assertEquals("example.com", host)
        assertEquals(8080, port)
        assertEquals("/a/b?c#d", pathWithQueryAndFragment)
      }
      request("https://example.com:8081/a/b?c#d").apply {
        assertTrue(secure)
        assertEquals("example.com", host)
        assertEquals(8081, port)
        assertEquals("/a/b?c#d", pathWithQueryAndFragment)
      }
    }

  }

  @Test
  fun test() {
    runBlocking {
      val response = Get.url("http://www.w3.org/Protocols/rfc2616/rfc2616-sec20.html").send()
      println(response.status)
      response.headers.lines.forEach { println(it) }
      println(response.body.remaining())
      val bytes = ByteArray(response.body.remaining())
      response.body.get(bytes)
      println(String(bytes))
    }
  }

}
