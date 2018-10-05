package info.jdavid.asynk.http.client

import com.fasterxml.jackson.databind.ObjectMapper
import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.MediaType
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class HeaderTests {

  @Test
  fun testRequestHeaders() {
    runBlocking {
      val response = Get.url("http://httpbin.org/headers").
        header("Test1", arrayOf("abc")).
        header("Test1", arrayOf("de")).
        header("Test2", arrayOf("fgh")).
        header("Test2", "ijk").
        header("Test3", "lmn").
        header("Test4", arrayOf("opq")).
        send()
      assertEquals(200, response.status)
      assertEquals(MediaType.JSON, response.headers.value(Headers.CONTENT_TYPE))
      assertEquals("close", response.headers.value(Headers.CONNECTION))
      assertTrue(response.headers.has(Headers.SERVER))
      assertTrue(response.headers.has(Headers.DATE))
      assertTrue(response.headers.has(Headers.CONTENT_LENGTH))
      val n = response.headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: throw RuntimeException()
      val bytes = ByteArray(n)
      response.body.get(bytes)
      assertEquals(0, response.body.remaining())
      @Suppress("UNCHECKED_CAST")
      val map = ObjectMapper().readValue(bytes, Map::class.java) as Map<String, *>
      assertEquals(1, map.size)
      val entry = map.entries.first()
      assertEquals("headers", entry.key)
      assertTrue(entry.value is Map<*,*>)
      @Suppress("UNCHECKED_CAST")
      val headers = entry.value as Map<String, String>
      assertEquals("*/*", headers[Headers.ACCEPT])
      assertEquals("close", headers[Headers.CONNECTION])
      assertEquals("httpbin.org", headers[Headers.HOST])
      assertEquals("asynk/0.0.0.12", headers[Headers.USER_AGENT])
      assertEquals("abc,de", headers["Test1"])
      assertEquals("ijk", headers["Test2"])
      assertEquals("lmn", headers["Test3"])
      assertEquals("opq", headers["Test4"])
    }
  }

  @Test
  fun testResponseHeaders() {
    runBlocking {
      val response = Get.url("http://httpbin.org/user-agent").send()
      assertEquals(200, response.status)
      assertEquals(MediaType.JSON, response.headers.value(Headers.CONTENT_TYPE))
      assertEquals("close", response.headers.value(Headers.CONNECTION))
      assertTrue(response.headers.has(Headers.SERVER))
      assertTrue(response.headers.has(Headers.DATE))
      assertTrue(response.headers.has(Headers.CONTENT_LENGTH))
      val n = response.headers.value(Headers.CONTENT_LENGTH)?.toInt() ?: throw RuntimeException()
      val bytes = ByteArray(n)
      response.body.get(bytes)
      assertEquals(0, response.body.remaining())
      @Suppress("UNCHECKED_CAST")
      val map = ObjectMapper().readValue(bytes, Map::class.java) as Map<String, *>
      assertEquals(1, map.size)
      val entry = map.entries.first()
      assertEquals("user-agent", entry.key)
      assertEquals("asynk/0.0.0.12", entry.value)
    }
  }

}
