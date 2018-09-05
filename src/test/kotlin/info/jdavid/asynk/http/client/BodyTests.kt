package info.jdavid.asynk.http.client

import com.fasterxml.jackson.databind.ObjectMapper
import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.MediaType
import kotlinx.coroutines.experimental.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class BodyTests {

  @Test
  fun testRequestStringBody() {
    runBlocking {
      val response = Post.url("http://httpbin.org/post").setBody("abc").send()
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
      assertEquals("abc", map["data"])
    }
  }

  @Test
  fun testRequestJsonBody() {
    val json = mapOf("a" to "b", "c" to true)
    val data = ObjectMapper().writeValueAsBytes(json)
    runBlocking {
      val response = Post.url("http://httpbin.org/post").setBody(data, MediaType.JSON).send()
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
      assertEquals(ObjectMapper().writeValueAsString(json), map["data"])
      assertEquals(ObjectMapper().writeValueAsString(json), ObjectMapper().writeValueAsString(map["json"]))
    }
  }

}
