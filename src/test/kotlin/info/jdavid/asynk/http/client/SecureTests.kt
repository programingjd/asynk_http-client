package info.jdavid.asynk.http.client

import com.fasterxml.jackson.databind.ObjectMapper
import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.MediaType
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class SecureTests {

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
