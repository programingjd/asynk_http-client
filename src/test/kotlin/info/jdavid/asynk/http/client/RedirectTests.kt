package info.jdavid.asynk.http.client

import kotlinx.coroutines.experimental.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.net.URLEncoder

class RedirectTests {

  @Test
  fun redirectAbsolute() {
    val redirect = "http://httpbin.org/get"
    runBlocking {
      val response = Get.
        url("http://httpbin.org/redirect-to?url=${URLEncoder.encode(redirect,"UTF-8")}").
        send()
      assertEquals(200, response.status)
    }
  }

}
