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

  @Test
  fun redirectRelative() {
    val redirect = "/get"
    runBlocking {
      val response = Get.
        url("http://httpbin.org/redirect-to?url=${URLEncoder.encode(redirect,"UTF-8")}").
        send()
      assertEquals(200, response.status)
    }
  }

  @Test
  fun multipleRedirectAbsolute() {
    runBlocking {
      val response = Get.
        url("http://httpbin.org/absolute-redirect/3").
        send()
      assertEquals(200, response.status)
    }
  }

  @Test
  fun multipleRedirectRelative() {
    runBlocking {
      val response = Get.
        url("http://httpbin.org/relative-redirect/3").
        send()
      assertEquals(200, response.status)
    }
  }


}
