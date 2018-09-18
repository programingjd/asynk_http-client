package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method
import info.jdavid.asynk.http.Status
import java.nio.ByteBuffer

internal object SecureRequest: Request.Requester {

  override suspend fun <T: Body>request(method: Method, host: String, port: Int,
                                        pathWithQueryAndFragment: String,
                                        headers: Headers, body: T?,
                                        timeoutMillis: Long,
                                        buffer: ByteBuffer): Request.Response {
    println(host)
    println(port)
    println(method)
    println(pathWithQueryAndFragment)
    return Request.Response(Status.OK, Headers(), buffer)
  }

}
