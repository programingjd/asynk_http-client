package info.jdavid.asynk.http.client

import info.jdavid.asynk.http.Headers
import info.jdavid.asynk.http.Method
import info.jdavid.asynk.http.Status
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

internal object SecureRequest: AbstractRequest<AsynchronousSocketChannel>() {

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

  override suspend fun open() = TODO()

  override suspend fun connect(channel: AsynchronousSocketChannel, address: InetSocketAddress) = TODO()

  override suspend fun read(channel: AsynchronousSocketChannel,
                            timeoutMillis: Long, buffer: ByteBuffer) = TODO()

  override suspend fun write(channel: AsynchronousSocketChannel,
                             timeoutMillis: Long, buffer: ByteBuffer) = TODO()

}
