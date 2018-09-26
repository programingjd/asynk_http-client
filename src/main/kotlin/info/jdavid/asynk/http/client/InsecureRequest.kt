package info.jdavid.asynk.http.client

import kotlinx.coroutines.experimental.nio.aConnect
import kotlinx.coroutines.experimental.nio.aRead
import kotlinx.coroutines.experimental.nio.aWrite
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

internal object InsecureRequest: AbstractRequest<AsynchronousSocketChannel>() {

  override suspend fun open() = AsynchronousSocketChannel.open()

  override suspend fun connect(channel: AsynchronousSocketChannel, address: InetSocketAddress) =
    channel.aConnect(address)

  override suspend fun read(channel: AsynchronousSocketChannel, timeoutMillis: Long, buffer: ByteBuffer) =
    channel.aRead(buffer, timeoutMillis)

  override suspend fun write(channel: AsynchronousSocketChannel, timeoutMillis: Long, buffer: ByteBuffer) =
    channel.aWrite(buffer, timeoutMillis)

}
