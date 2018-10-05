package info.jdavid.asynk.http.client

import info.jdavid.asynk.core.asyncConnect
import info.jdavid.asynk.core.asyncRead
import info.jdavid.asynk.core.asyncWrite
import kotlinx.coroutines.withTimeout
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

internal object InsecureRequest: AbstractRequest<AsynchronousSocketChannel>() {

  override suspend fun open() = AsynchronousSocketChannel.open()

  override suspend fun connect(channel: AsynchronousSocketChannel, address: InetSocketAddress) =
    channel.asyncConnect(address)

  override suspend fun read(channel: AsynchronousSocketChannel, timeoutMillis: Long, buffer: ByteBuffer) =
    withTimeout(timeoutMillis) { channel.asyncRead(buffer) }

  override suspend fun write(channel: AsynchronousSocketChannel, timeoutMillis: Long, buffer: ByteBuffer) =
    withTimeout(timeoutMillis) { channel.asyncWrite(buffer) }

}
