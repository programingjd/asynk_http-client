package info.jdavid.asynk.http.client

import info.jdavid.asynk.core.asyncConnect
import info.jdavid.asynk.core.asyncRead
import info.jdavid.asynk.core.asyncWrite
import info.jdavid.asynk.core.closeSilently
import kotlinx.coroutines.withTimeout
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel

internal object InsecureRequest: AbstractRequest<AsynchronousSocketChannel, Unit>() {

  override suspend fun open() = AsynchronousSocketChannel.open()

  override suspend fun terminate(channel: AsynchronousSocketChannel, handshake: Unit,
                                 buffer: ByteBuffer) = channel.closeSilently()

  override suspend fun connect(channel: AsynchronousSocketChannel, address: InetSocketAddress) =
    channel.asyncConnect(address)

  override suspend fun handshake(host: String,
                                 channel: AsynchronousSocketChannel,
                                 timeoutMillis: Long, buffer: ByteBuffer) = Unit

  override suspend fun asyncRead(socket: AsynchronousSocketChannel, buffer: ByteBuffer) =
    socket.asyncRead(buffer)

  override suspend fun asyncWrite(socket: AsynchronousSocketChannel, buffer: ByteBuffer) =
    socket.asyncWrite(buffer)

  override suspend fun read(channel: AsynchronousSocketChannel, handshake: Unit,
                            timeoutMillis: Long, buffer: ByteBuffer) =
    withTimeout(timeoutMillis) { channel.asyncRead(buffer) }

  override suspend fun write(channel: AsynchronousSocketChannel, handshake: Unit,
                             timeoutMillis: Long, buffer: ByteBuffer) =
    withTimeout(timeoutMillis) { channel.asyncWrite(buffer) }

}
