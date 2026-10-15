//! 苹果系统的固定接口 IPv4 套接字；此模块不创建或管理隧道。
use std::{io, net::SocketAddrV4, num::NonZeroU32};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone, Copy, Debug)]
pub struct InterfaceScope(NonZeroU32);
impl InterfaceScope {
    pub fn new(index: u32) -> io::Result<Self> {
        NonZeroU32::new(index)
            .map(Self)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "固定接口索引不能为零"))
    }
    /// 绑定失败直接返回错误，不创建替代连接，也不解除绑定。
    pub async fn connect_tcp(self, address: SocketAddrV4) -> io::Result<TcpStream> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket2::SockRef::from(&socket).bind_device_by_index_v4(Some(self.0))?;
        socket.connect(address.into()).await
    }
    /// 必须在首次发送前绑定接口；域名解析调用方只发送显式 DNS 报文。
    pub fn bind_udp(self) -> io::Result<UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.bind_device_by_index_v4(Some(self.0))?;
        socket.bind(&SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }
    pub fn index(self) -> u32 {
        self.0.get()
    }
}
