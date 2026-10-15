use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
use std::{
    io::{self, IoSlice, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::net::UnixStream,
    },
    time::Duration,
};
use uuid::Uuid;
use vpngate_auto_proxy::platform::{custody::receive, generation::WorkerGeneration};

#[test]
fn real_custody_rejects_non_tunnel_descriptors_and_closes_them() {
    use vpngate_auto_proxy::platform::custody::UtunCustody;
    let (owner, mut peer) = UnixStream::pair().unwrap();
    assert!(UtunCustody::verify(owner.into(), 1).is_err());
    assert_closed(&mut peer);
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(UtunCustody::verify(udp.into(), 1).is_err());
    let file = tempfile::tempfile().unwrap();
    assert!(UtunCustody::verify(file.into(), 1).is_err());
}

#[test]
fn real_custody_rejects_zero_index_before_publishing_scope() {
    let (owner, mut peer) = UnixStream::pair().unwrap();
    assert!(vpngate_auto_proxy::platform::custody::UtunCustody::verify(owner.into(), 0).is_err());
    assert_closed(&mut peer);
}

fn frame(id: Uuid, index: u32) -> Vec<u8> {
    [b"VAP1".as_slice(), id.as_bytes(), &index.to_be_bytes()].concat()
}
fn send(channel: &UnixStream, bytes: &[u8], fds: &[BorrowedFd<'_>]) {
    let mut storage = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
    let mut ancillary = SendAncillaryBuffer::new(&mut storage);
    if !fds.is_empty() {
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(fds)));
    }
    assert_eq!(
        sendmsg(
            channel,
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::empty()
        )
        .unwrap(),
        bytes.len()
    );
}
fn assert_closed(peer: &mut UnixStream) {
    peer.set_nonblocking(true).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0, "拒绝交接后仍泄漏描述符");
}

#[tokio::test]
async fn received_descriptor_pins_lifetime_until_generation_retirement() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (owner, mut peer) = UnixStream::pair().unwrap();
    let id = Uuid::new_v4();
    send(&sender, &frame(id, 1), &[owner.as_fd()]);
    drop(owner);
    let received = receive(&receiver, id, 1, Duration::from_secs(1)).unwrap();
    assert!(
        rustix::io::fcntl_getfd(&received)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    let generation = WorkerGeneration::with_custody(received);
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    generation.retire().await;
    peer.set_nonblocking(false).unwrap();
    assert_closed(&mut peer);
}

#[test]
fn fragmented_frame_preserves_following_command_and_restores_timeout() {
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (owner, _) = UnixStream::pair().unwrap();
    let id = Uuid::new_v4();
    let bytes = frame(id, 1);
    send(&sender, &bytes[..1], &[owner.as_fd()]);
    sender.write_all(&bytes[1..]).unwrap();
    sender.write_all(b"command\n").unwrap();
    receive(&receiver, id, 1, Duration::from_secs(1)).unwrap();
    assert_eq!(
        receiver.read_timeout().unwrap(),
        Some(Duration::from_secs(2))
    );
    let mut command = [0; 8];
    (&receiver).read_exact(&mut command).unwrap();
    assert_eq!(&command, b"command\n");
}

#[test]
fn rejects_wrong_authorization_index_and_version_without_leaking() {
    for case in 0..3 {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (owner, mut peer) = UnixStream::pair().unwrap();
        let id = Uuid::new_v4();
        let mut bytes = frame(id, 1);
        bytes[if case == 0 {
            4
        } else if case == 1 {
            23
        } else {
            0
        }] ^= 1;
        send(&sender, &bytes, &[owner.as_fd()]);
        drop(owner);
        assert!(receive(&receiver, id, 1, Duration::from_secs(1)).is_err());
        drop(receiver);
        assert_closed(&mut peer);
    }
}

#[test]
fn rejects_missing_and_excess_rights_without_leaking() {
    for count in [0, 2] {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let pairs: Vec<_> = (0..count).map(|_| UnixStream::pair().unwrap()).collect();
        let id = Uuid::new_v4();
        send(
            &sender,
            &frame(id, 1),
            &pairs.iter().map(|p| p.0.as_fd()).collect::<Vec<_>>(),
        );
        let mut peers: Vec<_> = pairs
            .into_iter()
            .map(|(owner, peer)| {
                drop(owner);
                peer
            })
            .collect();
        assert!(receive(&receiver, id, 1, Duration::from_secs(1)).is_err());
        drop(receiver);
        for peer in &mut peers {
            assert_closed(peer);
        }
    }
}

#[test]
fn incomplete_frame_times_out_and_releases_received_rights() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (owner, mut peer) = UnixStream::pair().unwrap();
    send(&sender, b"V", &[owner.as_fd()]);
    drop(owner);
    assert!(receive(&receiver, Uuid::new_v4(), 1, Duration::from_millis(50)).is_err());
    assert_eq!(receiver.read_timeout().unwrap(), None);
    assert_closed(&mut peer);
}

#[test]
fn premature_eof_releases_received_rights() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (owner, mut peer) = UnixStream::pair().unwrap();
    send(&sender, b"V", &[owner.as_fd()]);
    drop(owner);
    drop(sender);
    assert!(receive(&receiver, Uuid::new_v4(), 1, Duration::from_secs(1)).is_err());
    drop(receiver);
    assert_closed(&mut peer);
}
