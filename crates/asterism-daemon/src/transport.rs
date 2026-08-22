//! The daemon's side of the door: framing, deadlines, and how many peers may
//! be inside at once.
//!
//! The policy — who may connect, where the socket lives, what makes this
//! process the only daemon on its home — is
//! [`asterism_core::ipc`], deliberately, so that `ast` and `astd` cannot
//! drift on it. What is here is the part that needs a runtime: reading a
//! bounded line without letting the peer choose how much memory that takes,
//! writing a reply without letting the peer choose how long that takes, and
//! holding the number of open connections under a cap.
//!
//! # Why this is a seam and not a check in `serve`
//!
//! Every one of these limits is a property of *the connection*, not of the
//! command on it. A daemon that bounded frames in `serve` but not in the
//! pairing conversation, or that deadlined writes for replies but not for
//! progress lines, would have the limit and the hole at the same time — and
//! the hole would be in whichever path was added last. So a connection is
//! only reachable as an [`Admitted`], and an `Admitted` only hands out a
//! [`Frames`] and a [`Writer`]. There is no way to get at the raw halves,
//! which means there is no way for a new command to accidentally opt out.

use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, timeout_at, Instant};

use asterism_core::ipc;
use asterism_core::protocol::Response;

/// The bound socket, the election that proves it is ours, and the slots.
pub(crate) struct Door {
    listener: UnixListener,
    slots: Arc<Semaphore>,
    sock: std::path::PathBuf,
    /// The `flock(2)` that makes this the only daemon on this home. Never
    /// read; it is released when this process dies, whichever way it dies.
    _lock: std::fs::File,
}

impl Door {
    /// Win the election, bind, and be ready to accept.
    pub(crate) fn open(home: &std::path::Path, sock: &std::path::Path) -> Result<Door> {
        let (listener, lock, sock) = ipc::Door::open(home, sock)?.into_parts();
        listener
            .set_nonblocking(true)
            .context("putting the astd socket in non-blocking mode")?;
        let listener = UnixListener::from_std(listener)
            .with_context(|| format!("serving {}", sock.display()))?;
        Ok(Door {
            listener,
            slots: Arc::new(Semaphore::new(ipc::MAX_CONNECTIONS)),
            sock,
            _lock: lock,
        })
    }

    /// The next connection, unexamined.
    ///
    /// Accepting is deliberately not where a peer is checked or a slot is
    /// taken: both of those can wait, and an accept loop that waits stops
    /// draining the kernel's backlog — which is a way for one slow peer to
    /// keep every other one out. The examination is [`admit`], on the task
    /// that will serve the connection.
    pub(crate) async fn accept(&self) -> io::Result<UnixStream> {
        self.listener.accept().await.map(|(stream, _)| stream)
    }

    pub(crate) fn slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.slots)
    }

    pub(crate) fn socket(&self) -> &std::path::Path {
        &self.sock
    }
}

/// A connection that has proved who it belongs to and been given a slot.
pub(crate) struct Admitted {
    pub(crate) frames: Frames,
    pub(crate) write: Writer,
    /// Given back when this drops, which is what makes the cap a cap.
    _slot: OwnedSemaphorePermit,
}

/// Decide whether to serve a connection, and tell it if not.
///
/// Two questions, in this order. Whose it is comes first because it is free
/// and because a stranger must not be able to hold a slot, even for the
/// [`ipc::ACCEPT_WAIT`] it would take to be turned away. Then the slot,
/// which an honest burst waits briefly for and never notices.
///
/// A refusal is written to the peer before the connection is dropped: this
/// is the one place a user can be told *why* `ast` got nothing, and a socket
/// closed in silence is the failure mode that produces bug reports rather
/// than fixes.
pub(crate) async fn admit(stream: UnixStream, slots: Arc<Semaphore>) -> Result<Option<Admitted>> {
    let peer = ipc::same_user(stream.as_raw_fd());
    let (read, write) = stream.into_split();
    let mut write = Writer { inner: write };

    if let Err(e) = peer {
        let refusal = format!("{e:#}");
        write.refuse(&refusal).await;
        return Err(anyhow::anyhow!(refusal));
    }

    let slot = match timeout(ipc::ACCEPT_WAIT, Arc::clone(&slots).acquire_owned()).await {
        Ok(Ok(slot)) => slot,
        // The semaphore is never closed, so this is unreachable; treating it
        // as a refusal rather than an unwrap keeps it that way.
        Ok(Err(_)) => {
            write.refuse("astd is shutting down").await;
            return Ok(None);
        }
        Err(_) => {
            write
                .refuse(&format!(
                    "astd is already serving its limit of {} connections and none came \
                     free in {}s. Something is holding connections open — `ast ls` will \
                     say what this device is running.",
                    ipc::MAX_CONNECTIONS,
                    ipc::ACCEPT_WAIT.as_secs()
                ))
                .await;
            return Ok(None);
        }
    };

    Ok(Some(Admitted { frames: Frames::new(read), write, _slot: slot }))
}

// ---- reading -----------------------------------------------------------------

/// What came off the socket.
pub(crate) enum Framing {
    /// One complete line, newline stripped.
    Frame(String),
    /// The peer closed cleanly.
    Eof,
    /// The peer is not speaking this protocol. The string is what to tell it
    /// before the connection is dropped — bounded, and about what to do.
    Refused(String),
}

/// One JSON request per line, and no line longer than
/// [`ipc::MAX_REQUEST_FRAME`].
///
/// `tokio`'s own `read_line` is not this: it grows its buffer until it finds
/// a newline, so a peer that never sends one chooses how much memory the
/// daemon allocates. This reads through the buffered chunks and refuses as
/// soon as the *limit* is passed, which is before the bytes are kept.
pub(crate) struct Frames {
    reader: BufReader<OwnedReadHalf>,
    buf: Vec<u8>,
}

impl Frames {
    fn new(read: OwnedReadHalf) -> Frames {
        Frames { reader: BufReader::new(read), buf: Vec::new() }
    }

    /// The next request line.
    ///
    /// Waiting for a frame to *begin* is untimed, on purpose: `ast ssh` holds
    /// its connection open and says nothing for the whole life of the ssh it
    /// started, and an idle timeout would cut a working session. What is
    /// deadlined is the rest of a line once the first byte of it has arrived
    /// — which is the peer that dribbles a megabyte a byte at a time, and the
    /// only shape of slowness that costs the daemon anything.
    pub(crate) async fn next(&mut self) -> io::Result<Framing> {
        self.buf.clear();
        let mut deadline: Option<Instant> = None;
        loop {
            let chunk = match deadline {
                None => self.reader.fill_buf().await?,
                Some(at) => match timeout_at(at, self.reader.fill_buf()).await {
                    Ok(chunk) => chunk?,
                    Err(_) => return Ok(Framing::Refused(slow())),
                },
            };
            if chunk.is_empty() {
                return Ok(if self.buf.is_empty() {
                    Framing::Eof
                } else {
                    Framing::Refused(
                        "the connection ended in the middle of a request".to_owned(),
                    )
                });
            }
            // What this frame would be if it ended in this chunk: everything
            // kept so far, plus the part of this chunk before its newline.
            // The cap is checked against that on *both* paths below, and the
            // newline path is the one that used to skip it — a peer could
            // fill the buffer to exactly the limit, then send the last byte
            // and the terminator together, and the frame was accepted one
            // byte over. Anything that decides the length of a frame has to
            // be counted before the frame is handed on.
            let ends_here = chunk.iter().position(|b| *b == b'\n');
            let would_be = self.buf.len() + ends_here.unwrap_or(chunk.len());
            if would_be > ipc::MAX_REQUEST_FRAME {
                return Ok(Framing::Refused(oversize()));
            }
            if let Some(at) = ends_here {
                self.buf.extend_from_slice(&chunk[..at]);
                self.reader.consume(at + 1);
                return Ok(match String::from_utf8(std::mem::take(&mut self.buf)) {
                    Ok(line) => Framing::Frame(line),
                    Err(_) => Framing::Refused(
                        "a request frame was not utf-8; astd reads JSON".to_owned(),
                    ),
                });
            }
            let taken = chunk.len();
            self.buf.extend_from_slice(chunk);
            self.reader.consume(taken);
            // The clock starts at the first byte of a frame and covers the
            // whole of it, so a peer cannot restart it by sending one more
            // byte.
            deadline.get_or_insert_with(|| Instant::now() + ipc::FRAME_DEADLINE);
        }
    }
}

fn oversize() -> String {
    format!(
        "a request went past {} bytes before its newline. astd reads one JSON request \
         per line; nothing this protocol carries is that large.",
        ipc::MAX_REQUEST_FRAME
    )
}

fn slow() -> String {
    format!(
        "a request was still arriving {}s after it started. astd reads one JSON \
         request per line and will not hold a connection open for a partial one.",
        ipc::FRAME_DEADLINE.as_secs()
    )
}

// ---- writing -----------------------------------------------------------------

/// The reply half, with a deadline on it.
pub(crate) struct Writer {
    inner: OwnedWriteHalf,
}

impl Writer {
    /// One response line.
    ///
    /// Deadlined because a peer that asks and then never reads is otherwise
    /// free: the socket buffer fills, `write_all` waits forever, and the
    /// connection slot is held by a process that has stopped participating.
    /// Open the connection limit that way and the daemon is unreachable at
    /// the cost of a shell loop.
    pub(crate) async fn send(&mut self, response: &Response) -> Result<()> {
        let mut out = serde_json::to_vec(response)?;
        out.push(b'\n');
        match timeout(ipc::WRITE_DEADLINE, self.inner.write_all(&out)).await {
            Ok(written) => written.context("writing a reply")?,
            Err(_) => anyhow::bail!(
                "a peer stopped reading its replies for {}s; dropping the connection",
                ipc::WRITE_DEADLINE.as_secs()
            ),
        }
        Ok(())
    }

    /// Say why, on the way out. A peer already being turned away cannot be
    /// told twice, so a failure here is nothing to report.
    pub(crate) async fn refuse(&mut self, message: &str) {
        let _ = self.send(&Response::Error { message: message.to_owned() }).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A connected pair, one end wrapped as the daemon would wrap it.
    async fn pair() -> (UnixStream, Frames) {
        let (theirs, ours) = UnixStream::pair().expect("a socket pair");
        let (read, _write) = ours.into_split();
        (theirs, Frames::new(read))
    }

    /// The ordinary case, and the one that has to keep working: two frames
    /// on one connection, each ending where its newline is.
    #[tokio::test]
    async fn a_line_is_a_frame() {
        let (mut theirs, mut frames) = pair().await;
        theirs.write_all(b"{\"cmd\":\"ping\"}\n{\"cmd\":\"list\"}\n").await.unwrap();
        for want in ["{\"cmd\":\"ping\"}", "{\"cmd\":\"list\"}"] {
            match frames.next().await.unwrap() {
                Framing::Frame(line) => assert_eq!(line, want),
                _ => panic!("expected a frame"),
            }
        }
        drop(theirs);
        assert!(matches!(frames.next().await.unwrap(), Framing::Eof));
    }

    /// The reason this type exists: a peer that never sends a newline must
    /// not get to choose how much memory the daemon holds. The refusal has
    /// to arrive at the limit, not at whatever the peer runs out of.
    #[tokio::test]
    async fn a_frame_over_the_limit_is_refused_and_not_buffered() {
        let (mut theirs, mut frames) = pair().await;
        let writer = tokio::spawn(async move {
            let chunk = vec![b'a'; 64 * 1024];
            // Comfortably past the cap, and never a newline. The write ends
            // when the daemon drops its end, which is the behaviour under
            // test.
            for _ in 0..(ipc::MAX_REQUEST_FRAME / chunk.len() + 8) {
                if theirs.write_all(&chunk).await.is_err() {
                    return;
                }
            }
        });
        match frames.next().await.unwrap() {
            Framing::Refused(message) => {
                assert!(message.contains("before its newline"), "{message}");
                assert!(
                    message.contains(&ipc::MAX_REQUEST_FRAME.to_string()),
                    "the refusal says what the limit is: {message}"
                );
            }
            _ => panic!("a frame over the limit was accepted"),
        }
        assert!(
            frames.buf.len() <= ipc::MAX_REQUEST_FRAME,
            "refused after buffering {} bytes",
            frames.buf.len()
        );
        drop(frames);
        writer.await.unwrap();
    }

    /// Exactly the limit is a frame. The cap is on what a peer may make the
    /// daemon hold, so the boundary belongs on the accepting side of it —
    /// and a reader that refused at exactly the limit would refuse a frame
    /// the mesh, which shares this ceiling, is willing to send.
    #[tokio::test]
    async fn a_frame_of_exactly_the_limit_is_a_frame() {
        let (mut theirs, mut frames) = pair().await;
        let writer = tokio::spawn(async move {
            theirs.write_all(&vec![b'a'; ipc::MAX_REQUEST_FRAME]).await.unwrap();
            theirs.write_all(b"\n").await.unwrap();
            theirs
        });
        match frames.next().await.unwrap() {
            Framing::Frame(line) => assert_eq!(line.len(), ipc::MAX_REQUEST_FRAME),
            _ => panic!("a frame of exactly the limit was refused"),
        }
        drop(writer.await.unwrap());
    }

    /// The bypass the merge queue caught, in the shape it caught it in.
    ///
    /// The cap used to be checked only on the path where a chunk carried no
    /// newline. So a peer filled the buffer to exactly the limit — allowed,
    /// see above — waited for it to be consumed, and then sent the byte that
    /// went over *together with* the terminator. That put the last byte on
    /// the newline path, which counted nothing, and a limit+1 frame went
    /// through to the JSON parser. The limit has to be decided by every byte
    /// that is in the frame, not by every byte that arrives without one.
    #[tokio::test]
    async fn a_frame_that_goes_over_in_the_chunk_carrying_its_newline_is_refused() {
        let (mut theirs, mut frames) = pair().await;
        let writer = tokio::spawn(async move {
            // Exactly the limit, and no terminator. `write_all` returns once
            // the reader has taken it, which is the "waited for consumption"
            // half of the repro: the buffer now holds exactly the limit and
            // the next chunk is the one with the newline in it.
            theirs.write_all(&vec![b'a'; ipc::MAX_REQUEST_FRAME]).await.unwrap();
            theirs.write_all(b"x\n").await.unwrap();
            theirs
        });
        match frames.next().await.unwrap() {
            Framing::Refused(message) => {
                assert!(message.contains("before its newline"), "{message}");
                assert!(message.contains(&ipc::MAX_REQUEST_FRAME.to_string()), "{message}");
            }
            Framing::Frame(line) => panic!(
                "a {}-byte frame was accepted; the limit is {}",
                line.len(),
                ipc::MAX_REQUEST_FRAME
            ),
            Framing::Eof => panic!("the peer was cut off instead of refused"),
        }
        drop(writer.await.unwrap());
    }

    /// A frame that has begun has a deadline; one that has not begun does
    /// not. Both halves matter — the second is `ast ssh`, which holds a
    /// silent connection open for as long as its ssh session runs.
    #[tokio::test(start_paused = true)]
    async fn a_frame_that_dribbles_runs_out_of_time_but_a_silent_peer_does_not() {
        let (mut theirs, mut frames) = pair().await;
        theirs.write_all(b"{\"cmd\":").await.unwrap();
        match frames.next().await.unwrap() {
            Framing::Refused(message) => assert!(message.contains("still arriving"), "{message}"),
            _ => panic!("a half-sent frame was not deadlined"),
        }

        let (theirs, mut frames) = pair().await;
        let silent = tokio::time::timeout(ipc::FRAME_DEADLINE * 4, frames.next()).await;
        assert!(silent.is_err(), "a connection that has said nothing was cut");
        drop(theirs);
    }

    /// A peer that asks and then stops reading gets a bounded amount of the
    /// daemon's attention. Without this, the connection cap is the attack
    /// rather than the defence.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_reads_does_not_hold_the_connection() {
        let (theirs, ours) = UnixStream::pair().unwrap();
        let (_read, write) = ours.into_split();
        let mut writer = Writer { inner: write };
        // Fill the socket buffer with a reply nobody is reading. The size is
        // beside the point; what is under test is that it ends.
        let fat = Response::Log { text: "x".repeat(4 << 20), truncated: false };
        let sent: Result<()> = tokio::time::timeout(ipc::WRITE_DEADLINE * 4, async {
            loop {
                writer.send(&fat).await?;
            }
        })
        .await
        .expect("the write gave up on its own rather than being timed out here");
        let message = format!("{:#}", sent.expect_err("a peer that reads nothing must fail"));
        assert!(message.contains("stopped reading"), "{message}");
        drop(theirs);
    }

    /// The cap is on connections held, not on connections seen: a slot comes
    /// back when its connection drops, and a burst past the cap is turned
    /// away with something to read rather than in silence.
    #[tokio::test(start_paused = true)]
    async fn the_connection_cap_refuses_in_words_and_gives_slots_back() {
        let slots = Arc::new(Semaphore::new(1));
        let (client, server) = UnixStream::pair().unwrap();
        let held = admit(server, Arc::clone(&slots)).await.unwrap().expect("the first is served");

        let (mut turned_away, server) = UnixStream::pair().unwrap();
        let refused = admit(server, Arc::clone(&slots));
        let refused = tokio::time::timeout(ipc::ACCEPT_WAIT * 2, refused)
            .await
            .expect("the wait for a slot is bounded")
            .unwrap();
        assert!(refused.is_none(), "a connection past the cap was served");

        let mut said = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut turned_away, &mut said).await.unwrap();
        assert!(said.contains("limit"), "the refusal says what happened: {said}");

        drop(held);
        drop(client);
        let (_client, server) = UnixStream::pair().unwrap();
        let after = tokio::time::timeout(Duration::from_secs(1), admit(server, slots))
            .await
            .expect("the freed slot was available at once")
            .unwrap();
        assert!(after.is_some(), "the slot did not come back");
    }
}
