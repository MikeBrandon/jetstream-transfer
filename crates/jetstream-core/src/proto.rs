//! Wire protocol: message types and framing.
//!
//! Control messages travel on a single bidirectional stream as length-prefixed
//! [postcard](https://docs.rs/postcard) frames. Bulk file data travels on
//! separate QUIC streams, so a slow or stalled file can never block the control
//! channel or the other files alongside it.
//!
//! Every length read is bounded before a single byte is allocated. A peer is
//! not trusted, and "attacker sends a 4 GiB length prefix" must cost us nothing.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::identity::DeviceId;

/// Incremented only for incompatible changes. Compatible additions go in
/// [`Capabilities`], which is designed to be extended without a version bump.
pub const PROTOCOL_VERSION: u16 = 1;

/// Ceiling for a single control frame.
///
/// Control messages are small; manifests are streamed separately rather than
/// stuffed into one frame precisely so this limit can stay tight.
pub const MAX_CONTROL_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
    /// A device participating through the built-in browser receiver.
    Web,
    Unknown,
}

impl Platform {
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "android") {
            Self::Android
        } else if cfg!(target_os = "ios") {
            Self::Ios
        } else {
            Self::Unknown
        }
    }
}

/// Optional features a peer supports.
///
/// Encoded as a run of booleans at the end of [`Hello`], and decoded one at a
/// time until the bytes run out — see [`Hello::decode`]. That makes adding a
/// capability compatible in both directions: an older peer stops reading before
/// the new flags, and a newer one reads an older peer's missing flags as
/// unsupported. Append only; never reorder or remove a field without bumping
/// [`PROTOCOL_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Peer can read chunk frames that may be zstd-compressed — the
    /// [`ChunkHeaderV2`] layout.
    pub zstd: bool,
    /// Peer understands bundled small-file chunks.
    pub bundling: bool,
    /// Peer keeps reading the control stream for the whole transfer and
    /// understands [`Control::Progress`] and [`Control::Stop`].
    ///
    /// Gated rather than assumed because postcard cannot skip an enum variant it
    /// does not know: an older build that receives either message fails to
    /// decode it and drops the transfer. So both are only ever sent to a peer
    /// that said it understands them.
    pub live_status: bool,
    /// Peer answers [`DataRequest::ChunkHashes`], so a receiver holding an older
    /// copy of a file can reuse the chunks that have not changed.
    pub chunk_hashes: bool,
}

impl Capabilities {
    /// Everything this build supports.
    pub const fn ours() -> Self {
        Self {
            zstd: true,
            bundling: false,
            live_status: true,
            chunk_hashes: true,
        }
    }
}

/// First message on the control stream, sent by both sides.
///
/// `device_id` is carried for convenience and logging only. The authoritative
/// identity is the one derived from the TLS certificate — a peer can claim any
/// id it likes here, and [`Session`](crate::transport::Session) rejects the
/// connection if the claim disagrees with the key it actually proved it holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    pub device_id: DeviceId,
    /// Human-readable name, e.g. `"Mike's Desktop"`. Untrusted display data:
    /// treat it as hostile text when rendering.
    pub name: String,
    pub platform: Platform,
    pub app_version: String,
    pub capabilities: Capabilities,
}

impl Hello {
    pub fn new(device_id: DeviceId, name: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            device_id,
            name: name.into(),
            platform: Platform::current(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: Capabilities::ours(),
        }
    }

    /// Decode a `Hello` from any build, older or newer.
    ///
    /// Field by field, then the capability flags one at a time for as long as
    /// there are bytes. An older peer sends fewer flags, which read as
    /// unsupported; a newer one sends more, which are left unread. Decoding the
    /// whole struct in one go failed outright on any difference in length.
    pub fn decode(body: &[u8]) -> Result<Self> {
        fn take<'a, T: Deserialize<'a>>(rest: &mut &'a [u8]) -> Result<T> {
            let (value, remainder) = postcard::take_from_bytes(rest)
                .map_err(|e| Error::Protocol(format!("malformed hello: {e}")))?;
            *rest = remainder;
            Ok(value)
        }

        let mut rest = body;
        let version = take(&mut rest)?;
        let device_id = take(&mut rest)?;
        let name = take(&mut rest)?;
        let platform = take(&mut rest)?;
        let app_version = take(&mut rest)?;

        let mut flags = [false; 4];
        for flag in &mut flags {
            if rest.is_empty() {
                break;
            }
            *flag = take(&mut rest)?;
        }
        let [zstd, bundling, live_status, chunk_hashes] = flags;

        Ok(Self {
            version,
            device_id,
            name,
            platform,
            app_version,
            capabilities: Capabilities {
                zstd,
                bundling,
                live_status,
                chunk_hashes,
            },
        })
    }
}

/// Why one side deliberately stopped a transfer that was under way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    /// Stopped to be continued later. Staged data is kept.
    Paused,
    /// Stopped and not coming back by itself. Staged data is still kept, so a
    /// later send of the same files continues rather than restarts.
    Cancelled,
}

/// What a sender proposes, and what the receiver shows the user before
/// deciding.
///
/// Deliberately small: it must be enough to make an accept/reject decision
/// without downloading a 50,000-entry manifest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offer {
    /// Manifest digest, which is also the transfer id. Re-offering an
    /// unchanged tree yields the same digest and so resumes in place.
    pub digest: [u8; 32],
    pub summary: crate::manifest::Summary,
    pub entry_count: u64,
}

/// Messages on the control stream after the handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Control {
    /// Keepalive probe. QUIC has its own, but an application-level round trip
    /// is what tells us the *peer process* is alive, not just its socket.
    Ping(u64),
    Pong(u64),
    /// Orderly shutdown, so the other side can distinguish "finished" from
    /// "the network died" — the difference between completing a transfer and
    /// scheduling it for resume.
    Goodbye { reason: String },

    /// Sender proposes a transfer.
    Offer(Offer),
    /// Receiver agrees; the manifest follows.
    Accept,
    /// Receiver declines. `reason` is peer-supplied text — sanitize before
    /// display.
    Reject { reason: String },
    /// One slice of the manifest. Sent in batches so a large tree never needs
    /// a frame larger than [`MAX_CONTROL_FRAME`].
    ManifestBatch {
        entries: Vec<crate::manifest::Entry>,
        more: bool,
    },
    /// Receiver has everything and has verified it. The sender can stop
    /// serving and report success.
    Complete,
    /// Receiver gave up. The staged data is kept for a later resume.
    Abort { reason: String },

    /// A file has arrived, been verified, and been put in place.
    ///
    /// Purely informational, and the reason it exists is worth stating: only the
    /// receiver can know a file is *finished*, because only it verifies the hash
    /// and renames the result. The sender serves byte ranges and has no idea
    /// which file just became whole, so without this message a sending device can
    /// show bytes moving but never "27 of 43 files" — which is the progress a
    /// person actually reads.
    ///
    /// Sent fire-and-forget on the control stream. A sender that ignores it, or
    /// an older build that does not know it, loses a progress counter and nothing
    /// else — so this needs no capability negotiation.
    EntryDone { entry: u32 },

    /// What the receiver already had before this attempt began.
    ///
    /// Sent once, right after the receiver works out its resume plan. The sender
    /// is stateless by design and so has no idea how much of a resumed transfer is
    /// already done — it can only count what *it* sends. Without this the sending
    /// device shows a resumed 138 GB transfer as "0%, 1.6 KB of 138.5 GB, 509,960
    /// hours left", which reads as starting over when in fact almost everything is
    /// already there. The transfer was correct; only the reporting was not.
    ///
    /// Informational like [`Control::EntryDone`], so an older peer simply keeps
    /// the old misleading numbers rather than failing.
    AlreadyHave { bytes: u64, files: u64 },

    /// The receiver's running totals, sent a few times a second.
    ///
    /// The sender cannot tell on its own how much has *arrived*: it only sees
    /// what it hands to QUIC, and QUIC buffers far ahead of the network. Counting
    /// that made a sending device race to 100% at disk speed and then sit there
    /// while the data was still on the wire. The receiver's figure is the one the
    /// user means. Only sent to a peer with [`Capabilities::live_status`].
    Progress { bytes: u64, files: u64 },

    /// This side stopped on purpose — the user paused or cancelled.
    ///
    /// Distinct from [`Control::Abort`], which means something went wrong. The
    /// difference decides what the other device shows and whether it retries:
    /// a pause is not a failure, and a cancel is not a decline. Only sent to a
    /// peer with [`Capabilities::live_status`].
    Stop { reason: StopReason },
}

/// A request the receiver writes on a fresh data stream.
///
/// Every transfer of bytes starts here: the receiver asks, the sender answers
/// on the same stream. Because the sender keeps no per-transfer state, a
/// reconnect needs no renegotiation — the receiver simply asks again for
/// whatever is still missing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataRequest {
    /// Send these chunks of this entry, in order.
    Chunks {
        entry: u32,
        range: crate::chunk::ChunkRange,
    },
    /// Send the BLAKE3 of this entry's complete contents, for the final
    /// post-reassembly check.
    FileHash { entry: u32 },
    /// Send the BLAKE3 of each chunk in the range, 32 bytes apiece, in order.
    ///
    /// For a receiver that already holds an older copy of the file: any chunk
    /// whose hash matches what it has locally can be copied from disk instead of
    /// crossing the network. Only sent to a peer with
    /// [`Capabilities::chunk_hashes`].
    ChunkHashes {
        entry: u32,
        range: crate::chunk::ChunkRange,
    },
}

/// Fixed header preceding each chunk payload on a data stream.
///
/// Hand-encoded rather than serialized: the payload that follows is up to a
/// mebibyte, and it should reach the socket without a detour through a
/// serializer's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub index: u32,
    pub len: u32,
    pub hash: [u8; 32],
}

impl ChunkHeader {
    pub const SIZE: usize = 4 + 4 + 32;

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..4].copy_from_slice(&self.index.to_le_bytes());
        out[4..8].copy_from_slice(&self.len.to_le_bytes());
        out[8..40].copy_from_slice(&self.hash);
        out
    }

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        Self {
            index: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
            len: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            hash: bytes[8..40].try_into().expect("32 bytes"),
        }
    }
}

/// Chunk header for peers that read compressed frames ([`Capabilities::zstd`]).
///
/// One field more than [`ChunkHeader`]: how many bytes follow on the wire.
/// Fewer than `len` means the payload is zstd-compressed; exactly `len` means it
/// is raw. A sender only compresses when the result is strictly smaller, so the
/// two can never be confused. The hash is always of the *uncompressed* chunk, so
/// verification is identical either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeaderV2 {
    pub index: u32,
    pub len: u32,
    pub wire_len: u32,
    pub hash: [u8; 32],
}

impl ChunkHeaderV2 {
    pub const SIZE: usize = 4 + 4 + 4 + 32;

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..4].copy_from_slice(&self.index.to_le_bytes());
        out[4..8].copy_from_slice(&self.len.to_le_bytes());
        out[8..12].copy_from_slice(&self.wire_len.to_le_bytes());
        out[12..44].copy_from_slice(&self.hash);
        out
    }

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        Self {
            index: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
            len: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            wire_len: u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
            hash: bytes[12..44].try_into().expect("32 bytes"),
        }
    }

    pub fn compressed(&self) -> bool {
        self.wire_len < self.len
    }
}

/// Longest name we will accept from a peer, in bytes.
///
/// Bounded so a peer cannot push a megabyte of text into a device list.
pub const MAX_NAME_BYTES: usize = 128;

/// Trim an untrusted display name to something safe to store and render.
///
/// Strips control characters (including the bidirectional-override codepoints
/// that let a name render as something other than what it is) and clamps the
/// length. Returns a placeholder rather than an empty string so the UI always
/// has something to show.
pub fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_override(*c))
        .take(MAX_NAME_BYTES / 4) // worst-case 4 bytes per char
        .collect();

    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "Unnamed device".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Unicode bidi control codepoints, which can make `report.txt` render as
/// `report.exe` and vice versa.
fn is_bidi_override(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
}

/// Write a length-prefixed postcard frame.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = postcard::to_stdvec(message)
        .map_err(|e| Error::Protocol(format!("could not encode message: {e}")))?;

    if body.len() > MAX_CONTROL_FRAME {
        return Err(Error::FrameTooLarge {
            size: body.len(),
            limit: MAX_CONTROL_FRAME,
        });
    }

    writer.write_all(&(body.len() as u32).to_le_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed postcard frame, refusing anything over `limit`.
///
/// The length is validated *before* allocating, so an oversized prefix costs a
/// four-byte read and an error rather than a heap allocation.
pub async fn read_frame<R, T>(reader: &mut R, limit: usize) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let body = read_frame_bytes(reader, limit).await?;
    postcard::from_bytes(&body).map_err(|e| Error::Protocol(format!("malformed message: {e}")))
}

/// Read one length-prefixed frame without decoding it.
///
/// For messages that need a decoding fallback, such as [`Hello::decode`].
pub async fn read_frame_bytes<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    if len > limit {
        return Err(Error::FrameTooLarge { size: len, limit });
    }

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DEVICE_ID_LEN;

    fn test_hello() -> Hello {
        Hello::new(DeviceId::from_bytes([7u8; DEVICE_ID_LEN]), "Test Device")
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let mut buf = Vec::new();
        let original = test_hello();
        write_frame(&mut buf, &original).await.unwrap();

        let decoded: Hello = read_frame(&mut buf.as_slice(), MAX_CONTROL_FRAME).await.unwrap();

        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.name, "Test Device");
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn several_frames_stream_back_in_order() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Control::Ping(1)).await.unwrap();
        write_frame(&mut buf, &Control::Pong(1)).await.unwrap();

        let mut cursor = buf.as_slice();
        assert!(matches!(
            read_frame::<_, Control>(&mut cursor, MAX_CONTROL_FRAME).await.unwrap(),
            Control::Ping(1)
        ));
        assert!(matches!(
            read_frame::<_, Control>(&mut cursor, MAX_CONTROL_FRAME).await.unwrap(),
            Control::Pong(1)
        ));
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_refused_without_allocating() {
        // 4 GiB length prefix, no body. A naive reader would try to allocate it.
        let hostile = u32::MAX.to_le_bytes();

        let err = read_frame::<_, Control>(&mut hostile.as_slice(), MAX_CONTROL_FRAME)
            .await
            .unwrap_err();

        assert!(matches!(err, Error::FrameTooLarge { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error_not_a_hang() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &test_hello()).await.unwrap();
        buf.truncate(buf.len() - 3);

        assert!(read_frame::<_, Hello>(&mut buf.as_slice(), MAX_CONTROL_FRAME).await.is_err());
    }

    /// A `Hello` as a build with `flags` capabilities wrote it.
    #[derive(Serialize)]
    struct OtherHello<F: Serialize> {
        version: u16,
        device_id: DeviceId,
        name: String,
        platform: Platform,
        app_version: String,
        capabilities: F,
    }

    fn other_hello<F: Serialize>(flags: F) -> Vec<u8> {
        postcard::to_stdvec(&OtherHello {
            version: PROTOCOL_VERSION,
            device_id: DeviceId::from_bytes([3u8; DEVICE_ID_LEN]),
            name: "Other Build".into(),
            platform: Platform::Windows,
            app_version: "0.1.0".into(),
            capabilities: flags,
        })
        .unwrap()
    }

    #[test]
    fn an_older_peers_hello_still_decodes_without_the_new_capability() {
        // The first release: two flags.
        let decoded = Hello::decode(&other_hello((false, false))).unwrap();
        assert_eq!(decoded.name, "Other Build");
        assert!(
            !decoded.capabilities.live_status && !decoded.capabilities.chunk_hashes,
            "an older build must never be sent messages it cannot decode"
        );

        // The release that added `live_status`: three flags.
        let decoded = Hello::decode(&other_hello((false, false, true))).unwrap();
        assert!(decoded.capabilities.live_status);
        assert!(!decoded.capabilities.chunk_hashes);
    }

    #[test]
    fn a_newer_peers_extra_capabilities_are_ignored() {
        let decoded = Hello::decode(&other_hello((true, false, true, true, true, true))).unwrap();
        assert!(decoded.capabilities.zstd && decoded.capabilities.chunk_hashes);
    }

    #[test]
    fn a_newer_hello_decodes_with_its_capabilities() {
        let body = postcard::to_stdvec(&test_hello()).unwrap();
        assert_eq!(Hello::decode(&body).unwrap().capabilities, Capabilities::ours());
    }

    #[test]
    fn compressed_chunk_headers_round_trip() {
        let header = ChunkHeaderV2 {
            index: 7,
            len: 1 << 20,
            wire_len: 300_000,
            hash: [0xCD; 32],
        };
        assert_eq!(ChunkHeaderV2::decode(&header.encode()), header);
        assert!(header.compressed());
        assert!(!ChunkHeaderV2 { wire_len: 1 << 20, ..header }.compressed());
    }

    #[test]
    fn chunk_headers_round_trip() {
        let header = ChunkHeader {
            index: 4_000_000,
            len: 1 << 20,
            hash: [0xAB; 32],
        };
        assert_eq!(ChunkHeader::decode(&header.encode()), header);
    }

    #[test]
    fn hostile_display_names_are_defanged() {
        assert_eq!(sanitize_name("Mike's Desktop"), "Mike's Desktop");
        assert_eq!(sanitize_name("  padded  "), "padded");
        assert_eq!(sanitize_name(""), "Unnamed device");
        assert_eq!(sanitize_name("\u{202E}gnp.exe"), "gnp.exe", "bidi override stripped");
        assert_eq!(sanitize_name("line\nbreak\r\0"), "linebreak", "control chars stripped");
        assert!(sanitize_name(&"A".repeat(10_000)).len() <= MAX_NAME_BYTES);
    }
}
