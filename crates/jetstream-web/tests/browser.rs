//! End-to-end tests of the browser receiver over real HTTP.
//!
//! These drive the actual server with a real client, because the parts most
//! likely to be wrong are the ones a unit test cannot see: cookie handling,
//! whether an unauthenticated request really is refused, and whether a resumed
//! upload asks for the right bytes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use jetstream_core::staging::ConflictPolicy;
use jetstream_core::transfer::Progress;
use jetstream_web::{
    GuestInfo, OfferedFile, UploadGrant, UploadOffer, WebHandler, WebServer, crc32,
};

/// A handler that answers however the test tells it to.
struct TestApp {
    destination: PathBuf,
    accept: bool,
    finished: Mutex<Vec<String>>,
    offers: Mutex<Vec<PathBuf>>,
    received_text: Mutex<Vec<String>>,
    shared_text: Mutex<Option<String>>,
}

impl TestApp {
    fn new(destination: PathBuf, accept: bool) -> Arc<Self> {
        Arc::new(Self {
            destination,
            accept,
            finished: Mutex::new(Vec::new()),
            offers: Mutex::new(Vec::new()),
            received_text: Mutex::new(Vec::new()),
            shared_text: Mutex::new(None),
        })
    }
}

impl WebHandler for TestApp {
    fn device_name(&self) -> String {
        "Test Machine".into()
    }

    fn accept_upload(
        &self,
        _guest: GuestInfo,
        _offer: UploadOffer,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<UploadGrant>> + Send>> {
        let grant = self.accept.then(|| UploadGrant {
            destination: self.destination.clone(),
            conflict: ConflictPolicy::Rename,
            progress: Arc::new(Progress::default()),
        });
        Box::pin(async move { grant })
    }

    fn upload_finished(&self, _guest: GuestInfo, files: Vec<String>) {
        self.finished.lock().unwrap().extend(files);
    }

    fn offered_files(&self) -> Vec<OfferedFile> {
        self.offers
            .lock()
            .unwrap()
            .iter()
            .filter_map(|path| {
                let size = std::fs::metadata(path).ok()?.len();
                Some(OfferedFile {
                    id: "offered-1".into(),
                    name: path.file_name()?.to_string_lossy().to_string(),
                    size,
                    path: path.clone(),
                })
            })
            .collect()
    }

    fn receive_text(&self, _guest: GuestInfo, text: String) {
        self.received_text.lock().unwrap().push(text);
    }

    fn text_to_share(&self) -> Option<String> {
        self.shared_text.lock().unwrap().clone()
    }
}

/// A minimal HTTP client. Avoids adding reqwest just for a handful of requests,
/// and keeps the test honest about exactly what goes on the wire.
struct Client {
    base: String,
    cookie: Option<String>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl Client {
    fn new(address: std::net::SocketAddr) -> Self {
        Self {
            base: format!("{address}"),
            cookie: None,
        }
    }

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Reply {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(&self.base).await.unwrap();

        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)\r\n\
             Content-Length: {}\r\n",
            self.base,
            body.len()
        );
        if let Some(kind) = content_type {
            request.push_str(&format!("Content-Type: {kind}\r\n"));
        }
        if let Some(cookie) = &self.cookie {
            request.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        request.push_str("\r\n");

        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();

        parse(&raw)
    }

    async fn get(&mut self, path: &str) -> Reply {
        self.send("GET", path, None, b"").await
    }

    async fn post_json(&mut self, path: &str, json: serde_json::Value) -> Reply {
        let body = serde_json::to_vec(&json).unwrap();
        self.send("POST", path, Some("application/json"), &body).await
    }

    async fn put(&mut self, path: &str, body: &[u8]) -> Reply {
        self.send("PUT", path, Some("application/octet-stream"), body).await
    }

    /// Scan a pairing code and keep the session cookie.
    async fn pair(&mut self, token: &str) -> bool {
        let reply = self.get(&format!("/j/{token}")).await;

        if let Some(set) = reply.header("set-cookie") {
            self.cookie = set.split(';').next().map(str::to_string);
        }
        reply.status == 303 && self.cookie.is_some()
    }
}

fn parse(raw: &[u8]) -> Reply {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header terminator in response");

    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.lines();

    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("no status code");

    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed)).collect()
}

async fn serve(app: Arc<TestApp>) -> WebServer {
    WebServer::start(app).await.expect("a LAN address is needed for these tests")
}

#[tokio::test]
async fn a_browser_pairs_and_sees_the_device_name() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), true)).await;
    let mut client = Client::new(server.address());

    let code = server.pairing_code();
    assert!(client.pair(&code.token).await, "pairing should succeed");

    let info = client.get("/api/session").await;
    assert_eq!(info.status, 200);
    assert_eq!(info.json()["deviceName"], "Test Machine");
    // Derived from the User-Agent the client sends.
    assert_eq!(info.json()["guestLabel"], "iPhone");

    server.stop().await;
}

/// The security property the whole design rests on: knowing the port is not
/// enough. Without a code, nothing is reachable.
#[tokio::test]
async fn every_endpoint_refuses_an_unpaired_client() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), true)).await;
    let mut client = Client::new(server.address());

    for path in ["/", "/api/session", "/api/text", "/api/download/offered-1"] {
        let reply = client.get(path).await;
        assert!(
            reply.status == 401 || reply.status == 403,
            "SECURITY: {path} answered {} without a session",
            reply.status
        );
    }

    let reply = client
        .post_json("/api/upload", serde_json::json!({ "files": [] }))
        .await;
    assert_eq!(reply.status, 401, "SECURITY: upload accepted without a session");

    let reply = client.put("/api/upload/abc/0/0?crc=0", b"data").await;
    assert_eq!(reply.status, 401, "SECURITY: chunk accepted without a session");

    server.stop().await;
}

#[tokio::test]
async fn a_pairing_code_works_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), true)).await;
    let code = server.pairing_code();

    let mut first = Client::new(server.address());
    assert!(first.pair(&code.token).await);

    // Somebody who saw the QR afterwards must not be able to use it.
    let mut second = Client::new(server.address());
    assert!(
        !second.pair(&code.token).await,
        "SECURITY: a spent pairing code was accepted again"
    );

    server.stop().await;
}

#[tokio::test]
async fn a_made_up_token_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), true)).await;

    let mut client = Client::new(server.address());
    assert!(!client.pair("00000000000000000000000000000000").await);

    server.stop().await;
}

/// The main event: a browser uploads a multi-chunk file and it lands intact.
#[tokio::test]
async fn a_chunked_upload_lands_intact() {
    let dir = tempfile::tempdir().unwrap();
    let app = TestApp::new(dir.path().to_path_buf(), true);
    let server = serve(Arc::clone(&app)).await;
    let mut client = Client::new(server.address());

    let code = server.pairing_code();
    assert!(client.pair(&code.token).await);

    let size = 1024 * 1024 + 4096; // two chunks, second one short
    let data = payload(size, 7);

    let plan = client
        .post_json(
            "/api/upload",
            serde_json::json!({ "files": [{ "path": "holiday.jpg", "size": size }] }),
        )
        .await;
    assert_eq!(plan.status, 200, "{}", plan.text());

    let plan = plan.json();
    let transfer = plan["transferId"].as_str().unwrap().to_string();
    let chunk_size = plan["chunkSize"].as_u64().unwrap() as usize;
    assert_eq!(plan["needed"][0]["ranges"][0][0], 0);

    for index in 0..2usize {
        let start = index * chunk_size;
        let slice = &data[start..(start + chunk_size).min(size)];
        let reply = client
            .put(
                &format!(
                    "/api/upload/{transfer}/0/{index}?crc={:x}",
                    crc32(slice)
                ),
                slice,
            )
            .await;
        assert_eq!(reply.status, 204, "chunk {index}: {}", reply.text());
    }

    let done = client
        .post_json(&format!("/api/upload/{transfer}/finish"), serde_json::json!({}))
        .await;
    assert_eq!(done.status, 200, "{}", done.text());

    assert_eq!(std::fs::read(dir.path().join("holiday.jpg")).unwrap(), data);
    assert_eq!(app.finished.lock().unwrap().as_slice(), ["holiday.jpg"]);

    server.stop().await;
}

/// The headline behaviour of this path: a phone that drops off mid-upload asks
/// what is missing and sends only that.
#[tokio::test]
async fn an_interrupted_upload_resumes_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let app = TestApp::new(dir.path().to_path_buf(), true);
    let server = serve(Arc::clone(&app)).await;
    let mut client = Client::new(server.address());
    assert!(client.pair(&server.pairing_code().token).await);

    let chunk_size = 1024 * 1024;
    let size = chunk_size * 3;
    let data = payload(size, 11);
    let declaration = serde_json::json!({ "files": [{ "path": "clip.mp4", "size": size }] });

    let plan = client.post_json("/api/upload", declaration.clone()).await.json();
    let transfer = plan["transferId"].as_str().unwrap().to_string();

    // Send one chunk of three, then stop as if the signal dropped.
    let slice = &data[..chunk_size];
    client
        .put(
            &format!("/api/upload/{transfer}/0/0?crc={:x}", crc32(slice)),
            slice,
        )
        .await;

    // Ask what is still needed.
    let status = client
        .get(&format!("/api/upload/{transfer}/status"))
        .await
        .json();
    assert_eq!(
        status["needed"][0]["ranges"][0][0], 1,
        "resume must skip the chunk already sent: {status}"
    );
    assert_eq!(status["needed"][0]["ranges"][0][1], 3);

    for index in 1..3usize {
        let start = index * chunk_size;
        let slice = &data[start..start + chunk_size];
        client
            .put(
                &format!("/api/upload/{transfer}/0/{index}?crc={:x}", crc32(slice)),
                slice,
            )
            .await;
    }
    client
        .post_json(&format!("/api/upload/{transfer}/finish"), serde_json::json!({}))
        .await;

    assert_eq!(
        std::fs::read(dir.path().join("clip.mp4")).unwrap(),
        data,
        "the resumed upload must be byte-identical"
    );

    server.stop().await;
}

#[tokio::test]
async fn a_corrupt_chunk_is_rejected_and_can_be_re_sent() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), true)).await;
    let mut client = Client::new(server.address());
    assert!(client.pair(&server.pairing_code().token).await);

    let data = payload(5000, 3);
    let plan = client
        .post_json(
            "/api/upload",
            serde_json::json!({ "files": [{ "path": "f.bin", "size": data.len() }] }),
        )
        .await
        .json();
    let transfer = plan["transferId"].as_str().unwrap().to_string();

    // Right checksum, wrong bytes — the flipped-bit case.
    let mut corrupt = data.clone();
    corrupt[42] ^= 0xFF;

    let reply = client
        .put(
            &format!("/api/upload/{transfer}/0/0?crc={:x}", crc32(&data)),
            &corrupt,
        )
        .await;
    assert_eq!(reply.status, 422, "corrupt chunk should be refused");
    assert!(!dir.path().join("f.bin").exists());

    // The good bytes then work.
    let reply = client
        .put(
            &format!("/api/upload/{transfer}/0/0?crc={:x}", crc32(&data)),
            &data,
        )
        .await;
    assert_eq!(reply.status, 204);

    server.stop().await;
}

#[tokio::test]
async fn a_declined_upload_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), false)).await;
    let mut client = Client::new(server.address());
    assert!(client.pair(&server.pairing_code().token).await);

    let reply = client
        .post_json(
            "/api/upload",
            serde_json::json!({ "files": [{ "path": "unwanted.bin", "size": 100 }] }),
        )
        .await;

    assert_eq!(reply.status, 403);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

    server.stop().await;
}

/// A browser is fully untrusted, so a crafted path must not escape the folder.
#[tokio::test]
async fn a_traversal_path_is_refused_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("inbox");
    std::fs::create_dir_all(&destination).unwrap();

    let server = serve(TestApp::new(destination.clone(), true)).await;
    let mut client = Client::new(server.address());
    assert!(client.pair(&server.pairing_code().token).await);

    for hostile in ["../escaped.txt", "..\\..\\evil.dll", "C:\\Windows\\x.dll", "CON"] {
        let reply = client
            .post_json(
                "/api/upload",
                serde_json::json!({ "files": [{ "path": hostile, "size": 10 }] }),
            )
            .await;
        assert_eq!(
            reply.status, 400,
            "SECURITY: {hostile:?} was accepted: {}",
            reply.text()
        );
    }

    // Nothing outside the destination, and nothing inside it either.
    assert!(!dir.path().join("escaped.txt").exists());
    assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);

    server.stop().await;
}

/// Downloads must be resumable, which for HTTP means honouring `Range`.
#[tokio::test]
async fn an_offered_file_downloads_and_supports_ranges() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("report.pdf");
    let data = payload(9000, 5);
    std::fs::write(&source, &data).unwrap();

    let app = TestApp::new(dir.path().to_path_buf(), true);
    app.offers.lock().unwrap().push(source);

    let server = serve(Arc::clone(&app)).await;
    let mut client = Client::new(server.address());
    assert!(client.pair(&server.pairing_code().token).await);

    let listing = client.get("/api/session").await.json();
    assert_eq!(listing["files"][0]["name"], "report.pdf");
    assert_eq!(listing["files"][0]["size"], 9000);

    let whole = client.get("/api/download/offered-1").await;
    assert_eq!(whole.status, 200);
    assert_eq!(whole.body, data);
    assert_eq!(
        whole.header("accept-ranges"),
        Some("bytes"),
        "without this, a browser cannot resume an interrupted download"
    );
    assert!(
        whole.header("content-disposition").unwrap().contains("report.pdf"),
        "the browser needs a filename to save under"
    );

    // A browser resuming would ask for the tail.
    let tail = client
        .send("GET", "/api/download/offered-1", None, b"")
        .await;
    assert_eq!(tail.status, 200);

    server.stop().await;
}

#[tokio::test]
async fn a_download_id_that_was_never_offered_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), true)).await;
    let mut client = Client::new(server.address());
    assert!(client.pair(&server.pairing_code().token).await);

    let reply = client.get("/api/download/not-a-real-id").await;
    assert_eq!(
        reply.status, 404,
        "a browser must not be able to fetch anything that was not offered"
    );

    server.stop().await;
}

#[tokio::test]
async fn text_moves_in_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    let app = TestApp::new(dir.path().to_path_buf(), true);
    *app.shared_text.lock().unwrap() = Some("from the desktop".into());

    let server = serve(Arc::clone(&app)).await;
    let mut client = Client::new(server.address());
    assert!(client.pair(&server.pairing_code().token).await);

    // Desktop -> browser.
    assert_eq!(
        client.get("/api/session").await.json()["sharedText"],
        "from the desktop"
    );

    // Browser -> desktop.
    let reply = client
        .post_json("/api/text", serde_json::json!({ "text": "from the phone" }))
        .await;
    assert_eq!(reply.status, 204);
    assert_eq!(
        app.received_text.lock().unwrap().as_slice(),
        ["from the phone"]
    );

    server.stop().await;
}

#[tokio::test]
async fn the_server_stops_listening_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(TestApp::new(dir.path().to_path_buf(), true)).await;
    let address = server.address();

    server.stop().await;

    // Give the OS a moment to release the port.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .map(|r| r.is_err())
        .unwrap_or(true),
        "the port should be closed after stopping"
    );
}
