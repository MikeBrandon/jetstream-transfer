//! `jet` — headless Jetstream.
//!
//! This is the primary test surface for the transfer engine. Everything the
//! desktop app does goes through the same `jetstream-core` API, so a protocol
//! problem can always be reproduced here without a UI in the way.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use jetstream_core::manifest::Manifest;
use jetstream_discovery::Discovery;
use jetstream_core::identity::{Identity, store};
use jetstream_core::staging::{ConflictPolicy, Placement};
use jetstream_core::transfer::{self, Decision, Progress};
use jetstream_core::transport::{Endpoint, Session};
use jetstream_core::{DEFAULT_PORT, DeviceId, default_device_name};

#[derive(Parser)]
#[command(name = "jet", version, about = "Jetstream — resumable LAN file transfer")]
struct Cli {
    /// Override the data directory holding this device's identity.
    ///
    /// Mainly for running two independent devices on one machine while
    /// testing — without it they would share an identity and refuse to pair.
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Name shown to other devices. Defaults to the machine name.
    #[arg(long, global = true, value_name = "NAME")]
    name: Option<String>,

    #[arg(long, global = true, default_value = "info", value_name = "LEVEL")]
    log: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show this device's identity and fingerprint.
    Id,
    /// Listen for incoming connections and transfers.
    Listen(ListenArgs),
    /// Connect to a peer and report who answered.
    Connect(ConnectArgs),
    /// Send files or folders to a peer.
    Send(SendArgs),
    /// Watch the network for other Jetstream devices.
    Discover(DiscoverArgs),
    /// Explain why devices might not be showing up.
    Doctor(DiscoverArgs),
    /// Host the browser receiver, so phones and other machines can send here
    /// without installing anything.
    Browser(BrowserArgs),
    /// Measure transfer throughput.
    Bench(BenchArgs),
}

#[derive(Args)]
struct BenchArgs {
    /// Size of the test payload, in MiB.
    #[arg(long, default_value_t = 512)]
    size: u64,

    /// Number of files to split the payload across.
    ///
    /// One large file measures raw streaming; many small files measure
    /// per-file overhead, which is a completely different bottleneck and the
    /// one Dukto fails hardest at.
    #[arg(long, default_value_t = 1)]
    files: u64,

    /// Keep the temporary files, for inspection.
    #[arg(long)]
    keep: bool,
}

#[derive(Args)]
struct BrowserArgs {
    /// Where uploads land.
    #[arg(long, value_name = "DIR", default_value = ".")]
    to: PathBuf,

    /// Accept uploads without prompting.
    ///
    /// Necessary on a headless machine, where there is nobody to ask — and the
    /// reason the pairing code is the only thing standing between a stranger and
    /// this folder. Keep the code private.
    #[arg(long)]
    yes: bool,

    /// Files to offer for download.
    #[arg(long = "offer", value_name = "PATH")]
    offers: Vec<PathBuf>,
}

#[derive(Args)]
struct DiscoverArgs {
    /// How long to watch before reporting, in seconds.
    ///
    /// mDNS and broadcast both need a moment; reporting instantly would call
    /// a healthy network broken.
    #[arg(long, default_value_t = 6)]
    seconds: u64,

    /// Transfer port to advertise.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
}

#[derive(Args)]
struct ListenArgs {
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Bind to loopback only.
    #[arg(long)]
    local: bool,

    /// Where received files land.
    #[arg(long, value_name = "DIR", default_value = ".")]
    to: PathBuf,

    /// Accept transfers without prompting.
    ///
    /// Only reasonable on a trusted network — it is the behaviour that makes
    /// Dukto unsafe to leave running in a cafe.
    #[arg(long)]
    yes: bool,

    /// Only accept from this device.
    #[arg(long, value_name = "DEVICE_ID")]
    only: Option<String>,

    /// What to do when a file already exists: rename, overwrite, or skip.
    #[arg(long, value_name = "POLICY", default_value = "rename")]
    on_conflict: ConflictArg,
}

#[derive(Args)]
struct SendArgs {
    /// Where to send: an address like `192.168.1.42:4646`, or `@name` /
    /// `@device-id` to look the device up by discovery first.
    ///
    /// Discovery is worth preferring: it finds every address a device has and
    /// tries them in turn, which is the only reliable way to reach a machine
    /// that also runs a VPN client or Hyper-V.
    address: String,

    /// Files or folders to send.
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Require the peer to be this exact device.
    #[arg(long, value_name = "DEVICE_ID")]
    expect: Option<String>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ConflictArg {
    Rename,
    Overwrite,
    Skip,
}

impl From<ConflictArg> for ConflictPolicy {
    fn from(value: ConflictArg) -> Self {
        match value {
            ConflictArg::Rename => Self::Rename,
            ConflictArg::Overwrite => Self::Overwrite,
            ConflictArg::Skip => Self::Skip,
        }
    }
}

#[derive(Args)]
struct ConnectArgs {
    /// Peer address, e.g. `192.168.1.42:4646`. The port may be omitted.
    address: String,

    /// Require the peer to be this exact device.
    ///
    /// Without it this is a first-contact pairing attempt: whoever answers is
    /// accepted and their fingerprint printed for you to verify out of band.
    #[arg(long, value_name = "DEVICE_ID")]
    expect: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log.clone().into()),
        )
        .with_target(false)
        .init();

    // `--data-dir` is the explicit override; otherwise the same resolution the
    // desktop app uses, so a portable copy behaves the same from either binary.
    let location = match &cli.data_dir {
        Some(dir) => store::Location {
            dir: dir.clone(),
            protection: store::KeyProtection::User,
        },
        None => store::resolve_location().context("locating the Jetstream data directory")?,
    };
    let data_dir = location.dir.clone();

    let identity = Arc::new(
        store::load_or_create_protected(&data_dir, location.protection)
            .with_context(|| format!("loading device identity from {}", data_dir.display()))?,
    );

    let name = cli.name.clone().unwrap_or_else(default_device_name);

    match cli.command {
        Command::Id => {
            print_identity(&identity, &name, &data_dir);
            Ok(())
        }
        Command::Listen(args) => listen(identity, name, args).await,
        Command::Connect(args) => connect(identity, name, args).await,
        Command::Send(args) => send(identity, name, args).await,
        Command::Discover(args) => discover(identity, name, args, false).await,
        Command::Doctor(args) => discover(identity, name, args, true).await,
        Command::Browser(args) => browser(name, args).await,
        Command::Bench(args) => bench(args).await,
    }
}

/// Watch for peers, then either list them or explain what is missing.
async fn discover(
    identity: Arc<Identity>,
    name: String,
    args: DiscoverArgs,
    doctor: bool,
) -> Result<()> {
    let discovery = Discovery::start(identity.device_id(), &name, args.port);

    println!("Watching for devices as {name} for {}s...", args.seconds);
    tokio::time::sleep(std::time::Duration::from_secs(args.seconds)).await;

    let peers = discovery.peers();
    println!();

    if peers.is_empty() {
        println!("No other devices found.");
    } else {
        println!("Found {} device(s):", peers.len());
        for peer in &peers {
            let sources: Vec<&str> = peer.sources.iter().map(|s| s.label()).collect();
            println!();
            println!("  {}", peer.name);
            println!("    {}", peer.device_id.fingerprint());
            println!("    {}", peer.device_id);
            println!(
                "    {}  (via {})",
                peer.best_address()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "no address".into()),
                sources.join(", ")
            );
        }
        println!();
        println!("Send to one with:");
        if let Some(peer) = peers.first()
            && let Some(address) = peer.best_address()
        {
            println!("  jet send {address} <path> --expect {}", peer.device_id);
        }
    }

    if doctor {
        println!();
        println!("--- diagnostics ---");

        // The firewall rule first: it is the only check here that is a direct
        // observation about our own reachability rather than an inference.
        print_firewall_status();

        // Then the measured probe, because "nothing can reach us" explains an
        // empty peer list better than any pattern-matching can.
        println!("{}", jetstream_discovery::diagnostics::probe_inbound(identity).await);
        print!("{}", discovery.diagnose());
    } else if peers.is_empty() {
        println!();
        println!("Run `jet doctor` to find out why.");
    }

    Ok(())
}

fn print_identity(identity: &Identity, name: &str, data_dir: &std::path::Path) {
    let id = identity.device_id();
    println!("Name:        {name}");
    println!("Device ID:   {id}");
    println!("Fingerprint: {}", id.fingerprint());
    println!("Data dir:    {}", data_dir.display());
    println!();
    println!("Read the fingerprint aloud when pairing. If it does not match what");
    println!("the other device shows, do not accept the connection.");
}

async fn listen(identity: Arc<Identity>, name: String, args: ListenArgs) -> Result<()> {
    let endpoint = if args.local {
        Endpoint::bind(
            identity.clone(),
            name.clone(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, args.port)),
        )?
    } else {
        Endpoint::bind_all(identity.clone(), name.clone(), args.port)?
    };

    let bound = endpoint.local_addr()?;
    let id = identity.device_id();

    let only = args
        .only
        .as_deref()
        .map(str::parse::<DeviceId>)
        .transpose()
        .context("parsing --only")?;

    let destination = std::path::absolute(&args.to)
        .with_context(|| format!("resolving --to {}", args.to.display()))?;
    std::fs::create_dir_all(&destination)
        .with_context(|| format!("creating {}", destination.display()))?;

    println!("Listening on {bound}");
    println!("  {name} — {}", id.fingerprint());
    println!("  {id}");
    println!("  receiving into {}", destination.display());
    if let Some(only) = only {
        println!("  accepting only from {}", only.short());
    }
    println!();
    println!("Send from another machine with:");
    println!("  jet send <this-host>:{} <path> --expect {id}", bound.port());

    // Advertise so peers can find this device without being told an address.
    // Loopback-only listeners skip it: announcing an address nobody else can
    // reach would put a dead entry in everybody's peer list.
    let _discovery = if args.local {
        println!("  (loopback only — not advertising on the network)");
        None
    } else {
        Some(Discovery::start(id, &name, bound.port()))
    };
    println!();

    let policy = Policy {
        destination,
        conflict: args.on_conflict.into(),
        auto_accept: args.yes,
        only,
    };

    // Ctrl-C is the expected way to stop, so shut the endpoint down cleanly
    // rather than dropping connections on the floor.
    let serving = async {
        while let Some(result) = endpoint.accept().await {
            match result {
                Ok(session) => {
                    tokio::spawn(serve(session, policy.clone()));
                }
                Err(e) => tracing::warn!(error = %e, "rejected an inbound connection"),
            }
        }
    };

    tokio::select! {
        _ = serving => {}
        _ = tokio::signal::ctrl_c() => println!("\nShutting down..."),
    }

    endpoint.shutdown().await;
    Ok(())
}

/// How this listener decides what to accept.
#[derive(Clone)]
struct Policy {
    destination: PathBuf,
    conflict: ConflictPolicy,
    auto_accept: bool,
    only: Option<DeviceId>,
}

/// Handle one inbound session: receive at most one transfer, then hang up.
async fn serve(session: Arc<Session>, policy: Policy) {
    let peer = session.peer().clone();
    println!(
        "\n  <- {} ({}) from {}",
        peer.name,
        peer.device_id.fingerprint(),
        peer.remote_address,
    );

    if let Some(only) = policy.only
        && only != peer.device_id
    {
        println!("     refused: not the device this listener is pinned to");
        session.close("not accepting from this device").await;
        return;
    }

    let progress = Arc::new(Progress::default());
    let reporter = tokio::spawn(report_progress(Arc::clone(&progress)));

    let decision = {
        let policy = policy.clone();
        let peer_name = peer.name.clone();
        move |offer: jetstream_core::proto::Offer| async move {
            let description = transfer::describe(&offer.summary);
            println!("     offers {description}");

            if policy.auto_accept {
                println!("     accepted automatically (--yes)");
                return Decision::Accept {
                    destination: policy.destination,
                    conflict: policy.conflict,
                };
            }

            if confirm(&format!("     Accept {description} from {peer_name}?")) {
                Decision::Accept {
                    destination: policy.destination,
                    conflict: policy.conflict,
                }
            } else {
                Decision::Reject {
                    reason: "declined by the user".into(),
                }
            }
        }
    };

    let result = transfer::receive(&session, decision, Arc::clone(&progress)).await;
    reporter.abort();

    match result {
        Ok(received) => {
            println!(
                "     done — {} in {} item(s)",
                transfer::human_bytes(received.bytes),
                received.placements.len()
            );
            for placement in &received.placements {
                describe_placement(placement);
            }
        }
        Err(e) => {
            // Staged chunks survive, so this really is a pause.
            println!("     stopped: {e}");
            println!("     partial data was kept; sending the same files again will resume");
        }
    }

    session.close("transfer finished").await;
}

fn describe_placement(placement: &Placement) {
    match placement {
        Placement::Created(path) => println!("       + {}", path.display()),
        Placement::Renamed(path) => {
            println!("       + {} (renamed to avoid overwriting)", path.display())
        }
        Placement::Overwritten(path) => println!("       ~ {} (overwritten)", path.display()),
        Placement::Skipped(path) => println!("       . {} (skipped, already present)", path.display()),
    }
}

/// Ask on the terminal. Runs on the blocking pool because stdin is blocking.
fn confirm(question: &str) -> bool {
    use std::io::{BufRead, Write};

    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();

    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Redraw a one-line progress indicator until the transfer ends.
async fn report_progress(progress: Arc<Progress>) {
    use std::io::Write;
    use std::sync::atomic::Ordering;

    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    // Measured from bytes that moved, not bytes done: on a resume the latter
    // starts at everything already there, which is not speed.
    let mut meter = jetstream_core::rate::RateMeter::new();

    loop {
        ticker.tick().await;

        meter.update(
            std::time::Instant::now(),
            progress.bytes_moved.load(Ordering::Relaxed),
        );

        let total = progress.bytes_total.load(Ordering::Relaxed);
        if total == 0 {
            continue;
        }
        let done = progress.bytes_done.load(Ordering::Relaxed);

        print!(
            "\r     {:>5.1}%  {} / {}  at {}/s     ",
            progress.fraction() * 100.0,
            transfer::human_bytes(done),
            transfer::human_bytes(total),
            transfer::human_bytes(meter.rate()),
        );
        let _ = std::io::stdout().flush();
    }
}

async fn connect(identity: Arc<Identity>, name: String, args: ConnectArgs) -> Result<()> {
    let address = resolve(&args.address)?;

    let expected = args
        .expect
        .as_deref()
        .map(str::parse::<DeviceId>)
        .transpose()
        .context("parsing --expect: it should be the 64-character device id from `jet id`")?;

    // Ephemeral port: a dialer does not need a stable one.
    let endpoint = Endpoint::bind(
        identity,
        name,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    )?;

    println!("Connecting to {address}...");
    let session = endpoint.connect(address, expected).await?;
    let peer = session.peer();

    println!();
    println!("Connected to {}", peer.name);
    println!("  Device ID:   {}", peer.device_id);
    println!("  Fingerprint: {}", peer.device_id.fingerprint());
    println!("  Platform:    {:?}", peer.platform);
    println!("  Version:     {}", peer.app_version);
    println!("  Address:     {}", peer.remote_address);

    if expected.is_none() {
        println!();
        println!("This was a first-contact connection. Confirm the fingerprint above");
        println!("matches what the other device shows before trusting it, then reconnect");
        println!("with:  --expect {}", peer.device_id);
    }

    match session.ping().await {
        Ok(rtt) => println!("  Round trip:  {rtt:.1?}"),
        Err(e) => println!("  Round trip:  unavailable ({e})"),
    }

    session.close("done").await;
    endpoint.shutdown().await;
    Ok(())
}

async fn send(identity: Arc<Identity>, name: String, args: SendArgs) -> Result<()> {
    let mut expected = args
        .expect
        .as_deref()
        .map(str::parse::<DeviceId>)
        .transpose()
        .context("parsing --expect")?;

    // `@something` means "find this device", anything else is an address.
    let (candidates, discovery) = match args.address.strip_prefix('@') {
        Some(query) => {
            let discovery = Discovery::start(identity.device_id(), &name, DEFAULT_PORT);
            println!("Looking for {query}...");

            let peer = wait_for_peer(&discovery, query, std::time::Duration::from_secs(8))
                .await
                .with_context(|| format!("no device matching {query:?} appeared on the network"))?;

            println!(
                "Found {} ({})",
                peer.name,
                peer.device_id.fingerprint()
            );
            // Discovery is unauthenticated, so the id it reports is only a
            // hint. Pinning it here turns that hint into a requirement the
            // handshake must satisfy.
            expected.get_or_insert(peer.device_id);

            let mut addresses = peer.addresses_by_preference();
            // Prefer the fastest wire among those that would reach the peer — a
            // gigabit cable beats Wi-Fi even though both are routable.
            jetstream_discovery::linkspeed::prefer_fast_links(&mut addresses);
            (addresses, Some(discovery))
        }
        None => (vec![resolve(&args.address)?], None),
    };
    drop(discovery);

    // Absolute, so the manifest's relative paths hang off a stable root even
    // if the process changes directory.
    let sources: Vec<PathBuf> = args
        .paths
        .iter()
        .map(|p| std::path::absolute(p).with_context(|| format!("resolving {}", p.display())))
        .collect::<Result<_>>()?;

    // The manifest is built from `stat` alone — no file contents are read — so
    // this stays fast even on a very large folder.
    let (manifest, report) = Manifest::from_paths(&sources)?;
    let summary = manifest.summary();

    println!("Sending {}", transfer::describe(&summary));
    if !report.is_clean() {
        println!("  {} item(s) skipped:", report.skipped_count());
        for path in report.symlinks_skipped.iter().take(5) {
            println!("    symlink: {}", path.display());
        }
        for (path, why) in report.unreadable.iter().take(5) {
            println!("    unreadable: {} ({why})", path.display());
        }
        for (path, why) in report.unsupported_names.iter().take(5) {
            println!("    unsupported name: {} ({why})", path.display());
        }
    }

    // Every source shares a root only if they share a parent; sending items
    // from different directories at once would need one manifest each.
    let root = common_root(&sources)?;

    let endpoint = Endpoint::bind(
        identity,
        name,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
    )?;

    if candidates.len() > 1 {
        println!(
            "Connecting, trying {} address(es): {}",
            candidates.len(),
            candidates
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        println!("Connecting to {}...", candidates[0]);
    }

    let session = endpoint
        .connect_any(&candidates, expected, std::time::Duration::from_secs(4))
        .await?;

    println!(
        "Connected to {} at {} ({})",
        session.peer().name,
        session.peer().remote_address,
        session.peer().device_id.fingerprint()
    );
    if expected.is_none() {
        println!("  first contact — verify that fingerprint before sending anything private");
    }
    println!("Waiting for the other device to accept...");

    let progress = Arc::new(Progress::default());
    let reporter = tokio::spawn(report_progress(Arc::clone(&progress)));

    let result = transfer::send(&session, &root, &manifest, Arc::clone(&progress)).await;
    reporter.abort();
    println!();

    match result {
        Ok(()) => {
            println!(
                "Sent {} — the receiver verified every file.",
                transfer::human_bytes(manifest.total_bytes())
            );
        }
        Err(ref e) => {
            println!("Transfer stopped: {e}");
            println!("Run the same command again to resume from where it left off.");
        }
    }

    session.close("done").await;
    endpoint.shutdown().await;
    result.map_err(Into::into)
}

/// Measure end-to-end throughput over a loopback QUIC connection.
///
/// In-process on purpose: two endpoints on the loopback interface take the
/// firewall, the physical link, and the peer's disk out of the picture, so what
/// is left is the engine itself. That makes it the right tool for optimisation
/// work — a number that moves when the code changes and not when the network
/// has a bad day.
///
/// It is *not* a measure of what a real network will do. Loopback has no
/// bandwidth limit and no loss, so this reports an upper bound.
async fn bench(args: BenchArgs) -> Result<()> {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    let total_bytes = args.size * 1024 * 1024;
    let per_file = (total_bytes / args.files.max(1)).max(1);

    let workspace = tempfile::tempdir().context("creating a scratch directory")?;
    let source_root = workspace.path().join("source");
    let destination = workspace.path().join("destination");
    std::fs::create_dir_all(source_root.join("payload"))?;
    std::fs::create_dir_all(&destination)?;

    println!(
        "Preparing {} MiB across {} file(s)...",
        args.size, args.files
    );

    // Pseudo-random, because zero-filled files are unrealistically kind to any
    // compression and to a filesystem that may special-case sparse writes.
    let build = Instant::now();
    {
        use std::io::Write;
        let mut block = vec![0u8; 1 << 20];
        let mut state = 0x243F_6A88_85A3_08D3u64;
        for byte in block.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }

        for index in 0..args.files {
            let path = source_root.join("payload").join(format!("file-{index:05}.bin"));
            let mut file = std::io::BufWriter::new(std::fs::File::create(&path)?);
            let mut left = per_file;
            while left > 0 {
                let take = left.min(block.len() as u64) as usize;
                file.write_all(&block[..take])?;
                left -= take as u64;
            }
            file.flush()?;
        }
    }
    println!("  written in {:.1?}", build.elapsed());

    // Two independent devices, as a real transfer would have.
    let listener_identity = Arc::new(Identity::generate()?);
    let listener_id = listener_identity.device_id();
    let listener = Endpoint::bind(
        listener_identity,
        "bench-receiver",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )?;
    let listener_addr = listener.local_addr()?;

    let dialer = Endpoint::bind(
        Arc::new(Identity::generate()?),
        "bench-sender",
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )?;

    let (manifest, _) = Manifest::from_paths(&[source_root.join("payload")])?;
    let bytes = manifest.total_bytes();

    let accepting = {
        let listener = listener.clone();
        tokio::spawn(async move { listener.accept().await.unwrap().unwrap() })
    };
    let sender = dialer.connect(listener_addr, Some(listener_id)).await?;
    let receiver = accepting.await?;

    let send_progress = Arc::new(Progress::default());
    let recv_progress = Arc::new(Progress::default());

    let root = source_root.clone();
    let sending = {
        let session = Arc::clone(&sender);
        let progress = Arc::clone(&send_progress);
        tokio::spawn(async move { transfer::send(&session, &root, &manifest, progress).await })
    };

    println!("Transferring {}...", transfer::human_bytes(bytes));
    let started = Instant::now();

    let ticker = {
        let progress = Arc::clone(&recv_progress);
        tokio::spawn(report_progress(progress))
    };

    let destination_for_accept = destination.clone();
    let received = transfer::receive(
        &receiver,
        async move |_| transfer::Decision::Accept {
            destination: destination_for_accept,
            conflict: ConflictPolicy::Overwrite,
        },
        Arc::clone(&recv_progress),
    )
    .await?;

    let elapsed = started.elapsed();
    ticker.abort();
    sending.await??;
    println!();

    let moved = recv_progress.bytes_done.load(Ordering::Relaxed);
    let rate = moved as f64 / elapsed.as_secs_f64();

    println!();
    println!("  payload    {}", transfer::human_bytes(bytes));
    println!("  files      {}", args.files);
    println!("  elapsed    {:.2?}", elapsed);
    println!("  throughput {}/s", transfer::human_bytes(rate as u64));
    if args.files > 1 {
        println!(
            "  per file   {:.2} ms",
            elapsed.as_secs_f64() * 1000.0 / args.files as f64
        );
    }
    println!("  placed     {} item(s)", received.placements.len());

    let _ = send_progress;
    sender.close("bench done").await;
    dialer.shutdown().await;
    listener.shutdown().await;

    if args.keep {
        let kept = workspace.keep();
        println!("  kept       {}", kept.display());
    }
    Ok(())
}

/// Host the browser receiver until interrupted.
async fn browser(name: String, args: BrowserArgs) -> Result<()> {
    use jetstream_web::{GuestInfo, OfferedFile, UploadGrant, UploadOffer, WebHandler, WebServer};

    struct Cli {
        name: String,
        destination: PathBuf,
        auto_accept: bool,
        offers: Vec<PathBuf>,
    }

    impl WebHandler for Cli {
        fn device_name(&self) -> String {
            self.name.clone()
        }

        fn accept_upload(
            &self,
            guest: GuestInfo,
            offer: UploadOffer,
        ) -> std::pin::Pin<Box<dyn Future<Output = Option<UploadGrant>> + Send>> {
            let description = format!(
                "{} file(s), {}",
                offer.file_count,
                transfer::human_bytes(offer.total_bytes)
            );
            println!("
  <- {} wants to send {description}", guest.label);

            let grant = if self.auto_accept {
                println!("     accepted automatically (--yes)");
                Some(UploadGrant {
                    destination: self.destination.clone(),
                    conflict: ConflictPolicy::Rename,
                    progress: Arc::new(Progress::default()),
                })
            } else if confirm(&format!("     Accept {description} from {}?", guest.label)) {
                Some(UploadGrant {
                    destination: self.destination.clone(),
                    conflict: ConflictPolicy::Rename,
                    progress: Arc::new(Progress::default()),
                })
            } else {
                None
            };

            Box::pin(async move { grant })
        }

        fn upload_finished(&self, guest: GuestInfo, files: Vec<String>) {
            println!("     {} sent {} item(s)", guest.label, files.len());
            for file in files {
                println!("       + {file}");
            }
        }

        fn offered_files(&self) -> Vec<OfferedFile> {
            self.offers
                .iter()
                .filter_map(|path| {
                    let size = std::fs::metadata(path).ok()?.len();
                    Some(OfferedFile {
                        id: hex::encode(&blake3_of(path)[..8]),
                        name: path.file_name()?.to_string_lossy().to_string(),
                        size,
                        path: path.clone(),
                    })
                })
                .collect()
        }

        fn receive_text(&self, guest: GuestInfo, text: String) {
            println!("
  <- text from {}:
{text}
", guest.label);
        }

        fn text_to_share(&self) -> Option<String> {
            None
        }
    }

    let destination = std::path::absolute(&args.to)?;
    std::fs::create_dir_all(&destination)?;

    let offers: Vec<PathBuf> = args
        .offers
        .iter()
        .map(std::path::absolute)
        .collect::<std::io::Result<_>>()?;

    let server = WebServer::start(Arc::new(Cli {
        name: name.clone(),
        destination: destination.clone(),
        auto_accept: args.yes,
        offers,
    }))
    .await?;

    let code = server.pairing_code();

    println!("Browser receiver running on {}", server.address());
    println!("  receiving into {}", destination.display());
    println!();
    println!("Open this on the other device:");
    println!();
    println!("  {}", code.url);
    println!();
    println!("The link works once and expires in {} minutes.", code.expires_in.as_secs() / 60);
    println!("This connection is not encrypted — it is for your local network only.");
    println!();
    println!("Press Ctrl-C to stop.");

    tokio::signal::ctrl_c().await?;
    println!("
Stopping...");
    server.stop().await;
    Ok(())
}

fn blake3_of(path: &std::path::Path) -> [u8; 32] {
    *blake3::hash(path.to_string_lossy().as_bytes()).as_bytes()
}

/// Report whether Windows Firewall is letting us receive.
///
/// The desktop app can fix this with a button; a CLI cannot show a UAC prompt
/// usefully, so it names the exact command instead.
fn print_firewall_status() {
    use jetstream_discovery::firewall::{self, RuleStatus};

    let Ok(exe) = firewall::current_exe() else {
        return;
    };

    match firewall::status(&exe) {
        RuleStatus::Present => println!("[ok] Windows Firewall is allowing this program through."),
        RuleStatus::Absent => {
            println!("[problem] Windows Firewall is blocking inbound connections to this program.");
            println!("       This machine can send but never receive. Fix it from an");
            println!("       administrator terminal with:");
            println!();
            println!("         netsh advfirewall firewall add rule name=\"Jetstream\" \\");
            println!("           dir=in action=allow protocol=UDP program=\"{}\"", exe.display());
            println!();
            println!("       Or run the Jetstream desktop app, which offers a button for it.");
        }
        RuleStatus::Moved(previous) => {
            println!("[problem] The firewall rule points at a different copy of this program.");
            println!("       Windows ties the permission to a path, and the rule still names");
            println!("         {previous}");
            println!("       so this copy is blocked. Re-add it from an administrator terminal:");
            println!();
            println!("         netsh advfirewall firewall delete rule name=\"Jetstream\"");
            println!("         netsh advfirewall firewall add rule name=\"Jetstream\" \\");
            println!("           dir=in action=allow protocol=UDP program=\"{}\"", exe.display());
        }
        RuleStatus::Disabled => {
            println!("[problem] Jetstream's firewall rule exists but is switched off.");
            println!("       Re-enable it in Windows Security > Firewall & network protection.");
        }
        RuleStatus::Unknown(detail) => {
            println!("[note] Could not check the firewall: {detail}");
        }
    }

    // Phone sharing is a web server, so it needs TCP as well — the rule above
    // only covers QUIC.
    if matches!(
        firewall::browser_status(&exe),
        RuleStatus::Absent | RuleStatus::Moved(_)
    ) {
        println!("[note] Phones and browsers cannot reach `jet browser` through the firewall.");
        println!("       To allow them, from an administrator terminal:");
        println!();
        println!("         netsh advfirewall firewall delete rule name=\"{}\"", firewall::BROWSER_RULE_NAME);
        println!("         netsh advfirewall firewall add rule name=\"{}\" \\", firewall::BROWSER_RULE_NAME);
        println!("           dir=in action=allow protocol=TCP remoteip=localsubnet program=\"{}\"", exe.display());
    }
}

/// Poll discovery until a device matching `query` shows up.
///
/// Matches a device-id prefix or a case-insensitive substring of the name, so
/// `@laptop` and `@40a9ae` both work.
async fn wait_for_peer(
    discovery: &Discovery,
    query: &str,
    timeout: std::time::Duration,
) -> Option<jetstream_discovery::DiscoveredPeer> {
    let deadline = std::time::Instant::now() + timeout;
    let needle = query.to_lowercase();

    while std::time::Instant::now() < deadline {
        let matches: Vec<_> = discovery
            .peers()
            .into_iter()
            .filter(|peer| {
                peer.device_id.to_hex().starts_with(&needle)
                    || peer.name.to_lowercase().contains(&needle)
            })
            .collect();

        match matches.len() {
            0 => {}
            1 => return matches.into_iter().next(),
            _ => {
                // Ambiguous. Better to say so than to pick one and send the
                // user's files to the wrong machine.
                println!("More than one device matches {query:?}:");
                for peer in &matches {
                    println!("  {} — {}", peer.name, peer.device_id);
                }
                println!("Use a longer name or the full device id.");
                return None;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    None
}

/// The directory the manifest's relative paths are resolved against.
///
/// `Manifest::from_paths` makes each source relative to its own parent, so all
/// sources must share one parent for a single manifest to describe them.
fn common_root(sources: &[PathBuf]) -> Result<PathBuf> {
    let mut parents = sources.iter().filter_map(|p| p.parent());
    let first = parents
        .next()
        .context("nothing to send")?
        .to_path_buf();

    for parent in parents {
        if parent != first {
            anyhow::bail!(
                "all paths in one transfer must share a parent directory\n  {} and {} do not",
                first.display(),
                parent.display()
            );
        }
    }
    Ok(first)
}

/// Parse `host:port`, `host`, or a bare IP, defaulting the port.
fn resolve(input: &str) -> Result<SocketAddr> {
    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }

    // Hostname: let the resolver decide, appending the default port if the
    // user did not give one.
    let with_port = if input.contains(':') {
        input.to_string()
    } else {
        format!("{input}:{DEFAULT_PORT}")
    };

    std::net::ToSocketAddrs::to_socket_addrs(&with_port)
        .with_context(|| format!("could not resolve {input:?}"))?
        .next()
        .with_context(|| format!("{input:?} resolved to no addresses"))
}
