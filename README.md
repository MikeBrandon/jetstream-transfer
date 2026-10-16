# Jetstream

Zero-configuration LAN file transfer. A replacement for [Dukto](https://github.com/xtreme8000/Dukto), built around the thing Dukto never had: **transfers that resume.**

> *The jet stream is the high-altitude current that carries weather, aircraft and dust across whole continents — the thing that moves cargo a very long way, fast.*

---

## Download

**[Latest release](https://github.com/MikeBrandon/jetstream-transfer/releases/latest)** — Windows 10 or 11, 64-bit.

| | |
|---|---|
| **`Jetstream_x64-setup.exe`** | Installer. Start here. |
| **`Jetstream_x64_en-US.msi`** | Same thing for managed deployment. |
| **`Jetstream-portable.zip`** | No install. Unzip and run, including from a USB stick — see [Portable copies](#portable-copies). |

There is nothing else to install: Windows 11 and up-to-date Windows 10 already
ship the WebView2 runtime Jetstream renders with.

The binaries are **not code-signed**, so Windows SmartScreen will warn you the
first time. Choose *More info* → *Run anyway*, or check the SHA-256 against the
release notes. Signing certificates cost money this project does not have; if
that is a problem for you, building from source takes one command.

**Other platforms** send and receive through the browser — no install, scan a QR
code. See [The browser receiver](#the-browser-receiver). A native macOS and Linux
build is not done.

## What this fixes

Dukto R6 is from 2013 and unmaintained. Its problems, and what Jetstream does instead:

| Dukto | Jetstream |
|---|---|
| A dropped connection restarts the whole transfer | Resumes from the exact chunk, surviving app crashes and power cuts |
| No integrity check — corruption is invisible | BLAKE3 per chunk *and* per file; a bad chunk is refused before it touches disk |
| No encryption, no authentication; anyone on the LAN can push files at you silently | TLS 1.3 over QUIC, Ed25519 device identity, pairing confirmed by a spoken six-word fingerprint |
| UDP broadcast only — dies across subnets and on isolated Wi-Fi | mDNS + broadcast + manual + saved peers, merged into one list |
| Empty peer list, no explanation | A diagnostics pass that names the actual cause and what to do |
| Blocked by Windows Firewall with no hint, forever | Detected on the main screen, with a one-click fix |
| Both ends need the app installed | Anything with a browser can take part — scan a QR code, no install |
| Silently overwrites existing files | Renames by default; overwrite and skip are opt-in |
| Loses empty folders, mtimes; breaks on long paths and reserved names | All preserved and handled, with hostile paths rejected before anything is created |

## The core idea

**Resume is not a feature — it is a property of the wire format.**

Every file is split into fixed 1 MiB chunks, and the **receiver drives the transfer** by asking for the chunks it does not already have. The sender keeps no per-transfer state at all.

That single decision gives, for free:

- **Resume** — reconnecting runs the same code as starting. There is no "resume mode" to get wrong.
- **Crash safety** — a chunk bitmap sits beside each partial file, checkpointed after the data it describes is flushed, so the bitmap can never claim more than the disk holds.
- **Stateless senders** — a sender that restarts mid-transfer costs nothing.
- **Harmless retries** — duplicate and overlapping requests are absorbed, so retry logic can be blunt and still correct.

Files are delivered as each one completes, not batched to the end, so an interrupted transfer leaves *usable files* rather than an opaque staging directory.

## Trust model

Device identity is an Ed25519 keypair, stored DPAPI-wrapped under `%LOCALAPPDATA%`. The device id is derived from the public key, so it survives certificate regeneration and app restarts — pair once, trust forever.

TLS proves *possession of a key*. Whether that key is welcome is a separate, application-level decision. Concretely:

- Certificate hostnames and validity dates are ignored. Pinning the key is the entire check.
- Discovery is **unauthenticated by nature** — anything on the network can claim any name or id. It is only ever used to decide *which key to pin*, never to grant trust.
- A mismatched identity aborts the handshake with an error naming the device you expected.

## Layout

```
crates/
  jetstream-core/       identity, TLS, QUIC transport, manifest, chunking, staging, trust, transfer engine
  jetstream-discovery/  mDNS + UDP broadcast + registry + network diagnostics + firewall
  jetstream-web/        browser receiver — resumable HTTP uploads, ranged downloads
  jetstream-cli/        `jet` — headless daemon and the primary test surface
apps/
  desktop/            Tauri 2 + React desktop app (src-tauri/ is the Rust half)
```

`jetstream-core` has no UI dependencies. The CLI drives the full engine, so any protocol problem can be reproduced without a UI in the way.

## Using it

### Desktop app

```bash
cd apps/desktop && npm install && npm run tauri dev
```

Drop files on the window and pick a device, or click a device to browse. Set
`JETSTREAM_DATA_DIR` to run a second independent instance on one machine.

### Command line

```bash
cargo build --release
```

Show this device's identity:

```bash
jet id
```

Receive (prompts before accepting; `--yes` to auto-accept on a trusted network):

```bash
jet listen --to ./Downloads
```

Send — by address, or by name via discovery:

```bash
jet send @Laptop ./Photos
```

```bash
jet send 192.168.1.42:4646 ./Photos --expect <device-id>
```

If the same command is run again after an interruption, it resumes.

Host the browser receiver, so a phone can send without installing anything:

```bash
jet browser --to ./Downloads
```

See who is around, or find out why nobody is:

```bash
jet discover
```

```bash
jet doctor
```

## Status

| Milestone | State |
|---|---|
| M0 — identity, TLS, QUIC handshake, pairing | done |
| M1 — manifest, chunking, staging, resume, verification | done |
| M2 — discovery and diagnostics | done |
| M3 — Tauri desktop UI | done |
| M4 — browser receiver for non-Windows devices | done |
| M5 — throughput | done |
| M6 — tray, shell integration, history, auto-resume, installer | done |

Measured on loopback with `jet bench` (median of three runs):

| Shape | Before M5 | After M5 |
|---|---|---|
| 1 × 512 MiB | 94.8 MB/s | **104.9 MB/s** |
| 64 × 4 MiB | — | **112.1 MB/s** |
| 1600 × 128 KiB | 6.3 MB/s | **42.3 MB/s** |

Loopback is an upper bound, not a prediction — but 105–112 MB/s comfortably
saturates gigabit Ethernet (~112 MB/s practical), which was the goal. Dukto
typically manages 30–60 MB/s and collapses on small files.

Measure your own setup:

```bash
jet bench --size 512 --files 1
```

### Portable copies

```bash
pwsh scripts/portable.ps1
```

Produces `target/portable/Jetstream-<version>-portable.zip` — the executable, a
`Jetstream Data` folder, and a README. Unzip it anywhere, including a USB stick,
and run it. Nothing to install: Windows 11 and up-to-date Windows 10 already
ship the WebView2 runtime Jetstream renders with.

**The folder is the switch.** If `Jetstream Data` exists beside the executable,
everything — identity, trusted devices, settings, history — goes in there and
nothing is written to the host machine. Detection is by folder rather than a
marker file because it is then visible and self-explaining: the data sits where
the flag is, and deleting the folder is the whole of "stop being portable". The
folder must already exist; creating it on demand would silently turn an
installed copy portable the first time it ran somewhere writable, stranding the
user's real identity and pairings.

The identity travels with the folder, so devices that trusted this one still do
after it moves. Three consequences worth stating plainly:

- **The private key is not DPAPI-wrapped.** It cannot be — the point is to work
  on a machine whose DPAPI master key we have never seen. So a portable copy is
  as exposed as an unencrypted `id_ed25519`: whoever holds the drive can act as
  that device. An installed copy has no such tradeoff, and this is the only
  reason to prefer one.
- **Start-with-Windows and the "Send to" entry are refused.** Both record this
  executable's path on the host, and both would outlive the drive being
  unplugged — a Run entry pointing at nothing, a dead shortcut. The user would
  be elsewhere by the time either failed, so the app refuses rather than warns.
- **The firewall rule is per-path.** Move the folder or change drive letter and
  it needs allowing again, because the rule names the executable.

`JETSTREAM_DATA_DIR` still takes precedence over both, and stays per-user
protected — its job is running two devices on one machine, which is not
portability.

### First run on Windows

Windows blocks inbound connections to any new program, which for a transfer app
is a silent failure: it still announces itself, still appears in everyone's
device list, and still *sends* — it simply never receives.

Jetstream detects this on the main screen and offers **Allow through firewall**.
That triggers a Windows permission prompt, because changing firewall settings
always requires an administrator; accepting it adds two narrow rules — inbound
UDP for transfers, and inbound TCP from the local subnet only for phone sharing,
which is a small web server. Nobody should have to find their way to Windows
Security settings to make a file transfer work. A copy that was allowed through
before phone sharing had its own rule is offered the fix on the Phone tab.

The CLI cannot show a permission prompt usefully, so `jet doctor` prints the
exact `netsh` command instead.

## Staying reachable

An app that must be running to receive anything has to survive the ways people
close things. Three behaviours follow from that, and each is the opposite of what
a normal window does:

- **The close button hides the window, it does not quit.** Closing means "get out
  of my way", not "make me unreachable" — and a transfer app that silently stops
  receiving because a window was closed is broken. Quitting is a deliberate,
  separate act from the tray menu. The first time a close hides the window,
  Jetstream says so; behaving this way *silently* is the version people
  reasonably find creepy.
- **Only one copy ever runs.** A second launch — Start menu, Send to, a desktop
  shortcut — reaches the copy already holding the port and shows its window,
  rather than starting a rival that cannot bind and appears broken.
- **Starting with Windows starts hidden.** An app launched by the OS at login
  should be ready to receive, not competing for attention, so there is no flash
  of window at sign-in.

**Interrupted sends retry themselves.** A send whose peer vanished is recorded,
and when that device reappears Jetstream resumes it — from the chunk it reached,
so nothing already transferred crosses the wire twice. History shows which
transfers are waiting, because a user who does not know this is happening will
retry by hand or assume the transfer is lost. It gives up after five attempts in
a row that move nothing, rather than retrying a genuinely dead transfer forever —
an attempt that gets somewhere resets the count, so a link that drops every half
hour still finishes.

The receiving side treats the next attempt as the same transfer: the same row,
the same history entry, the same folder, and — if it was interrupted rather than
stopped by someone — no second accept prompt for exactly the files it already
said yes to. Its progress picks up from what is already there.

**Devices on a VPN or another network** — Radmin, Tailscale, ZeroTier, a
different subnet — never appear by themselves, because discovery does not cross
those links. **Add by address** on the Devices tab finds one once; from then on
it is checked every few seconds and listed while it answers. A paired device with
a transfer waiting to resume is checked at its last address automatically, so
resuming across a VPN needs nothing added at all.

**Right-click → Send to → Jetstream** works from Explorer, because going to the
app first and browsing for a file you were already looking at is backwards. It is
a per-user shortcut, so unlike the firewall rule it needs no administrator
rights.

## Where the throughput came from

Every change below was made because a measurement pointed at it, and two
plausible-sounding theories were measured and discarded first — quinn's flow
control window and the MTU ceiling both turned out to be nearly irrelevant here.

- **Small files were drowning in `fsync`.** 20 ms per file, almost all of it
  waiting on durability barriers for progress bitmaps that were saving less than
  they cost. Files under 8 MiB now skip bitmap persistence entirely; their resume
  granularity becomes the whole file, which is the right granularity for
  something that re-sends in milliseconds.
- **A single-chunk file needs no whole-file hash.** For a file that fits in one
  chunk, the chunk hash *is* the file hash, and it was already verified on
  arrival. The whole-file hash exists to catch assembly errors, and one chunk has
  no assembly. Skipping it removes a round trip plus a full file read on each
  side, per file.
- **Nothing overlapped.** The receiver read a chunk, verified it, wrote it to
  disk, then read the next — network and disk taking turns. Now eight requests
  run concurrently and feed one dedicated writer thread that owns the staging
  area, so no blocking file operation ever lands on an async worker.
- **The sender reopened the file per chunk.** It now opens once per request and
  reads sequentially on a blocking thread, feeding the socket through a small
  channel so reads and sends overlap.
- **Congestion control started for the internet.** QUIC's default initial window
  is ten packets, so a transfer spent seconds ramping — most transfers are short
  enough to never leave the ramp. On a LAN a 1 MiB initial window is appropriate;
  a future relay path must *not* inherit it.

The browser path deliberately keeps chunk-level resume for every file however
small: a phone on patchy Wi-Fi is the opposite trade from a LAN peer, and losing
a 5 MB upload at 80% is the exact failure this project exists to prevent.

## The browser receiver

Devices that cannot run Jetstream — a phone, a Mac, a locked-down work laptop —
take part through their browser. Scan a QR code and you get a page that can
upload and download. No install, no account.

Uploads are **resumable**, which a plain HTML form cannot be: the browser slices
each file, computes a CRC-32 per chunk in JavaScript, and PUTs the pieces into
the same staging area the native path uses. A phone that loses signal at 80%
asks what is missing and sends only that. Downloads use HTTP `Range`, so the
browser's own download manager resumes them for free.

**The honest limits of this path**, which the UI states rather than hides:

- The connection is **plain HTTP** and unencrypted. A self-signed certificate
  would put a full-page security warning in front of every user, and telling
  people to click through security warnings is worse than the thing it fixes.
- Integrity is **CRC-32, not BLAKE3** — corruption detection, not a
  cryptographic guarantee. A page served over HTTP has no secure context, so
  `crypto.subtle` is unavailable, and it does not offer BLAKE3 anyway. On this
  path the sender *is* the user at their own phone, so there is no second party
  to authenticate; what remains worth catching is a flipped bit, and CRC-32
  catches that at hundreds of MB/s in plain JavaScript.
- It is **off until switched on**, each pairing code is **single-use** and
  expires in five minutes, and a browser guest is **prompted every time** — it
  holds no key, so there is no identity to remember. Opening the link does not
  spend the code — only the page it opens does — so a QR app or chat preview that
  fetches the link first cannot use it up. A fresh code appears by itself once
  one is used or runs out.
- It listens on every IPv4 interface, and on a machine with several networks
  the Phone tab lets you pick which one the code points at — the phone has to be
  on the same one.

Native transfers keep the full guarantee: TLS 1.3, pinned Ed25519 identity, and
BLAKE3 per chunk and per file.

## Tests

```bash
cargo test --workspace
```

Around 290 tests. The ones that matter most:

- `an_interrupted_transfer_resumes_instead_of_restarting` — kill a transfer mid-flight, reconnect, verify byte-identical output
- `resume_picks_up_from_bitmaps_written_by_a_previous_process` — resume across a process boundary
- `files_that_complete_early_are_delivered_before_an_interruption` — finished work is delivered, not just staged
- `refuses_every_way_out_of_the_destination` — 14 real path-traversal attempts, all rejected
- `connecting_to_the_wrong_device_is_refused` — identity pinning against an impersonator
- `a_manifest_that_contradicts_the_offer_is_refused` — you get what the prompt said you would
- `an_endpoint_bound_to_all_interfaces_accepts_ipv4` — Windows defaults `IPV6_V6ONLY` on, which silently made the app unreachable
- `a_decline_reaches_the_sender_even_if_the_receiver_hangs_up_at_once` — a refusal must not look like a network failure
- `an_interrupted_upload_resumes_over_http` — the browser path resumes too, over a real TCP client
- `every_endpoint_refuses_an_unpaired_client` — knowing the port is not enough
- `a_pairing_code_works_exactly_once` — a QR left on screen is not a standing invitation
- `the_single_chunk_shortcut_refuses_without_a_verified_chunk` — the fast path must never skip verification, only redundant work
- `small_files_skip_bitmap_persistence_and_restart_wholesale` — the fsync optimisation, pinned
- `only_interrupted_sends_are_retried` — a receive, a decline, or a send whose files are gone must never auto-retry
- `retries_stop_after_the_limit` — a dead transfer must not be retried forever
- `clearing_keeps_what_still_needs_retrying` — "clear finished" must not quietly cancel pending work
- `a_portable_key_is_readable_without_dpapi` — a portable identity that cannot open on the next machine is not portable
- `an_existing_key_keeps_its_wrapping_regardless_of_the_request` — plugging a drive into a second machine must not rewrite the identity on it
- `portable_mode_needs_the_folder_to_already_exist` — never invent the folder, or an installed copy silently loses its identity
- `files_delivered_before_an_interruption_count_on_resume` — a resume starts from where it really was, not from what is still staged
- `stopping_early_keeps_every_chunk_that_was_written` — an interruption keeps everything already on disk, not only the last periodic checkpoint
- `pausing_the_sender_stops_both_ends_and_the_receiver_knows_why` — pause works from the sending side, and the other side says so
- `the_sender_shows_what_arrived_not_what_it_buffered` — the sending device's progress is the receiver's, not QUIC's send buffer
- `lumpy_arrivals_do_not_swing_between_zero_and_double` — the speed shown holds still
- `an_attempt_that_moved_data_resets_the_retry_count` — a flaky link that keeps making progress keeps resuming
- `opening_the_link_does_not_spend_the_code` — a link preview cannot use up a phone's pairing code
- `an_older_peers_hello_still_decodes_without_the_new_capability` — mixed versions still talk

## License

MIT OR Apache-2.0
