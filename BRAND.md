# Jetstream — logo brief

Everything here is a spec for assets that do **not** exist yet. The app
currently ships the old placeholder icon, and every reference to it is in one
place (`apps/desktop/src-tauri/icons/`), so swapping it in is a five-minute job
once the artwork exists.

---

## The idea to draw

A jet stream is a fast, narrow current high in the atmosphere that carries
things across continents. Two properties matter for the mark:

1. **It is a single continuous line.** Not a cloud, not a burst, not a network
   of nodes. One current, going somewhere.
2. **It has direction and speed.** It should read as *departed here, arriving
   there* — which is what the app does.

What to avoid, because every file-transfer app already does it: paired arrows,
a cloud with an up-arrow, two computers with a line between them, a paper
plane. Paper planes especially — the association is Wetransfer and Telegram,
and it says "message", not "the whole folder arrived intact".

## The mark

A single ribbon or stroke crossing the frame, bending as it goes, thicker where
it starts and tapering as it leaves. Think of a contrail seen from below, or the
jet stream as drawn on a weather map.

```
        ╱▔▔▔▔▔╮
   ╱▔▔▔╯       ╰────────►
```

Concretely:

- **One stroke, no second element.** The whole mark should be drawable without
  lifting the pen.
- **Left to right, rising.** Ascending reads as progress. A descending line
  reads as a fall, and no one wants that on a transfer app.
- **Taper.** Wide at the origin, narrow at the destination — or the reverse, if
  the arrival end feels more important to you. Uniform width reads as a generic
  swoosh.
- **One bend, not three.** Two curves start to look like a ribbon logo from
  2011.
- **Square canvas, generous margin.** It must survive being rendered at 16×16 in
  a Windows taskbar, which means the stroke cannot be thinner than about 1/12 of
  the canvas width.

### Test it at 16 pixels first

Not last. Draw it small, then scale up. A mark that only works at 512px is not
an app icon. At 16×16 the whole thing should still read as "a line going
somewhere fast", even if the taper disappears.

## Colour

The palette stays as it is — these are already in `styles.css` and in the app:

| Role | Hex | Where it is used |
|---|---|---|
| Primary | `#62B3C5` | identity, progress, the active state |
| Accent | `#E7507E` | decisions with a consequence — decline, block |
| Warm | `#FBB583` | caution, the firewall card |
| Base | `#0F1417` | app background (dark) |

### The same colours as text

Those three hexes are tuned for the dark background and are pale on purpose. As
**fills** — a progress bar, a button, an icon stroke — they are correct on either
theme. As small **text** on a white card they fail outright:

| | on `#161D21` | on `#FFFFFF` |
|---|---|---|
| `#62B3C5` cyan | 7.1:1 | **2.4:1** |
| `#E7507E` pink | 4.8:1 | **3.6:1** |
| `#FBB583` amber | 9.8:1 | **1.7:1** |
| `#5FC48F` green | 7.9:1 | **2.2:1** |

4.5:1 is the floor for text at these sizes, so the light theme needs its own
values. `styles.css` therefore carries a second set of tokens used *only* for
coloured text — `--on-cyan`, `--on-pink`, `--on-amber`, `--on-ok` — which equal
the brand colours on dark and darken on light to `#2A7F92`, `#B8244F`, `#96551A`,
`#2F7D52` (4.6:1 to 6.2:1, same hues).

**The rule: `--brand-*` for anything filled, `--on-*` for anything read.** Use a
brand colour directly as `color:` and it will be illegible for half the users.

For the mark, run the stroke as a **gradient along its length**, in the order
the eye travels it:

```
#62B3C5  ──────────────►  #FBB583  ──────────────►  #E7507E
  cyan at the origin        amber mid-flight        pink at arrival
```

That is not arbitrary. It is the order those three colours appear in a real
sunset sky, and it means the mark carries the whole palette without needing a
second element. It also gives you a monochrome fallback for free: the same
stroke in `#62B3C5` alone works fine.

**One icon, not two.** A dark-background version is enough — Windows renders
taskbar icons over their own chrome, and a transparent PNG with the gradient
stroke works on both light and dark. Do not draw a filled square background
unless you want the icon to look like a tile.

## Wordmark

Nova Square, uppercase, letter-spaced about `0.06em` — this is what the app
header already uses, so the logo and the running app will match:

```
JETSTREAM
```

The header currently pairs it with a small cyan dot. If you make the ribbon
mark, replace that dot with a small version of the ribbon and I will wire it in
(`apps/desktop/src/App.tsx`, the `.wordmark` block).

Nova Square is a display face — good at large sizes and in a wordmark, poor for
body text. It is deliberately used only for the app name, device names, and
numbers; everything a user actually reads is in the system font. Please keep
that split.

## What I need from you

If you want to draw it, the files to produce are:

| File | Size | Notes |
|---|---|---|
| `icon.svg` | vector | the master; everything else derives from it |
| `icon.ico` | multi | 16, 24, 32, 48, 64, 128, 256 in one file |
| `32x32.png` | 32×32 | |
| `128x128.png` | 128×128 | |
| `128x128@2x.png` | 256×256 | |
| `icon.png` | 512×512 | store listings |

Drop them in `apps/desktop/src-tauri/icons/` and I will generate any missing
sizes from the SVG.

If you would rather I take a first pass, I can produce the ribbon as inline SVG
so you have something concrete to react to — it is faster to correct a drawing
than to describe one.

## Naming, for consistency

- Product: **Jetstream** — one word, capital J only. Never "JetStream",
  "Jet Stream", or "Jetstream Drop".
- CLI binary: `jet`
- Bundle identifier: `app.jetstream.desktop`
- Data directory: `%LOCALAPPDATA%\Jetstream`
- Firewall rule name: `Jetstream` (this is user-visible in Windows Security)
