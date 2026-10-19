# KvmShare

One continuous workspace across **laptop display → desktop secondary → desktop primary**: the pointer
crosses edges by itself, keyboard follows the pointer, clipboard and files follow you. Windows ↔ Windows,
LAN only, no cloud, no relay, nothing leaves your network.

> **Status / honesty note.** The portable core (topology, routing state machine, protocol, TLS pairing,
> session/reconnect, clipboard sync, file transfer) is covered by 36 automated tests, plus an
> end-to-end two-daemon run. The Windows layer (`win32.py`, `winio.py`, `winclip.py`) was written without
> access to Windows hardware and has **not been executed yet**. Run `python -m kvmshare selftest` on both
> machines first; it checks the OS assumptions this design relies on (see *Assumptions to verify*).

## Quick start

On both computers (Python 3.10+):
```powershell
cd kvmshare
powershell -ExecutionPolicy Bypass -File install\install.ps1      # venv + firewall (private/LocalSubnet only) + logon task
& $env:LOCALAPPDATA\KvmShare\venv\Scripts\python.exe -m kvmshare selftest
```
Pair once (explicit approval on both screens, one-time code):
```powershell
# desktop
python -m kvmshare pair --host --role desktop        # shows a 6-digit code
# laptop
python -m kvmshare pair --join                        # finds the host, asks for the code
```
Start: `Start-ScheduledTask KvmShare` (or `python -m kvmshare run`). Then just move the mouse right.
In Windows Display Settings the desktop's secondary monitor must sit **left** of the primary.

Useful commands: `status`, `reclaim`, `privacy on|off`, `feature input|clipboard|files on|off`,
`devices`, `revoke <name>`, `transfers`, `accept <id>`, `cancel <id>`, `bench net|local|clip`.

## How it works

One logical pointer, owned by exactly one machine at a time (`router.py`).

* The owner's devices act natively (hooks pass events through). The *other* machine is in forward mode:
  its low-level hooks swallow local mouse/keyboard events, park and hide its cursor, and send them to the
  owner, which injects them. This is symmetric, so the laptop trackpad, a mouse on either machine, and
  either keyboard all drive whichever screen the pointer is on. No duplicated clicks: an event is either
  handled locally or forwarded, never both.
* Ownership moves with `ENTER(epoch+1, x, y)` when the pointer reaches a managed edge. The epoch is a fencing
  token: input carrying a stale epoch is dropped, so handoffs cannot double-inject or loop.
* Injected events are tagged (`dwExtraInfo` marker plus an "injecting" flag), so our own hooks never
  re-forward them.
* The owner tracks the pointer in software when driven remotely, and crossing uses the real clamped
  position when driven locally. Native seams (secondary→primary on the desktop) are left to Windows.
* Edge mapping (`topology.py`): proportional along the edge by default (no dead zones, corners clamp),
  or `top` / `center` / `physical` (DPI-aware) alignment with pixel offsets. Everything is derived from
  detected monitor rectangles and DPI; nothing is hard-coded. Display changes re-resolve the layout live.
* Stuck-key protection: keys are owned by the side that saw the key-down. Pressed-before-handoff keys
  release locally; forwarded keys are released on the peer on handoff, disconnect, or a 3.5 s heartbeat
  timeout. Link loss immediately returns local control and releases everything.
* Reclaim: `Ctrl+Alt+Shift+F12` on either keyboard (or `kvmshare reclaim`) takes the pointer back
  unconditionally. Secure desktop (UAC, lock screen) is detected: routing suspends and each machine
  falls back to its own devices automatically.

Transport: TLS 1.3 with mutual certificate pinning. Persistent `input` connection (TCP_NODELAY, binary
fixed-size frames, per-sender sequence numbers, adaptive coalescing: the first event leaves immediately,
motion that piles up while the loop is busy is merged into one frame). Bulk data (large clipboard, files)
uses separate on-demand connections so it can never queue in front of a mouse move. Reconnect uses
backoff + beacons; sleep/resume forces a fast reconnect.

## Clipboard
Text (Unicode, multiline, up to 64 MB), HTML, RTF and images (DIB) sync both ways. Lamport versions prevent
stale overwrites; content hash + OS sequence number prevent echo loops. Unsupported formats (OLE objects,
app-private) are reported by name, never silently dropped. Content is never logged. Apps that flag
clipboard data as sensitive (`ExcludeClipboardContentFromMonitorProcessing`, e.g. password managers) are
skipped. `privacy on` / `Ctrl+Alt+Shift+F11` pauses both directions.

## Files
Copy files/folders on one machine → an offer (counts/sizes) reaches the other → the receiver pulls over its
own TLS connection into a **new per-transfer folder** under `files.inbox` (default `Downloads\KvmShare`),
verifies SHA-256, preserves names/structure/mtime/read-only, resumes after interruption, and then places the
staged files on its clipboard, so a normal **Ctrl+V in Explorer pastes them**. Offers above
`auto_stage_max_mb` (256) wait for `kvmshare accept <id>`. Nothing is ever executed or overwritten; paths
from the peer are validated (no `..`, drive letters, ADS, reserved names, symlink/junction skipping).
`files.max_rate_mbps` caps bulk traffic if Wi-Fi latency suffers during big copies. Drag-and-drop across
the screen edge is deliberately not included (see LIMITATIONS).

## Configuration
`%LOCALAPPDATA%\KvmShare\config.json` (only overrides). Example, a custom link with a vertical offset:
```json
{ "topology": { "screens": [
    {"id":"laptop","machine":"laptop","select":"primary"},
    {"id":"desk-secondary","machine":"desktop","select":"index:0"},
    {"id":"desk-primary","machine":"desktop","select":"primary"}],
  "order": ["laptop","desk-secondary","desk-primary"],
  "links": [{"a":"laptop","a_side":"right","b":"desk-secondary","b_side":"left","align":"physical","offset":-40},
            {"a":"desk-secondary","a_side":"right","b":"desk-primary","b_side":"left"}]},
  "input": {"switch_cooldown_ms": 150, "pointer_speed": 1.0, "key_mode": "vk"},
  "files": {"inbox": "D:\\Transfers", "max_rate_mbps": 200},
  "peer_address": "192.168.1.20" }
```
Monitor selectors: `primary`, `secondary`, `leftmost`, `rightmost`, `index:N` (left→right), `device:\\.\DISPLAY2`.

## Security model
* Pairing: one-time 6-digit code through **SPAKE2** (a PAKE), so the code can't be brute-forced offline;
  an attacker gets one online guess and the host burns the code. The confirmation MAC binds both device
  certificates and the TLS certificate actually seen (man-in-the-middle detection). Explicit `y/N`
  approval on both machines showing the certificate fingerprint.
* After pairing: mutual TLS 1.3, only the pinned certificates are trusted; every connection is re-checked
  against the paired list (so `revoke` takes effect immediately and drops the live link).
  Private keys are encrypted at rest; the passphrase is DPAPI-protected (per Windows user).
* Network exposure: firewall rules limited to Private profile + LocalSubnet; the code additionally refuses
  non-private source addresses. Control API and air-mouse socket listen on 127.0.0.1 with secrets.
* Hardening: frame size limits, token-bucket rate limiting, handshake/idle timeouts, delta clamps, hello
  identity binding, strict manifest validation, no content logging. No keylogging: key events exist only
  in memory long enough to be forwarded.
* Independent switches: `feature clipboard off`, `feature files off`, `feature input off`.

## Air mouse
Firmware untouched. Replace only the final `pyautogui` call in your Python script with
`integrations/airmouse_adapter.py` (`sink.move(dx, dy)`; falls back to pyautogui if KvmShare isn't running).
It then crosses screens like any pointer.

## Tests
`python -m pytest tests -q`: topology (corners, mixed DPI/height, offsets, bad arrangements), router
simulation (handoff, epochs, stuck keys, reclaim, secure desktop), protocol fuzz-ish cases, PAKE pairing
(right/wrong code, decline), mutual-TLS session (coalescing, drop+reconnect, revocation), clipboard
(unicode, 6 MB, stale, privacy, limits), file transfer (tree, resume, hostile manifests).

See `docs/LIMITATIONS.md` and `docs/BENCHMARKING.md`.
