# Performance targets and repeatable benchmark

## Realistic targets (LAN, Wi-Fi 5/6 5 GHz, same room; wired should be better)
| Metric | Target | Why / limit |
|---|---|---|
| Network RTT on input channel, p50 | < 4 ms (Wi-Fi), < 0.6 ms (wired) | physical medium |
| RTT p99 | < 15 ms Wi-Fi | Wi-Fi retries/power-save; wired < 2 ms |
| Capture-to-inject, remote path (p50) | ≈ RTT/2 + ~0.3 ms software | hook ~50 µs, coalescing 0 ms added |
| Event-to-photon (camera test) | one display frame (≈ 8-17 ms) + network | cannot beat the monitor's refresh |
| Clipboard text propagation (<32 KB) | < 25 ms | one JSON frame + OS clipboard write |
| Reconnect after Wi-Fi blip | < 1.5 s | 0.2 s backoff start + 3 s dead-peer detection otherwise |
| Idle CPU / RSS | < 1 % / < 60 MB | event-driven, no polling except a 4 Hz tick |
| CPU while moving a 1 kHz mouse | < 8 % of one core | Python hook callback |

No "native-level" claim is made: measure it.

## Built-in measurements
Run from either machine with both daemons up:
```
python -m kvmshare bench net --count 2000 --rate 1000   # RTT min/p50/p95/p99/max, jitter, loss, clock offset
python -m kvmshare bench local --count 500                # SendInput/SetCursorPos cost + injection->hook latency
python -m kvmshare bench clip --count 20 --size 20000     # clipboard send -> remote write -> ack
python -m kvmshare status                                   # histograms: rtt_ms, inject_us, reconnect_ms,
                                                            # clip_roundtrip_ms, cpu_percent, rss_mb, counters
```
* `rate 1000` mimics a 1 kHz mouse stream, so it shows how latency behaves at real event rates.
* Set `"metrics": {"stamp_moves": true}` in config on the *sending* machine; the receiver then records
  `move_oneway_ms` (capture→inject) using the NTP-style clock offset from the heartbeat
  (accuracy ≈ ± half the RTT asymmetry; treat as an estimate).
* Reconnect: unplug/replug Wi-Fi, or `Restart-Service`-style sleep/resume; `status` shows `reconnect_ms`.

## Event-to-display (end to end) with a phone
Record both screens at 240 fps while rapidly tapping a key / moving the mouse across the edge; count frames
between the physical action (LED/hand/finger on key) and the visible change on the remote screen.
Repeat 20×, report median/p95. Do it wired and on Wi-Fi.

## Wired / direct link
Gigabit Ethernet or a direct cable (set static IPs, e.g. 192.168.77.1/2, link-local addressing also
works) removes Wi-Fi jitter: expect p99 RTT < 1 ms. KvmShare uses whatever route reaches `peer_address`
or the beacon source, so a direct cable plus Wi-Fi works: set `peer_address` to the cable IP. Disable Wi-Fi
power saving on both adapters and prefer 5 GHz/6 GHz; these have more effect than anything in software.
