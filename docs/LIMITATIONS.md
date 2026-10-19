# Limitations, Windows API constraints, and assumptions to verify

## Windows constraints (by design of the OS, not bugs)
* **Elevated windows / UAC / login / lock screen / Ctrl+Alt+Del.** A normal-integrity process cannot
  inject input into admin windows (UIPI), and nothing can reach the secure desktop. KvmShare detects the
  secure desktop and suspends routing so each computer's own devices work, but you cannot type a UAC
  password with the *other* machine's keyboard. For admin windows: `install.ps1 -Elevated` (runs at highest
  privilege; slightly larger attack surface). Lock-screen input needs a SYSTEM service: out of scope.
* `Win+L`, `Ctrl+Alt+Del`, and secure-attention sequences cannot be forwarded.
* **Games / apps using Raw Input or relative mouse capture** see absolute `SetCursorPos` moves, not raw
  deltas; many 3D games will not behave. Use the machine's own mouse.
* **Password fields:** forwarded keystrokes are ordinary injected input. Apps that reject injected input
  (some banking/anti-cheat/remote-desktop clients) will ignore them. Clipboard from password managers that
  set the exclusion flag is not synced.
* Caps/Num/Scroll lock state is not synchronised; swapped-mouse-button setups should be tested.
* Other tools that install low-level hooks (AutoHotkey, etc.) interact via hook order: the most recently
  installed hook runs first. Start KvmShare **after** them if you want their hotkeys to keep working on
  the local machine while the pointer is remote; otherwise forwarded keys never reach them.
* Per-monitor DPI is handled in physical pixels; pointer speed is 1:1 in pixels, so crossing between a
  150 % laptop and a 100 % monitor changes physical cursor speed. Use `input.pointer_speed` to taste.
* Extra mouse buttons beyond X1/X2 and high-resolution horizontal scroll are not supported.
* Precision-touchpad gestures (three-finger, pinch) are OS-level and stay local; only the pointer
  motion, taps and scroll they synthesize are forwarded.

## Not implemented (deliberately)
* Drag-and-drop of files across the screen edge (needs OLE `IDropTarget`/delayed rendering; the
  copy/paste flow covers the use case). Possible later phase.
* Mac/Linux, more than two computers, UDP fast path. TCP_NODELAY on a wired or good 5 GHz link is
  normally sufficient; a UDP path would only help under sustained Wi-Fi loss. Decide with `bench net`.

## Assumptions to verify on your hardware (`python -m kvmshare selftest` covers 1-3)
1. `SetCursorPos` lands exactly on the requested pixel on every monitor corner (mixed DPI).
2. Low-level mouse hooks are invoked for our own injected moves (used only for benchmarking; routing
   works either way thanks to the expected-position check).
3. Swallowing events in the hook leaves the parked cursor in place, so `pt - park` equals the motion
   delta. If you see drifting/jumping on the remote side, tell me which machine and I'll switch that
   path to Raw Input deltas.
4. Overlay window hides the cursor on the parked machine (`input.hide_cursor`), else the cursor simply
   rests mid-screen.
5. Precision touchpads deliver motion through the LL hook (expected: yes).
