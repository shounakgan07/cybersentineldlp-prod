"""
Linux Screen Capture / Recording / Sharing Monitor

Linux port of the Windows agent's ScreenCaptureMonitor
(agents/endpoint/windows/screen_capture_monitor.cpp / .h). Mirrors its
architecture and decision model as closely as the two platforms allow:

    * process_monitor_thread  -> psutil-based detection of screenshot,
      screen-recording and screen-sharing applications (the Linux
      equivalent of Windows' ProcessMonitorThread / TerminateProcessByName).
    * content_scan_thread     -> periodic screenshot + OCR classification
      that maintains ``self.screen_is_sensitive`` (the Linux equivalent of
      Windows' ContentScanThread / m_screenIsSensitive).
    * keyboard_monitor_thread -> evdev-based detection of PrintScreen-style
      shortcuts (the Linux equivalent of Windows' low-level keyboard hook).

Platform differences from the Windows implementation, and why:

    * Windows installs a low-level keyboard HOOK that can literally swallow
      the PrintScreen keystroke before the OS acts on it. There is no
      equivalent portable, unprivileged mechanism on Linux: doing the same
      thing here would mean exclusively grabbing every input device
      (evdev `grab()`) and re-injecting every non-blocked key through a
      virtual `uinput` device -- i.e. turning this module into a
      general-purpose system-wide keystroke interceptor/injector. That is
      a much bigger (and much more dangerous, dual-use) capability than a
      DLP screenshot filter needs, so this port deliberately does not do
      it. Instead, the keyboard thread *detects and logs* the shortcut
      (as requested) and, in Protection Mode, triggers an immediate
      reactive sweep of the process list so that any screenshot/recording
      tool the shortcut just spawned is killed within one poll cycle.
      The process-monitor layer is the real enforcement mechanism; the
      keyboard layer is a fast detector, exactly as documented in
      _handle_keyboard_shortcut() below.
    * Windows timestamps hardcode an IST offset. The rest of this Linux
      agent (agent.py, print_monitor.py) uses naive UTC ISO-8601 timestamps,
      so this module does the same for consistency with the existing
      pipeline/server rather than copying the Windows quirk.
    * Active-window and screenshot capture require X11. Both are no-ops
      (with a one-time log message, not a crash) under Wayland, where no
      portable API exists for either. Process/keyboard/OCR-of-last-frame
      detection still function; see README for the Wayland limitation.

This module intentionally has no knowledge of *how* events reach the
DLP server -- it only ever calls the ``event_callback`` it was given.
See agent.py's ``handle_screen_capture_event`` for how the Linux agent
wires these events into ``DLPAgent.send_event()``.
"""

import os
import time
import logging
import shutil
import threading
import subprocess
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import psutil

try:
    from PIL import Image, ImageGrab
    PIL_AVAILABLE = True
except ImportError:
    Image = None
    ImageGrab = None
    PIL_AVAILABLE = False

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    pytesseract = None
    TESSERACT_AVAILABLE = False

try:
    from Xlib import X
    from Xlib import display as xlib_display
    from Xlib.error import XError
    XLIB_AVAILABLE = True
except ImportError:
    X = None
    xlib_display = None
    XError = Exception
    XLIB_AVAILABLE = False

try:
    import evdev
    from evdev import ecodes
    EVDEV_AVAILABLE = True
except ImportError:
    evdev = None
    ecodes = None
    EVDEV_AVAILABLE = False

logger = logging.getLogger("dlp-agent.screen-capture")


# â”€â”€â”€ Classification levels (match CLASSIFICATION_SYSTEM.md) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

CLASSIFICATION_PUBLIC = "Public"
CLASSIFICATION_INTERNAL = "Internal"
CLASSIFICATION_CONFIDENTIAL = "Confidential"
CLASSIFICATION_RESTRICTED = "Restricted"

# Screenshots/recording/sharing are only blocked for these two levels,
# matching the Windows m_classifier check:
#   nowSensitive = (classification == "Restricted" || classification == "Confidential")
SENSITIVE_CLASSIFICATIONS = {CLASSIFICATION_CONFIDENTIAL, CLASSIFICATION_RESTRICTED}

_CLASSIFICATION_RANK = {
    CLASSIFICATION_PUBLIC: 0,
    CLASSIFICATION_INTERNAL: 1,
    CLASSIFICATION_CONFIDENTIAL: 2,
    CLASSIFICATION_RESTRICTED: 3,
}

# Keyword -> classification level. Matched case-insensitively against the
# active window title plus any OCR'd screen text. When several keywords
# match, the highest-ranked classification wins.
DEFAULT_SENSITIVE_KEYWORDS: Dict[str, str] = {
    "restricted": CLASSIFICATION_RESTRICTED,
    "secret": CLASSIFICATION_RESTRICTED,
    "aadhaar": CLASSIFICATION_RESTRICTED,
    "credit card": CLASSIFICATION_RESTRICTED,
    "bank account": CLASSIFICATION_RESTRICTED,
    "confidential": CLASSIFICATION_CONFIDENTIAL,
    "salary": CLASSIFICATION_CONFIDENTIAL,
    "password": CLASSIFICATION_CONFIDENTIAL,
    "pan": CLASSIFICATION_CONFIDENTIAL,
    "internal": CLASSIFICATION_INTERNAL,
}


# â”€â”€â”€ Known capture / recording / sharing applications â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

SCREENSHOT_PROCESSES: Set[str] = {
    "flameshot", "gnome-screenshot", "gnome-screenshot-service",
    "spectacle", "shutter", "ksnip", "xfce4-screenshooter",
}

RECORDING_PROCESSES: Set[str] = {
    "obs", "obs64", "simplescreenrecorder", "kazam", "peek",
    "vokoscreen", "vokoscreenng", "green-recorder", "recordmydesktop",
}

# NOTE on false positives: these are matched by process name alone, i.e.
# "the app is running", not "the app is actively sharing your screen right
# now". For a video-call app that's a real limitation -- opening Zoom/Teams
# for an audio-only call, with no screen share started, will still trigger
# this. Reliably detecting "currently sharing" (vs. just "open") would need
# per-app integration (each vendor exposes this differently, if at all) and
# is out of scope for a process-name-based monitor; flagging this so it's
# an informed tradeoff rather than a silent gap.
SHARING_PROCESSES: Set[str] = {
    "zoom", "teams", "teams-for-linux", "teams-insiders", "anydesk",
    "teamviewer", "rustdesk", "chrome-remote-desktop", "remotedesktop",
    "discord", "skype", "webex",
}

# Some tools (vlc, ffmpeg) are legitimate for a huge range of everyday use
# and only become a screen-recording concern when invoked with a screen
# capture source. Detected via a cheap command-line substring check rather
# than blanket process-name matching, to avoid false positives on normal
# media playback / transcoding.
RECORDING_CMDLINE_MARKERS: Dict[str, Tuple[str, ...]] = {
    "ffmpeg": ("x11grab", "-f x11grab"),
    "vlc": ("screen://", "--screen"),
}

# Human-friendly display names for event "method"/"processName" fields.
_DISPLAY_NAMES: Dict[str, str] = {
    "obs": "OBS", "obs64": "OBS", "gnome-screenshot": "GNOME Screenshot",
    "gnome-screenshot-service": "GNOME Screenshot", "flameshot": "Flameshot",
    "spectacle": "Spectacle", "shutter": "Shutter", "ksnip": "Ksnip",
    "xfce4-screenshooter": "Xfce Screenshooter", "kazam": "Kazam",
    "peek": "Peek", "simplescreenrecorder": "SimpleScreenRecorder",
    "vokoscreen": "VokoscreenNG", "vokoscreenng": "VokoscreenNG",
    "green-recorder": "Green Recorder", "recordmydesktop": "RecordMyDesktop",
    "zoom": "Zoom", "teams": "Microsoft Teams",
    "teams-for-linux": "Microsoft Teams", "teams-insiders": "Microsoft Teams",
    "anydesk": "AnyDesk", "teamviewer": "TeamViewer", "rustdesk": "RustDesk",
    "chrome-remote-desktop": "Chrome Remote Desktop",
    "remotedesktop": "Chrome Remote Desktop", "ffmpeg": "ffmpeg",
    "vlc": "VLC", "discord": "Discord", "skype": "Skype", "webex": "Webex",
}


def _display_name(process_name: str) -> str:
    """Return a human-friendly name for a known process, else the raw name."""
    return _DISPLAY_NAMES.get(process_name, process_name)


# GNOME screenshot keybindings that actually trigger the OS-level screenshot
# action (as opposed to third-party tools, which bind their own hotkeys
# outside of gsettings and are instead handled by process termination).
# Clearing these to an empty array makes PrintScreen / Shift+PrintScreen /
# etc. do nothing at the shell level -- no screenshot is taken, no file is
# written -- without grabbing the input device or touching any other key.
GNOME_SCREENSHOT_KEYBINDING_SCHEMAS: Tuple[Tuple[str, str], ...] = (
    ("org.gnome.shell.keybindings", "screenshot"),
    ("org.gnome.shell.keybindings", "screenshot-window"),
    ("org.gnome.shell.keybindings", "show-screenshot-ui"),
    ("org.gnome.settings-daemon.plugins.media-keys", "screenshot"),
    ("org.gnome.settings-daemon.plugins.media-keys", "screenshot-clip"),
    ("org.gnome.settings-daemon.plugins.media-keys", "area-screenshot"),
    ("org.gnome.settings-daemon.plugins.media-keys", "area-screenshot-clip"),
    ("org.gnome.settings-daemon.plugins.media-keys", "window-screenshot"),
    ("org.gnome.settings-daemon.plugins.media-keys", "window-screenshot-clip"),
)


ClassifierCallback = Callable[[str, str], str]
EventCallback = Callable[[Dict[str, Any]], None]


# Standalone script run as a short-lived child process to paint a
# full-screen black overlay with a centered warning message. Run
# out-of-process (rather than embedding a Tk mainloop directly in this
# module/thread) so its lifecycle is a plain subprocess we can
# start/terminate, with no risk of Tk's mainloop threading quirks
# affecting the monitor's own daemon threads.
#
# Deliberately does NOT grab keyboard/mouse input or set any "always on
# top, unclosable" tricks beyond -topmost: it is a visual block, not an
# input lock. See _engage_blackout()'s docstring for why.
#
# The message to display is passed as argv[1] so different call sites
# (keyboard shortcut vs. process termination) can show a tailored line.
DEFAULT_BLACKOUT_MESSAGE = "Taking Screenshot is blocked by CyberSentinel DLP"

_BLACKOUT_OVERLAY_SCRIPT = """
import sys
import tkinter as tk

message = sys.argv[1] if len(sys.argv) > 1 else "Blocked by CyberSentinel DLP"

try:
    root = tk.Tk()
    root.configure(bg="black")
    try:
        root.attributes("-fullscreen", True)
    except Exception:
        root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}+0+0")
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    root.overrideredirect(True)

    label = tk.Label(
        root, text=message, fg="white", bg="black",
        font=("Sans", 28, "bold"), wraplength=root.winfo_screenwidth() - 120,
        justify="center",
    )
    label.place(relx=0.5, rely=0.5, anchor="center")

    root.mainloop()
except Exception as exc:
    print(f"blackout overlay failed: {exc}", file=sys.stderr)
    sys.exit(1)
"""


class ScreenCaptureMonitor:
    """
    Detects (and, in Protection Mode, actively disrupts) unauthorized
    screenshots, screen recordings and screen sharing of sensitive
    content on Linux endpoints.

    Detection layers (independent of one another, matching the Windows
    design so no single bypass -- menu, CLI, D-Bus, browser API -- defeats
    the monitor):

        1. Keyboard shortcut detection (evdev)
        2. Process monitoring (psutil)
        3. Active window monitoring (python-xlib, X11 only)
        4. OCR-based content classification (pytesseract)
        5. Screen recording process detection
        6. Screen sharing process detection

    Operating modes:
        "monitor"    -- detect and log/alert only, never terminate anything.
        "protection" -- detect AND actively terminate offending processes
                        when sensitive content is on screen.

    Args:
        event_callback: Called with a dict for every detected event. See
            ``_build_event`` for the schema.
        classifier: Optional override for classification. Must match the
            signature ``(window_title, process_name) -> classification_str``
            where classification_str is one of Public/Internal/
            Confidential/Restricted. If omitted, the monitor performs its
            own screenshot + OCR + keyword based classification.
        mode: "monitor" or "protection".
        process_poll_interval: Seconds between process-list scans.
        title_scan_interval: Seconds between *fast* window-title checks
            (no screenshot/OCR -- just a string match). This is what
            keyboard-shortcut and process-detection blocking react to, so
            keep this short (default 1s); it's cheap.
        content_scan_interval: Seconds between *slow* screenshot+OCR
            content scans, run on a separate decoupled thread so a slow
            OCR pass (which can take anywhere from under a second to tens
            of seconds depending on hardware) never delays the fast
            title-based reaction path.
        sensitive_keywords: Optional override/extension of
            DEFAULT_SENSITIVE_KEYWORDS.
        popup_cooldown_seconds: Minimum gap between "blocked" log/alert
            entries for repeated keyboard shortcut presses, so mashing
            PrintScreen doesn't flood the log (mirrors the Windows
            m_lastPopupMs cooldown).
    """

    def __init__(
        self,
        event_callback: Optional[EventCallback] = None,
        classifier: Optional[ClassifierCallback] = None,
        mode: str = "monitor",
        process_poll_interval: float = 2.0,
        title_scan_interval: float = 1.0,
        content_scan_interval: float = 5.0,
        sensitive_keywords: Optional[Dict[str, str]] = None,
        popup_cooldown_seconds: float = 3.0,
    ) -> None:
        self.event_callback = event_callback
        self._external_classifier = classifier
        self.mode = mode if mode in ("monitor", "protection") else "monitor"
        self.process_poll_interval = process_poll_interval
        self.title_scan_interval = title_scan_interval
        self.content_scan_interval = content_scan_interval
        self.sensitive_keywords = dict(sensitive_keywords or DEFAULT_SENSITIVE_KEYWORDS)
        self.popup_cooldown_seconds = popup_cooldown_seconds

        self._running = False
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()

        # Read by the fast keyboard-shortcut/process-detection path exactly
        # like Windows' m_screenIsSensitive. Kept up to date by merging
        # the fast title-based classification with the slower OCR-based
        # one -- see _recompute_effective_classification().
        self.screen_is_sensitive: bool = False
        self._current_classification: str = CLASSIFICATION_PUBLIC
        self._title_classification: str = CLASSIFICATION_PUBLIC
        self._ocr_classification: str = CLASSIFICATION_PUBLIC

        self._known_screenshot_pids: Set[int] = set()
        self._known_recording_pids: Set[int] = set()
        self._known_sharing_pids: Set[int] = set()

        # Full-screen black overlay (defense-in-depth: covers the screen
        # while a capture attempt is in progress / while sensitive content
        # is being actively recorded or shared). See _engage_blackout().
        self._blackout_lock = threading.Lock()
        self._blackout_reasons: Set[str] = set()
        self._blackout_process: Optional[subprocess.Popen] = None

        self._last_alert_monotonic: float = 0.0

        self._xlib_display = None
        self._is_wayland = self._detect_wayland()
        self._logged_no_display = False

        # OS-level screenshot-shortcut suppression (GNOME only, Protection
        # Mode only). See GNOME_SCREENSHOT_KEYBINDING_SCHEMAS above.
        self._is_gnome = "GNOME" in os.environ.get("XDG_CURRENT_DESKTOP", "").upper()
        self._gsettings_available = shutil.which("gsettings") is not None
        self._notify_send_available = shutil.which("notify-send") is not None
        self._keybindings_suppressed = False
        self._saved_keybindings: Dict[Tuple[str, str], str] = {}

        if self._is_wayland:
            logger.warning(
                "WAYLAND_SESSION_DETECTED: active-window lookup and "
                "screenshot/OCR classification are unavailable under "
                "Wayland (no portable API for either). Process, keyboard "
                "shortcut, and recording/sharing-app detection still run "
                "normally; content classification will default to '%s' "
                "until a window/screenshot-capable session is available.",
                CLASSIFICATION_PUBLIC,
            )
        elif not os.environ.get("DISPLAY"):
            logger.warning(
                "NO_DISPLAY_DETECTED: $DISPLAY is not set. Active-window "
                "lookup and OCR-based content classification will be "
                "skipped until a display is available."
            )

        if not PIL_AVAILABLE:
            logger.warning("Pillow not installed â€” screenshot-based OCR content scanning disabled")
        if not TESSERACT_AVAILABLE:
            logger.warning("pytesseract not installed â€” OCR content scanning disabled")
        if not XLIB_AVAILABLE:
            logger.warning("python-xlib not installed â€” active window detection disabled")
        if not EVDEV_AVAILABLE:
            logger.warning("evdev not installed â€” keyboard shortcut detection disabled")

        if self.mode == "protection":
            if self._is_gnome and self._gsettings_available:
                logger.info(
                    "GNOME + gsettings detected â€” Protection Mode will disable the "
                    "OS-level screenshot keybindings (PrintScreen etc.) while "
                    "sensitive content is on screen, in addition to terminating "
                    "capture/recording/sharing tool processes."
                )
            else:
                logger.warning(
                    "gsettings/GNOME not detected â€” OS-level PrintScreen keybinding "
                    "suppression is unavailable on this desktop environment. "
                    "Protection Mode will still terminate detected capture/"
                    "recording/sharing tool processes, but the built-in "
                    "PrintScreen action itself cannot be disabled here. Note: "
                    "even on GNOME, a screenshot triggered directly via D-Bus "
                    "(org.gnome.Shell.Screenshot) rather than the keybinding, or "
                    "any third-party tool with its own independent hotkey, is not "
                    "covered by keybinding suppression -- those still rely on "
                    "process-based detection/termination."
                )

            if self._is_wayland:
                logger.warning(
                    "Wayland session detected â€” the black-screen overlay is "
                    "skipped rather than attempted, since fullscreen-always-on-"
                    "top behavior is compositor-dependent and unreliable under "
                    "Wayland/XWayland. Process termination and keybinding "
                    "suppression (X11 only) remain the enforcement mechanisms."
                )
            else:
                logger.info(
                    "Protection Mode will show a full-screen black overlay "
                    "(requires python3-tk) the moment a screenshot attempt is "
                    "detected, and for as long as a screen-recording/sharing "
                    "tool remains active while sensitive content is on screen. "
                    "Note: the overlay is a visual block only â€” it does not "
                    "grab keyboard/mouse input, so it is a deterrent/"
                    "compensating control, not an unbypassable lock."
                )

            if not self._notify_send_available:
                logger.warning(
                    "notify-send not found â€” desktop notification bubbles for "
                    "blocked capture attempts are disabled (the on-overlay "
                    "message and log/event alerts are unaffected). Install "
                    "libnotify-bin to enable it."
                )

    # â”€â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def start(self) -> None:
        """Start all monitoring threads as daemon threads."""
        if self._running:
            return
        self._running = True

        self._threads = [
            threading.Thread(target=self.process_monitor_thread, daemon=True,
                              name="scm-process-monitor"),
            threading.Thread(target=self.content_scan_thread, daemon=True,
                              name="scm-title-scan"),
            threading.Thread(target=self.ocr_scan_thread, daemon=True,
                              name="scm-ocr-scan"),
            threading.Thread(target=self.keyboard_monitor_thread, daemon=True,
                              name="scm-keyboard-monitor"),
        ]
        for t in self._threads:
            t.start()

        logger.info("Monitor started (mode=%s)", self.mode)

    def stop(self) -> None:
        """Signal all monitoring threads to stop and join them."""
        if not self._running:
            return
        self._running = False

        for t in self._threads:
            try:
                t.join(timeout=10)
            except Exception as exc:
                logger.error("Error joining thread %s: %s", t.name, exc)
        self._threads = []

        # Safety net: never leave the user's screenshot shortcuts disabled,
        # or the screen blacked out, if the monitor stops (or crashes)
        # while suppression/blackout was active.
        self._restore_screenshot_keybindings()
        with self._blackout_lock:
            self._blackout_reasons.clear()
            proc = self._blackout_process
            self._blackout_process = None
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        logger.info("Monitor stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def _sleep_interruptible(self, seconds: float) -> None:
        """Sleep in small increments so stop() takes effect quickly."""
        deadline = time.monotonic() + max(seconds, 0.0)
        while self._running and time.monotonic() < deadline:
            time.sleep(0.1)

    # â”€â”€â”€ Wayland / X11 helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def _detect_wayland() -> bool:
        session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
        if session_type == "wayland":
            return True
        if os.environ.get("WAYLAND_DISPLAY"):
            return True
        return False

    def _get_active_window(self) -> Tuple[str, str]:
        """
        Return (window_title, process_name) of the active X11 window.
        Returns ("", "") gracefully on Wayland or any X11 error â€” never
        raises.
        """
        if self._is_wayland or not XLIB_AVAILABLE:
            return "", ""

        try:
            if self._xlib_display is None:
                self._xlib_display = xlib_display.Display()

            root = self._xlib_display.screen().root
            net_active = self._xlib_display.intern_atom("_NET_ACTIVE_WINDOW")
            prop = root.get_full_property(net_active, X.AnyPropertyType)
            if not prop or not prop.value:
                return "", ""

            window_id = prop.value[0]
            window = self._xlib_display.create_resource_object("window", window_id)

            title = self._read_window_title(window)
            pid = self._read_window_pid(window)
            process_name = ""
            if pid:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    process_name = ""

            return title, process_name

        except (XError, OSError, Exception) as exc:
            logger.debug("Active window lookup failed: %s", exc)
            # Reset the display handle; a fresh Display() on the next call
            # recovers from a dropped X11 connection instead of wedging.
            self._xlib_display = None
            return "", ""

    def _read_window_title(self, window) -> str:
        try:
            net_wm_name = self._xlib_display.intern_atom("_NET_WM_NAME")
            utf8_string = self._xlib_display.intern_atom("UTF8_STRING")
            prop = window.get_full_property(net_wm_name, utf8_string)
            if prop and prop.value:
                value = prop.value
                return value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
        except Exception:
            pass
        try:
            wm_name = window.get_wm_name()
            if wm_name:
                return wm_name if isinstance(wm_name, str) else wm_name.decode("utf-8", errors="ignore")
        except Exception:
            pass
        return ""

    def _read_window_pid(self, window) -> Optional[int]:
        try:
            net_wm_pid = self._xlib_display.intern_atom("_NET_WM_PID")
            prop = window.get_full_property(net_wm_pid, X.AnyPropertyType)
            if prop and prop.value:
                return int(prop.value[0])
        except Exception:
            pass
        return None

    # â”€â”€â”€ OCR content scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _capture_screenshot(self):
        """Grab the current screen via Pillow. Returns None on any failure."""
        if self._is_wayland or not PIL_AVAILABLE:
            return None
        try:
            return ImageGrab.grab()
        except Exception as exc:
            logger.debug("Screenshot capture failed: %s", exc)
            return None

    def _run_ocr(self, image) -> str:
        """Run OCR on a captured screenshot. Returns "" on any failure."""
        if not TESSERACT_AVAILABLE or image is None:
            return ""
        try:
            text = pytesseract.image_to_string(image) or ""
            logger.debug("OCR completed (%d chars extracted)", len(text))
            return text
        except Exception as exc:
            logger.debug("OCR failed: %s", exc)
            return ""

    def _classify_text(self, text: str) -> str:
        """Classify raw text against the sensitive keyword table."""
        text_lower = (text or "").lower()
        best = CLASSIFICATION_PUBLIC
        for keyword, level in self.sensitive_keywords.items():
            if keyword in text_lower and _CLASSIFICATION_RANK[level] > _CLASSIFICATION_RANK[best]:
                best = level
        return best

    def _get_effective_classification(self, window_title: str = "", process_name: str = "") -> str:
        """
        Return the current classification for keyboard/process-detection
        handlers to act on.

        If an external classifier was supplied at construction time, it is
        called fresh every time (matching Windows' SetClassifier()
        extension point), so a caller can plug in a more sophisticated,
        policy-aware classifier without touching this module.

        Otherwise, returns the already-computed effective classification
        maintained by content_scan_thread (fast, title-based) and
        ocr_scan_thread (slower, screenshot+OCR-based) -- see
        _recompute_effective_classification(). This is deliberately a
        cheap read, not a fresh screenshot+OCR call: running OCR
        synchronously on every keypress/process detection would stall
        the calling thread for however long OCR takes (which, on modest
        hardware, can be tens of seconds -- exactly the bug that made
        earlier testing look like the block "wasn't working": a slow
        synchronous OCR call was leaving screen_is_sensitive stale for
        a full cycle).
        """
        if self._external_classifier is not None:
            try:
                return self._external_classifier(window_title, process_name)
            except Exception as exc:
                logger.error("External classifier raised an exception: %s", exc)
                return CLASSIFICATION_PUBLIC

        with self._lock:
            return self._current_classification

    def _recompute_effective_classification(self, title_for_log: str = "") -> None:
        """
        Merge the fast title-based classification with the slower OCR-based
        classification (whichever is more severe wins) into
        self._current_classification / self.screen_is_sensitive, and react
        to any sensitive/non-sensitive transition. Called by both
        content_scan_thread (every title_scan_interval) and
        ocr_scan_thread (every content_scan_interval) after each updates
        its half of the picture.
        """
        with self._lock:
            title_class = self._title_classification
            ocr_class = self._ocr_classification
            effective = title_class if _CLASSIFICATION_RANK[title_class] >= _CLASSIFICATION_RANK[ocr_class] else ocr_class
            was_sensitive = self.screen_is_sensitive
            self.screen_is_sensitive = effective in SENSITIVE_CLASSIFICATIONS
            self._current_classification = effective
            now_sensitive = self.screen_is_sensitive

        if now_sensitive and not was_sensitive:
            logger.warning(
                "SCREEN_CONTEXT_SENSITIVE: %s content on screen â€” "
                "screenshots/recording/sharing will be %s | window=%r",
                effective,
                "blocked" if self.mode == "protection" else "alerted",
                title_for_log,
            )
            if self.mode == "protection":
                self._suppress_screenshot_keybindings()
        elif not now_sensitive and was_sensitive:
            logger.info("SCREEN_CONTEXT_CLEAR: foreground no longer sensitive | window=%r", title_for_log)
            if self.mode == "protection":
                self._restore_screenshot_keybindings()

        self._update_continuous_blackout()

    def content_scan_thread(self) -> None:
        """
        FAST loop: re-classify the active window's *title* only (no
        screenshot, no OCR -- just a string match, effectively instant)
        and keep ``self.screen_is_sensitive`` current. This is the
        fast-path flag that the keyboard-monitor thread reads, so a
        block reacts in ~title_scan_interval seconds regardless of how
        long OCR takes. See ocr_scan_thread() for the slower, deeper
        content check that supplements this one.
        """
        while self._running:
            try:
                title, _process_name = self._get_active_window()
                title_class = self._classify_text(title)
                with self._lock:
                    self._title_classification = title_class
                self._recompute_effective_classification(title)
            except Exception as exc:
                logger.error("Title scan error: %s", exc)

            self._sleep_interruptible(self.title_scan_interval)

    def ocr_scan_thread(self) -> None:
        """
        SLOW loop: take a screenshot and run OCR on it every
        content_scan_interval seconds, and fold the result into the
        effective classification (escalating it if OCR finds sensitive
        text the window title alone didn't reveal -- e.g. a generically
        named file whose *contents* are confidential).

        Deliberately decoupled from content_scan_thread's fast loop: OCR
        can legitimately take anywhere from under a second to tens of
        seconds depending on hardware/VM performance, and must never
        block the fast title-based reaction path.
        """
        if self._external_classifier is not None:
            logger.info(
                "External classifier supplied â€” internal OCR content-scan "
                "thread will not run (the classifier is responsible for "
                "its own content inspection)"
            )
            return

        while self._running:
            try:
                title, _process_name = self._get_active_window()
                image = self._capture_screenshot()
                ocr_text = self._run_ocr(image) if image is not None else ""
                ocr_class = self._classify_text(ocr_text)

                with self._lock:
                    self._ocr_classification = ocr_class

                if ocr_class in SENSITIVE_CLASSIFICATIONS:
                    logger.warning("SENSITIVE_CONTENT_DETECTED (OCR): classification=%s window=%r",
                                   ocr_class, title)

                self._recompute_effective_classification(title)
            except Exception as exc:
                logger.error("OCR content scan error: %s", exc)

            self._sleep_interruptible(self.content_scan_interval)

    # â”€â”€â”€ Process monitoring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _categorize_process(self, name: str, cmdline_str: str) -> Optional[str]:
        """Return 'screenshot' | 'recording' | 'sharing' | None for a process."""
        if name in SCREENSHOT_PROCESSES:
            return "screenshot"
        if name in RECORDING_PROCESSES:
            return "recording"
        markers = RECORDING_CMDLINE_MARKERS.get(name)
        if markers and any(marker in cmdline_str for marker in markers):
            return "recording"
        if name in SHARING_PROCESSES:
            return "sharing"
        return None

    def process_monitor_thread(self) -> None:
        """Continuously scan running processes for capture/recording/sharing tools."""
        while self._running:
            try:
                current: Dict[str, Dict[int, str]] = {
                    "screenshot": {}, "recording": {}, "sharing": {},
                }

                for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        name = (proc.info.get("name") or "").lower()
                        cmdline = proc.info.get("cmdline") or []
                        cmdline_str = " ".join(cmdline).lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                    category = self._categorize_process(name, cmdline_str)
                    if category is None:
                        continue

                    current[category][proc.info["pid"]] = name

                self._handle_new_detections(current["screenshot"], self._known_screenshot_pids, "screenshot")
                self._handle_new_detections(current["recording"], self._known_recording_pids, "recording")
                self._handle_new_detections(current["sharing"], self._known_sharing_pids, "sharing")

                self._known_screenshot_pids = set(current["screenshot"])
                self._known_recording_pids = set(current["recording"])
                self._known_sharing_pids = set(current["sharing"])

                self._update_continuous_blackout()

            except Exception as exc:
                logger.error("Process monitor error: %s", exc)

            self._sleep_interruptible(self.process_poll_interval)

    def _handle_new_detections(self, current: Dict[int, str], known: Set[int], category: str) -> None:
        for pid in set(current) - known:
            process_name = current[pid]
            logger.info("Detected capture application: %s", _display_name(process_name))
            self._handle_process_detection(pid, process_name, category)

    def _handle_process_detection(self, pid: int, process_name: str, category: str) -> None:
        title, active_process = self._get_active_window()
        classification = self._get_effective_classification(title, process_name)
        is_sensitive = classification in SENSITIVE_CLASSIFICATIONS

        action = "Allowed"
        if is_sensitive:
            if self.mode == "protection":
                display = _display_name(process_name)
                category_verb = {
                    "screenshot": "Screenshot",
                    "recording": "Screen recording",
                    "sharing": "Screen sharing",
                }.get(category, "Screen capture")
                block_message = f"{category_verb} via {display} is blocked by CyberSentinel DLP"

                # Cover the screen immediately, before/while the kill happens,
                # rather than waiting for termination to complete. For
                # recording/sharing tools this is quickly superseded by the
                # continuous blackout (engaged at the end of this same
                # process-monitor cycle); for one-shot screenshot tools this
                # flash is the only blackout they get, since there's no
                # ongoing pid to key continuous coverage off of.
                self._flash_blackout(f"proc-{category}-{pid}", duration=2.0, message=block_message)
                terminated = self._terminate_process(pid, process_name)
                action = "Blocked" if terminated else "Alerted"
            else:
                action = "Alerted"

        method = _display_name(process_name)
        self._emit_event(self._build_event(
            method=method,
            process_name=_display_name(process_name),
            active_window=title,
            classification=classification,
            contains_sensitive_data=is_sensitive,
            action_taken=action,
            blackout_active=self.is_blackout_active,
        ))

        if action == "Blocked":
            logger.warning("SCREEN_ACTION_ENFORCED: terminated %s (pid=%d) â€” %s data visible",
                            method, pid, classification)
        elif is_sensitive:
            logger.warning("SCREEN_CAPTURE_ALERT: %s detected while %s content on screen",
                            method, classification)
        else:
            logger.info("SCREEN_CAPTURE_ALLOWED: %s â€” no sensitive data on screen", method)

    def _terminate_process(self, pid: int, process_name: str) -> bool:
        """Terminate a process by PID. Returns True if it is no longer running afterwards."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            return True
        except psutil.NoSuchProcess:
            return True
        except psutil.AccessDenied as exc:
            logger.error("Permission denied terminating %s (pid=%d): %s â€” "
                         "the agent may need to run with elevated privileges "
                         "to enforce Protection Mode", process_name, pid, exc)
            return False
        except Exception as exc:
            logger.error("Failed to terminate %s (pid=%d): %s", process_name, pid, exc)
            return False

    def _suppress_screenshot_keybindings(self) -> None:
        """
        Disable GNOME's screenshot keybindings so PrintScreen etc. do
        nothing at the OS level -- a real block, not just a log entry.
        No-op if not on GNOME, gsettings isn't available, or already
        suppressed.
        """
        if not (self._is_gnome and self._gsettings_available):
            return
        if self._keybindings_suppressed:
            return

        for schema, key in GNOME_SCREENSHOT_KEYBINDING_SCHEMAS:
            try:
                result = subprocess.run(
                    ["gsettings", "get", schema, key],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0:
                    self._saved_keybindings[(schema, key)] = result.stdout.strip()
                subprocess.run(
                    ["gsettings", "set", schema, key, "@as []"],
                    capture_output=True, text=True, timeout=3,
                )
            except Exception as exc:
                logger.debug("Could not suppress keybinding %s.%s: %s", schema, key, exc)

        self._keybindings_suppressed = True
        logger.warning(
            "SCREENSHOT_KEYBINDINGS_SUPPRESSED: OS-level PrintScreen shortcuts "
            "disabled while sensitive content is on screen"
        )

    def _restore_screenshot_keybindings(self) -> None:
        """Restore the user's original screenshot keybindings."""
        if not self._keybindings_suppressed:
            return

        for (schema, key), original_value in self._saved_keybindings.items():
            try:
                subprocess.run(
                    ["gsettings", "set", schema, key, original_value],
                    capture_output=True, text=True, timeout=3,
                )
            except Exception as exc:
                logger.debug("Could not restore keybinding %s.%s: %s", schema, key, exc)

        self._keybindings_suppressed = False
        logger.info("SCREENSHOT_KEYBINDINGS_RESTORED: OS-level PrintScreen shortcuts re-enabled")

    # â”€â”€â”€ Full-screen black overlay â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _notify_user(self, message: str, title: str = "CyberSentinel DLP") -> None:
        """
        Show a desktop notification bubble (in addition to the on-overlay
        text) so there's a visible record even after the black overlay
        clears. Best-effort; a missing/failed notify-send never raises.
        """
        if not self._notify_send_available:
            return
        try:
            subprocess.run(
                ["notify-send", "--urgency=critical", "--icon=dialog-warning", title, message],
                capture_output=True, timeout=3,
            )
        except Exception as exc:
            logger.debug("notify-send failed: %s", exc)

    def _engage_blackout(self, reason: str, message: str = DEFAULT_BLACKOUT_MESSAGE) -> None:
        """
        Show the full-screen black overlay, if not already shown, and
        register `reason` as one of (possibly several) causes currently
        requiring it. The overlay stays up until every registered reason
        has been cleared via _disengage_blackout(). No-op under Wayland
        (see startup log for why) or outside Protection Mode.

        `message` is only used the moment the overlay is first created
        (i.e. the first reason to engage it "wins" the displayed text);
        subsequent reasons piling on while it's already up don't change it.

        This is a visual block, not an input lock: it does not grab the
        keyboard or mouse, so switching to another window/workspace still
        works. It is intended as a compensating control alongside process
        termination and keybinding suppression, not a replacement for them.
        """
        if self._is_wayland or self.mode != "protection":
            return

        with self._blackout_lock:
            first = not self._blackout_reasons
            self._blackout_reasons.add(reason)
            if first and self._blackout_process is None:
                try:
                    self._blackout_process = subprocess.Popen(
                        ["python3", "-c", _BLACKOUT_OVERLAY_SCRIPT, message],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    logger.warning("SCREEN_BLACKOUT_ENGAGED: full-screen black overlay shown (reason=%s)", reason)
                    threading.Thread(target=self._verify_blackout_launched,
                                      args=(self._blackout_process,), daemon=True).start()
                except Exception as exc:
                    logger.error("Failed to show blackout overlay: %s", exc)
                    self._blackout_process = None

        if first:
            self._notify_user(message)

    def _verify_blackout_launched(self, proc: subprocess.Popen) -> None:
        """Detect a blackout overlay that failed immediately (e.g. missing python3-tk)."""
        time.sleep(0.5)
        if proc.poll() is None:
            return  # still running -- looks fine
        try:
            _, stderr = proc.communicate(timeout=1)
        except Exception:
            stderr = ""
        logger.error(
            "Blackout overlay process exited immediately (rc=%s): %s",
            proc.returncode, (stderr or "no error output captured").strip()[:300],
        )
        with self._blackout_lock:
            if self._blackout_process is proc:
                self._blackout_process = None

    def _disengage_blackout(self, reason: str) -> None:
        """Remove `reason` from the active set; hide the overlay once no reasons remain."""
        with self._blackout_lock:
            self._blackout_reasons.discard(reason)
            if self._blackout_reasons or self._blackout_process is None:
                return
            proc = self._blackout_process
            self._blackout_process = None

        try:
            proc.terminate()
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as exc:
            logger.debug("Error stopping blackout overlay process: %s", exc)
        logger.info("SCREEN_BLACKOUT_CLEARED: black overlay removed")

    def _flash_blackout(self, reason: str, duration: float = 1.5, message: str = DEFAULT_BLACKOUT_MESSAGE) -> None:
        """Engage the overlay for a fixed duration, e.g. to cover an instantaneous screenshot attempt."""
        self._engage_blackout(reason, message=message)

        def _auto_clear() -> None:
            time.sleep(duration)
            self._disengage_blackout(reason)

        threading.Thread(target=_auto_clear, daemon=True).start()

    def _update_continuous_blackout(self) -> None:
        """
        Keep the overlay engaged for as long as a screen-recording or
        screen-sharing tool remains running while sensitive content is on
        screen (a one-shot screenshot doesn't need this â€” it's covered by
        _flash_blackout at the moment of detection instead).
        """
        with self._lock:
            sensitive = self.screen_is_sensitive
        ongoing_capture = bool(self._known_recording_pids) or bool(self._known_sharing_pids)
        if self.mode == "protection" and sensitive and ongoing_capture:
            if self._known_sharing_pids:
                message = "Screen sharing is blocked by CyberSentinel DLP"
            else:
                message = "Screen recording is blocked by CyberSentinel DLP"
            self._engage_blackout("continuous", message=message)
        else:
            self._disengage_blackout("continuous")

    @property
    def is_blackout_active(self) -> bool:
        with self._blackout_lock:
            return bool(self._blackout_reasons)

    def _reactive_sweep(self) -> None:
        """
        Run an immediate, out-of-cycle process scan. Triggered right after
        a screenshot hotkey is detected while sensitive content is on
        screen, so a tool the shortcut just launched is caught without
        waiting for the next scheduled process_monitor_thread poll.
        """
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    name = (proc.info.get("name") or "").lower()
                    cmdline = proc.info.get("cmdline") or []
                    cmdline_str = " ".join(cmdline).lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

                category = self._categorize_process(name, cmdline_str)
                if category is None:
                    continue

                pid = proc.info["pid"]
                already_known = pid in (
                    self._known_screenshot_pids | self._known_recording_pids | self._known_sharing_pids
                )
                if already_known:
                    continue

                logger.info("Detected capture application: %s (reactive sweep)", _display_name(name))
                self._handle_process_detection(pid, name, category)
        except Exception as exc:
            logger.error("Reactive sweep error: %s", exc)

    # â”€â”€â”€ Keyboard shortcut monitoring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def keyboard_monitor_thread(self) -> None:
        """
        Detect (never blocks, see module docstring) screenshot-related
        keyboard shortcuts using evdev: PrintScreen, Shift/Ctrl/Alt+
        PrintScreen, and Meta+Shift+S.
        """
        if not EVDEV_AVAILABLE:
            return

        devices = self._find_keyboard_devices()
        if not devices:
            logger.warning(
                "No accessible keyboard input devices found â€” keyboard "
                "shortcut detection disabled. On most distributions this "
                "requires the agent's user to be in the 'input' group "
                "(or running as root)."
            )
            return

        logger.info("Keyboard monitor attached to %d input device(s)", len(devices))

        pressed: Set[int] = set()
        try:
            import selectors
            selector = selectors.DefaultSelector()
            for dev in devices:
                selector.register(dev, selectors.EVENT_READ)

            while self._running:
                for key, _mask in selector.select(timeout=0.5):
                    device = key.fileobj
                    try:
                        for event in device.read():
                            self._process_key_event(event, pressed)
                    except (OSError, BlockingIOError):
                        continue
                    except Exception as exc:
                        logger.debug("Keyboard device read error: %s", exc)
        except Exception as exc:
            logger.error("Keyboard monitor thread error: %s", exc)
        finally:
            for dev in devices:
                try:
                    dev.close()
                except Exception:
                    pass

    def _find_keyboard_devices(self) -> List["evdev.InputDevice"]:
        found: List["evdev.InputDevice"] = []
        try:
            paths = evdev.list_devices()
        except Exception as exc:
            logger.warning("Could not list input devices: %s", exc)
            return found

        for path in paths:
            try:
                dev = evdev.InputDevice(path)
                capabilities = dev.capabilities().get(ecodes.EV_KEY, [])
                if ecodes.KEY_SYSRQ in capabilities or getattr(ecodes, "KEY_PRINT", -1) in capabilities:
                    found.append(dev)
            except PermissionError as exc:
                logger.debug("No permission for input device %s: %s", path, exc)
            except Exception as exc:
                logger.debug("Skipping input device %s: %s", path, exc)
        return found

    def _process_key_event(self, event, pressed: Set[int]) -> None:
        if event.type != ecodes.EV_KEY:
            return

        code = event.code
        if event.value == 1:      # key down
            pressed.add(code)
        elif event.value == 0:    # key up
            pressed.discard(code)
            return
        else:                      # autorepeat â€” ignore for combo detection
            return

        is_print_screen = code == ecodes.KEY_SYSRQ or code == getattr(ecodes, "KEY_PRINT", -1)
        shift_down = bool(pressed & {ecodes.KEY_LEFTSHIFT, ecodes.KEY_RIGHTSHIFT})
        ctrl_down = bool(pressed & {ecodes.KEY_LEFTCTRL, ecodes.KEY_RIGHTCTRL})
        alt_down = bool(pressed & {ecodes.KEY_LEFTALT, ecodes.KEY_RIGHTALT})
        meta_down = bool(pressed & {ecodes.KEY_LEFTMETA, ecodes.KEY_RIGHTMETA})

        method: Optional[str] = None
        if is_print_screen:
            if ctrl_down:
                method = "Ctrl+PrintScreen"
            elif alt_down:
                method = "Alt+PrintScreen"
            elif shift_down:
                method = "Shift+PrintScreen"
            else:
                method = "PrintScreen"
        elif code == ecodes.KEY_S and meta_down and shift_down:
            method = "Meta+Shift+S"

        if method:
            self._handle_keyboard_shortcut(method)

    def _handle_keyboard_shortcut(self, method: str) -> None:
        logger.info("Keyboard shortcut detected: %s", method)

        title, process_name = self._get_active_window()
        with self._lock:
            is_sensitive = self.screen_is_sensitive
            classification = self._current_classification

        action = "Allowed"
        if is_sensitive:
            action = "Blocked" if self.mode == "protection" else "Alerted"

            now = time.monotonic()
            with self._lock:
                should_log_alert = (now - self._last_alert_monotonic) > self.popup_cooldown_seconds
                if should_log_alert:
                    self._last_alert_monotonic = now

            if should_log_alert:
                logger.warning(
                    "SCREEN_CAPTURE_%s: %s â€” %s content currently on screen",
                    action.upper(), method, classification,
                )

            if self.mode == "protection":
                # Immediate visual cover: the shortcut may have already
                # triggered the OS-level screenshot before the keybinding
                # suppression engaged, or a third-party tool with its own
                # hotkey; flash the overlay right away rather than waiting.
                self._flash_blackout(f"shortcut-{time.monotonic()}", duration=1.5)
                # Reactive prevention: this thread cannot itself swallow the
                # keystroke (see module docstring), so it immediately sweeps
                # for -- and terminates -- any capture/recording tool the
                # shortcut may have just launched, instead of waiting for
                # the next scheduled process_monitor_thread poll.
                self._reactive_sweep()
        else:
            logger.info("SCREEN_CAPTURE_ALLOWED: %s â€” no sensitive data on screen", method)

        self._emit_event(self._build_event(
            method=method,
            process_name=process_name or "unknown",
            active_window=title,
            classification=classification,
            contains_sensitive_data=is_sensitive,
            action_taken=action,
            blackout_active=self.is_blackout_active,
        ))

    # â”€â”€â”€ Event construction / dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def _get_timestamp() -> str:
        return datetime.utcnow().isoformat() + "Z"

    def _build_event(
        self,
        method: str,
        process_name: str,
        active_window: str,
        classification: str,
        contains_sensitive_data: bool,
        action_taken: str,
        blackout_active: bool = False,
    ) -> Dict[str, Any]:
        return {
            "eventType": "screen_capture",
            "method": method,
            "processName": process_name,
            "activeWindow": active_window,
            "classification": classification,
            "containsSensitiveData": contains_sensitive_data,
            "actionTaken": action_taken,
            "screenBlanked": blackout_active,
            "timestamp": self._get_timestamp(),
        }

    def _emit_event(self, event: Dict[str, Any]) -> None:
        if not self.event_callback:
            return
        try:
            self.event_callback(event)
        except Exception as exc:
            logger.error("Event callback raised an exception: %s", exc)

