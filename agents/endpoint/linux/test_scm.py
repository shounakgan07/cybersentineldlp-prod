"""
Standalone test harness for screen_capture_monitor.py

Run this from inside agents/endpoint/linux/ (same folder as
screen_capture_monitor.py), on your Ubuntu desktop's own terminal
(not over SSH), so it has a real DISPLAY to work with.
"""

import logging
import time

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")

from screen_capture_monitor import ScreenCaptureMonitor


def on_event(event):
    print("EVENT:", event)


if __name__ == "__main__":
    # Start in "monitor" mode first (detect + log only, nothing gets killed).
    # Switch to mode="protection" later once monitor mode looks correct.
    monitor = ScreenCaptureMonitor(event_callback=on_event, mode="protection")
    monitor.start()

    print("\nMonitor running. Try opening flameshot / gnome-screenshot / pressing")
    print("PrintScreen / typing 'CONFIDENTIAL salary' in a text editor window.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()

