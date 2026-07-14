from screen_capture_monitor import ScreenCaptureMonitor

import time



def callback(event):

    print(event)



monitor = ScreenCaptureMonitor(callback)



monitor.start()



print("Screen Capture Monitor running...")

print("Press Ctrl+C to stop")



try:

    while True:

        time.sleep(1)



except KeyboardInterrupt:

    monitor.stop()
