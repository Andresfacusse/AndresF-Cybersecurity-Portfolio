import time

def monitor_log(filepath):
    with open(filepath, "r") as file:
        file.seek(0, 2)  # Go to end
        while True:
            line = file.readline()
            if "Failed password" in line:
                print("[ALERT] Suspicious login:", line.strip())
            time.sleep(1)

monitor_log("/var/log/auth.log")

#sends alert (email, telegram, or just prints)
#File I/O, Linux Logs, Alert Logic
