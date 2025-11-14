import datetime

def log_alert(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"[ALERT] {timestamp} - {message}")

    with open("ids_alerts.log", "a") as file:
        file.write(f"{timestamp} - {message}\n")
