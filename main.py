import threading
from sniffer import start_sniffer
from dashboard import start_dashboard

if __name__ == "__main__":
    print("=== Home Network IDS Started ===")

    # Run dashboard in background thread
    dash_thread = threading.Thread(target=start_dashboard, daemon=True)
    dash_thread.start()

    # Start packet sniffing
    start_sniffer()
