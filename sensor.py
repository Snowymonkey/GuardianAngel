import time
from scapy.all import AsyncSniffer
from brain import analyze


if __name__ == "__main__":
    try:
        sniffer = AsyncSniffer(prn=analyze)
        sniffer.start()
        print("\n[*] Guardian Angel Active.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping Guardian Angel...")

    finally:
        sniffer.stop()