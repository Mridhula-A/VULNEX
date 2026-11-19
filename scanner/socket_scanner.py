import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import CONNECT_TIMEOUT, MAX_WORKERS

def scan_ports(target, ports, progress=None):
    results = []
    total = len(ports)
    def check(port):
        try:
            with socket.create_connection((target, port), timeout=CONNECT_TIMEOUT):
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                return {"port": port, "protocol": "tcp", "state": "open",
                        "service": service, "product": "", "version": "", "method": "socket"}
        except (OSError, socket.timeout):
            return None

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total)) as pool:
        futures = {pool.submit(check, p): p for p in ports}
        for index, future in enumerate(as_completed(futures), 1):
            item = future.result()
            if item:
                results.append(item)
            if progress:
                progress(index, total, f"Socket scan: {index}/{total}")
    return sorted(results, key=lambda x: x["port"])
