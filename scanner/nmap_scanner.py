import shutil
import nmap


def nmap_available():
    return shutil.which("nmap") is not None


def scan_with_nmap(target, ports):

    if not nmap_available():
        raise RuntimeError(
            "Nmap executable not found. "
            "Please install Nmap and add it to PATH."
        )

    scanner = nmap.PortScanner()

    port_spec = ",".join(map(str, ports))

    arguments = (
        "-sV "
        "--version-all "
        "--version-intensity 9 "
        "-T3 "
        "--reason "
        "--script smb-os-discovery,smb-protocols,rpcinfo"
    )

    scanner.scan(
        hosts=target,
        ports=port_spec,
        arguments=arguments
    )

    findings = []

    for host in scanner.all_hosts():

        for protocol in scanner[host].all_protocols():

            for port, info in scanner[host][protocol].items():

                if info.get("state") != "open":
                    continue

                findings.append({

                    "host": host,
                    "port": int(port),
                    "protocol": protocol,

                    "state": info.get("state", "open"),

                    "service": info.get(
                        "name", "unknown"
                    ),

                    "product": info.get(
                        "product", ""
                    ),

                    "version": info.get(
                        "version", ""
                    ),

                    "extrainfo": info.get(
                        "extrainfo", ""
                    ),

                    "reason": info.get(
                        "reason", ""
                    ),

                    "scripts": info.get(
                        "script", {}
                    ),

                    "method": "nmap"

                })

    return findings


def discover_hosts(network):

    if not nmap_available():
        raise RuntimeError(
            "Nmap is required for network discovery."
        )

    scanner = nmap.PortScanner()

    scanner.scan(
        hosts=network,
        arguments="-sn -T3"
    )

    return [
        {
            "host": host,
            "state": scanner[host].state()
        }
        for host in scanner.all_hosts()
    ]