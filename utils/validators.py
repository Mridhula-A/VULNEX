import ipaddress
import re
import socket

def validate_target(value: str):
    value = value.strip()
    if not value:
        raise ValueError("Enter a target IP address, hostname or CIDR range.")
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses > 256:
                raise ValueError("For safety, CIDR scans are limited to 256 addresses.")
            return str(network), "network"
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR range: {exc}") from exc
    try:
        ipaddress.ip_address(value)
        return value, "host"
    except ValueError:
        pass
    if len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", value):
        raise ValueError("Enter a valid hostname or IP address.")
    try:
        socket.getaddrinfo(value, None)
    except socket.gaierror as exc:
        raise ValueError(f"Hostname could not be resolved: {exc}") from exc
    return value, "host"

def parse_ports(value: str):
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bits = part.split("-", 1)
            if len(bits) != 2:
                raise ValueError("Invalid port range.")
            start, end = map(int, bits)
            if start < 1 or end > 65535 or start > end or end - start > 2000:
                raise ValueError("Port ranges must be valid and contain at most 2,001 ports.")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.add(port)
    if not ports:
        raise ValueError("Enter at least one port.")
    if len(ports) > 2001:
        raise ValueError("A maximum of 2,001 ports can be scanned at once.")
    return sorted(ports)
