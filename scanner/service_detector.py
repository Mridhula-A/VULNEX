COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP alternate",
    8443: "HTTPS alternate"
}


WINDOWS_PRODUCTS = {
    135: "Microsoft Windows RPC",
    445: "Microsoft Windows SMB",
    139: "Microsoft NetBIOS"
}


def enrich_service(item):

    item = dict(item)

    port = int(item.get("port", 0))

    service = item.get("service", "")

    # Identify service name
    if not service or service.lower() == "unknown":
        item["service"] = COMMON_SERVICES.get(
            port,
            "unknown"
        )

    # Identify common Windows products
    if not item.get("product"):
        product = WINDOWS_PRODUCTS.get(port)

        if product:
            item["product"] = product

    # Preserve Nmap script output
    scripts = item.get("scripts", {})

    if not isinstance(scripts, dict):
        scripts = {}

    item["scripts"] = scripts

    # Extract SMB operating-system information
    smb_output = scripts.get(
        "smb-os-discovery",
        ""
    )

    if smb_output:
        item["os_hint"] = smb_output
    else:
        item["os_hint"] = ""

    # Keep missing versions explicitly unknown
    if not item.get("version"):
        item["version"] = ""

    return item