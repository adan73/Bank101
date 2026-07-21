import pydivert
from router import handle_request

FILTER = "tcp.DstPort == 3000"


def extract_request(packet):

    return {
        "src_ip": packet.src_addr,
        "dst_ip": packet.dst_addr,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "protocol": packet.protocol,
        "payload": bytes(packet.payload),
        "packet": packet
    }


def start_capture():

    print("[+] PyDivert Started")
    print("[+] Listening on port 3000")

    with pydivert.WinDivert(FILTER) as w:

        for packet in w:

            request = extract_request(packet)

            handle_request(request, w)


if __name__ == "__main__":
    start_capture()