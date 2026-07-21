from detector import analyze


def forward_to_bank(packet, windivert):

    print("[ALLOW] Forwarding to Bank")

    windivert.send(packet)


def forward_to_honeypot(packet, windivert):

    print("[HONEYPOT] Redirecting")

    windivert.send(packet)


def drop_request():

    print("[BLOCK] Packet Dropped")


def handle_request(request, windivert):

    print("Router received packet from:", request["src_ip"])

    decision = analyze(request)

    if decision == "ALLOW":

        forward_to_bank(request["packet"], windivert)

    elif decision == "HONEYPOT":

        forward_to_honeypot(request["packet"], windivert)

    elif decision == "BLOCK":

        drop_request()