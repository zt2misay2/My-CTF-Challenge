import json
from pathlib import Path

from Crypto.Util.number import long_to_bytes


E = 65537
N = int(
    "0ac4848f614d41d1f100ff73fef6d528c478dce950b20826eb32eed68bb82027"
    "ca38b38628a989a66888234188ac64b5a0ff05a897153761995e020de0c5b0a0"
    "8b4e17b578fb6955ddc698d197bf534f8221e3b1be912ab1b69230e265fb01c0"
    "325e96b15448cb17ca5628b11de2d1a82e92c8a108960d7e63c2b44a5720aade"
    "676ba72f3e436182b6e05b1d86c7f5b7ecceffeea3bb16353924e1b61932e7d14"
    "0ddf7d51a9814452f73760bdbcb6125ab1f5ed18bde952ad3f857e8309945f35"
    "9f076654168598f000dd8b5d19f4b94a1b38f817d373834a72fa8bcf7be10723"
    "5290086ad13646d9538ba1cce8d3ae139b8e59340151c5cef3d386340dd60cd",
    16,
)

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "pcap_messages.json"


def eval_poly(coeffs, x):
    value = 0
    for coeff in reversed(coeffs):
        value = value * x + coeff
    return value


def recover_factors_from_base12():
    a_coeffs = [0] * 286
    for index, coeff in {
        0: 1,
        1: 1,
        3: 1,
        4: 2,
        5: 2,
        6: 2,
        8: 2,
        9: 2,
        10: 2,
        12: 1,
        14: 2,
        15: 1,
        16: 2,
        17: 1,
        18: 1,
        20: 2,
        21: 2,
        23: 1,
        24: 1,
        25: 2,
        27: 1,
        29: 2,
        31: 2,
        33: 2,
        34: 2,
        35: 2,
        36: 2,
        37: 2,
        38: 1,
        39: 1,
        285: 1,
    }.items():
        a_coeffs[index] = coeff

    b_coeffs = [0] * 286
    for index, coeff in {
        0: 1,
        40: 2,
        120: 1,
        200: 2,
        240: 2,
        280: 1,
        285: 1,
    }.items():
        b_coeffs[index] = coeff

    p = eval_poly(a_coeffs, 12)
    q = eval_poly(b_coeffs, 12)
    if p * q != N:
        raise ValueError("factor reconstruction failed")
    return min(p, q), max(p, q)


def decrypt_ciphertext(ct_hex, d_value):
    c_value = int.from_bytes(bytes.fromhex(ct_hex)[::-1], "big")
    m_value = pow(c_value, d_value, N)
    return long_to_bytes(m_value).decode("utf-8")


def main():
    p, q = recover_factors_from_base12()
    phi = (p - 1) * (q - 1)
    d_value = pow(E, -1, phi)

    messages = json.loads(DATA_PATH.read_text(encoding="utf-8"))["unique_messages"]
    parts = {}
    for message in messages:
        plaintext = decrypt_ciphertext(message["ct"], d_value)
        print(f"frame={message['frame']} {message['sender']} -> {message['recipient']}: {plaintext}")
        if "part1 =" in plaintext:
            parts["part1"] = plaintext.split("=", 1)[1].strip()
        elif "part2 =" in plaintext:
            parts["part2"] = plaintext.split("=", 1)[1].strip()
        elif "part3 =" in plaintext:
            parts["part3"] = plaintext.split("=", 1)[1].strip()

    if {"part1", "part2", "part3"} <= parts.keys():
        print()
        print(parts["part1"] + parts["part2"] + parts["part3"])


if __name__ == "__main__":
    main()
