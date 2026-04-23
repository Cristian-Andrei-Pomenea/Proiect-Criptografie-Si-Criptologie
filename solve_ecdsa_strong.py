#!/usr/bin/env python3

import re
import math
import json
from collections import defaultdict

from ecdsa import curves
from ecdsa.ellipticcurve import Point

try:
    from fpylll import IntegerMatrix, LLL
    LATTICE_AVAILABLE = True
except:
    LATTICE_AVAILABLE = False

KNOWN_BITS_DEFAULT = 8


def format_key(d):
    return format(d, "X")


def parse_signatures_auto(path):
    if path.endswith(".json"):
        with open(path) as f:
            data = json.load(f)
        return [
            {"m": int(x["hash"], 16), "r": int(x["r"], 16), "s": int(x["s"], 16)}
            for x in data
        ]
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    matches = re.findall(
        r"Hash:\s*([0-9A-Fa-f]+).*?R:\s*([0-9A-Fa-f]+).*?S:\s*([0-9A-Fa-f]+)",
        txt, re.S
    )
    return [{"m": int(h,16), "r": int(r,16), "s": int(s,16)} for h,r,s in matches]


def load_curve_and_pub():
    ref = curves.NIST224p
    q   = ref.order
    G   = ref.generator

    with open("public.oct", "rb") as f:
        data = f.read()
    half  = (len(data) - 1) // 2
    pub_x = int.from_bytes(data[1:1+half], "big")
    pub_y = int.from_bytes(data[1+half:], "big")

    pub_point = Point(ref.curve, pub_x, pub_y)

    return q, G, pub_point


def verify(d, G, pub_point):
    return d * G == pub_point


def group_by_r(sigs):
    g = defaultdict(list)
    for s in sigs:
        g[s["r"]].append(s)
    return g


def recover_private_key_reuse(m1, m2, r, s1, s2, q):
    num = (m2 * s1 - m1 * s2) % q
    den = (r * (s2 - s1)) % q
    return (num * pow(den, -1, q)) % q


def lattice_attack(sigs, q, known_bits):
    if not LATTICE_AVAILABLE:
        return []

    valid = [s for s in sigs if math.gcd(s["s"], q) == 1]
    if len(valid) < 2:
        return []

    n = len(valid)
    K = 2 ** known_bits

    t = [(s["r"] * pow(s["s"], -1, q)) % q for s in valid]
    u = [(s["m"] * pow(s["s"], -1, q)) % q for s in valid]

    B = IntegerMatrix(n + 2, n + 2)

    for i in range(n):
        B[i, i] = K * q

    for i in range(n):
        B[n, i] = K * t[i]
    B[n, n] = 1

    for i in range(n):
        B[n+1, i] = K * u[i]
    B[n+1, n+1] = K

    LLL.reduction(B)

    candidates = []
    for row in B:
        for sign in (1, -1):
            d = (sign * int(row[n])) % q
            if 0 < d < q:
                candidates.append(d)
    return candidates


def full_attack(sigs, q, G, pub_point):
    groups = group_by_r(sigs)
    for g in groups.values():
        if len(g) > 1:
            for i in range(len(g)):
                for j in range(i+1, len(g)):
                    a, b = g[i], g[j]
                    if a["s"] == b["s"]:
                        continue
                    d = recover_private_key_reuse(
                        a["m"], b["m"], a["r"], a["s"], b["s"], q
                    )
                    if verify(d, G, pub_point):
                        print("gasit: nonce refolosit")
                        return d

    print("incerc lattice...")
    for n in [20, 30, 40, 60, len(sigs)]:
        if n > len(sigs):
            continue
        candidates = lattice_attack(sigs[:n], q, KNOWN_BITS_DEFAULT)
        for d in candidates:
            if verify(d, G, pub_point):
                print(f"gasit: lattice (n={n})")
                return d

    return None


if __name__ == "__main__":
    print("incarc fisierele...")
    q, G, pub_point = load_curve_and_pub()
    sigs = parse_signatures_auto("signatures.txt")
    print(f"{len(sigs)} semnaturi")

    d = full_attack(sigs, q, G, pub_point)

    if d:
        print(f"\ncheie privata:\n{format_key(d)}")
    else:
        print("\nesec — incearca NUM_SIGS=80 in generate.py")
