#!/usr/bin/env python3

import os
import re
import json
from collections import defaultdict
from multiprocessing import Pool

try:
    from fpylll import IntegerMatrix, LLL
    LATTICE_AVAILABLE = True
except:
    LATTICE_AVAILABLE = False

MAX_LATTICE_SIGS = 8
KNOWN_BITS_DEFAULT = 8

def format_key(d):
    return format(d, "X")


def parse_signatures_auto(path):
    if path.endswith(".json"):
        with open(path) as f:
            data = json.load(f)
        return [
            {"m": int(x["hash"],16), "r": int(x["r"],16), "s": int(x["s"],16)}
            for x in data
        ]

    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()

    matches = re.findall(
        r"Hash:\s*([0-9A-Fa-f]+).*?R:\s*([0-9A-Fa-f]+).*?S:\s*([0-9A-Fa-f]+)",
        txt,
        re.S
    )

    return [
        {"m": int(h,16), "r": int(r,16), "s": int(s,16)}
        for h,r,s in matches
    ]


class ECPoint:
    def __init__(self,x,y,c):
        self.x,self.y,self.curve=x,y,c
        self.inf=(x is None)

    @classmethod
    def INF(cls,c):
        p=cls.__new__(cls)
        p.x=p.y=None
        p.curve=c
        p.inf=True
        return p

    def __add__(self,o):
        p,a=self.curve.p,self.curve.a
        if self.inf:return o
        if o.inf:return self

        if self.x==o.x:
            if (self.y+o.y)%p==0:
                return ECPoint.INF(self.curve)
            l=(3*self.x*self.x+a)*pow(2*self.y,-1,p)%p
        else:
            l=(o.y-self.y)*pow(o.x-self.x,-1,p)%p

        x3=(l*l-self.x-o.x)%p
        y3=(l*(self.x-x3)-self.y)%p
        return ECPoint(x3,y3,self.curve)

    def __mul__(self,k):
        r=ECPoint.INF(self.curve)
        a=self
        k%=self.curve.q
        while k:
            if k&1:r=r+a
            a=a+a
            k>>=1
        return r

    __rmul__=__mul__

class Curve:
    def __init__(self,p,a,b,xg,yg,q):
        self.p,self.a,self.b,self.q=p,a,b,q
        self.G=ECPoint(xg,yg,self)


def recover_private_key(m1,m2,r,s1,s2,q):
    num = (m2*s1 - m1*s2) % q
    den = (r*(s2-s1)) % q
    return (num * pow(den,-1,q)) % q


def recover_nonce_k(m1,m2,s1,s2,q):
    num = (m1 - m2) % q
    den = (s1 - s2) % q
    return (num * pow(den,-1,q)) % q


def verify(curve,d,pub):
    P = d * curve.G
    return P.x == pub[0] and P.y == pub[1]

def group_by_r(sigs):
    g = defaultdict(list)
    for s in sigs:
        g[s["r"]].append(s)
    return g


def detect_reuse(groups):
    return [g for g in groups.values() if len(g)>1]


def weak_nonce_signals(sigs):
    rs = [s["r"] for s in sigs]
    return {
        "duplicate_r": len(rs) != len(set(rs)),
        "count": len(rs)
    }

def lattice_attack(signatures, q, known_bits=KNOWN_BITS_DEFAULT):
    if not LATTICE_AVAILABLE:
        print("[-] Lattice skipped (fpylll not installed)")
        return None

    print("[*] Lattice attempt with", len(signatures), "signatures")

    n = len(signatures)
    B = IntegerMatrix(n+1, n+1)
    K = 2 ** known_bits

    for i, sig in enumerate(signatures):
        m,r,s = sig["m"],sig["r"],sig["s"]
        s_inv = pow(s,-1,q)

        t = (r * s_inv) % q
        B[i,i] = q
        B[i,n] = t

    for j, sig in enumerate(signatures):
        m,r,s = sig["m"],sig["r"],sig["s"]
        s_inv = pow(s,-1,q)
        u = (m * s_inv) % q
        B[n,j] = u

    B[n,n] = K

    LLL.reduction(B)

    for row in B:
        d = row[n] % q
        if d != 0:
            return d

    return None

def full_auto_attack(sigs, curve, pub):

    print("[*] Running FULL AUTO attack")

    groups = group_by_r(sigs)
    reuse = detect_reuse(groups)

    # ── STEP 1: nonce reuse
    if reuse:
        print("[+] Reuse detected → exploiting")

        for g in reuse:
            for i in range(len(g)):
                for j in range(i+1,len(g)):

                    a,b = g[i],g[j]

                    d = recover_private_key(
                        a["m"],b["m"],
                        a["r"],
                        a["s"],b["s"],
                        curve.q
                    )

                    if verify(curve,d,pub):
                        print("[✔] PRIVATE KEY (reuse)")
                        print(format_key(d))
                        return d

    # ── STEP 2: lattice
    print("[*] Trying lattice fallback")

    subset = sigs[:MAX_LATTICE_SIGS]

    d = lattice_attack(subset, curve.q)

    if d and verify(curve,d,pub):
        print("[✔] PRIVATE KEY (lattice)")
        print(format_key(d))
        return d

    print("[-] No attack succeeded")
    return None

if __name__ == "__main__":

    PARAMS = "parameters.der"
    PUB    = "public.oct"
    SIGS   = "signatures.txt"

    print("[*] Loading data...")

    with open(PARAMS,"rb") as f:
        r = f.read()

    p = int.from_bytes(r[0x14:0x14+28],"big")
    a = r[0x34]
    b = r[0x37]
    xG = int.from_bytes(r[0x3b:0x3b+28],"big")
    yG = int.from_bytes(r[0x57:0x57+28],"big")
    q = int.from_bytes(r[0x75:0x75+29],"big")

    curve = Curve(p,a,b,xG,yG,q)

    with open(PUB,"rb") as f:
        d = f.read()
        n = (len(d)-1)//2
        pub = (
            int.from_bytes(d[1:1+n],"big"),
            int.from_bytes(d[1+n:],"big")
        )

    sigs = parse_signatures_auto(SIGS)

    print("[+] Loaded", len(sigs), "signatures")
    print("[*] Analysis:", weak_nonce_signals(sigs))

    d = full_auto_attack(sigs, curve, pub)

    if d:
        print("\n" + "="*60)
        print("FINAL PRIVATE KEY:")
        print(format_key(d))
        print("="*60)
    else:
        print("[-] Key not found")