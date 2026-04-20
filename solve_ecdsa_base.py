#!/usr/bin/env python3
"""
MITRE ICCS 2012 - Multi-Day Challenge
ECDSA Private Key Recovery via Nonce Reuse Attack
Tool-uri folosite: Python 3 (stdlib + sympy)
"""

import os

def parse_public_oct(filepath):
    """Citeste cheia publica din fisierul .oct (format uncompressed: 04 || x || y)."""
    with open(filepath, 'rb') as f:
        data = f.read()
    assert data[0] == 0x04, "Punct necomprimat asteptat (prefix 0x04)"
    n = (len(data) - 1) // 2
    xV = int.from_bytes(data[1:1+n], 'big')
    yV = int.from_bytes(data[1+n:], 'big')
    return xV, yV

def parse_parameters_der(filepath):
    """
    Parsare manuala DER pentru ECParameters (SEC 1 / X9.62).
    """
    with open(filepath, 'rb') as f:
        raw = f.read()

    p = int.from_bytes(raw[0x14:0x14+28], 'big')
    a = raw[0x34]
    b = raw[0x37]

    g_offset = 0x3a
    xG = int.from_bytes(raw[g_offset+1:g_offset+29], 'big')
    yG = int.from_bytes(raw[g_offset+29:g_offset+57], 'big')

    q = int.from_bytes(raw[0x75:0x75+29], 'big')

    return p, a, b, xG, yG, q

class ECPoint:
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve
        self.infinity = (x is None)

    @classmethod
    def infinity_point(cls, curve):
        pt = cls.__new__(cls)
        pt.x = pt.y = None
        pt.curve = curve
        pt.infinity = True
        return pt

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.infinity:
            return "O (infinity)"
        return f"({hex(self.x)}, {hex(self.y)})"

    def __add__(self, other):
        p, a = self.curve.p, self.curve.a
        if self.infinity:
            return other
        if other.infinity:
            return self
        if self.x == other.x:
            if (self.y + other.y) % p == 0:
                return ECPoint.infinity_point(self.curve)
            lam = (3 * self.x**2 + a) * pow(2 * self.y, -1, p) % p
        else:
            lam = (other.y - self.y) * pow(other.x - self.x, -1, p) % p
        x3 = (lam**2 - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return ECPoint(x3, y3, self.curve)

    def __rmul__(self, scalar):
        return self.__mul__(scalar)

    def __mul__(self, scalar):
        result = ECPoint.infinity_point(self.curve)
        addend = ECPoint(self.x, self.y, self.curve)
        scalar = scalar % self.curve.q
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        return result

class EllipticCurve:
    def __init__(self, p, a, b, xG, yG, q):
        self.p = p
        self.a = a
        self.b = b
        self.q = q
        self.G = ECPoint(xG, yG, self)

    def verify_point(self, x, y):
        lhs = pow(y, 2, self.p)
        rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return lhs == rhs

def recover_private_key(m1, m2, r, s1, s2, q):
    numerator   = (m2 * s1 - m1 * s2) % q
    denominator = (r  * (s2 - s1))    % q
    s_priv = numerator * pow(denominator, -1, q) % q
    return s_priv

def verify_private_key(curve, s_priv, xV, yV):
    V_computed = s_priv * curve.G
    return V_computed.x == xV and V_computed.y == yV


if __name__ == '__main__':
    print("=" * 65)
    print("  MITRE ICCS 2012 - ECDSA Nonce Reuse Attack")
    print("=" * 65)

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    parameters_path = os.path.join(BASE_DIR, 'parameters.der')
    public_path     = os.path.join(BASE_DIR, 'public.oct')

    print("\n[1] Parsare fisiere...")
    p, a, b, xG, yG, q = parse_parameters_der(parameters_path)
    xV, yV              = parse_public_oct(public_path)

    print(f"    p  = {hex(p)}")
    print(f"    a  = {a}, b = {b}")
    print(f"    xG = {hex(xG)}")
    print(f"    yG = {hex(yG)}")
    print(f"    q  = {hex(q)}")
    print(f"    xV = {hex(xV)}")
    print(f"    yV = {hex(yV)}")

    curve = EllipticCurve(p, a, b, xG, yG, q)
    assert curve.verify_point(xG, yG), "G nu este pe curba!"
    assert curve.verify_point(xV, yV), "V nu este pe curba!"
    print("\n[2] Curba verificata ✓")

    m1 = int("DE37B3145DB7359A0ACC13F0A4AFBD67EB496903", 16)
    m2 = int("28469B02BF0D2CFC86FF43CB612EE8FC05A5DBAA", 16)
    r  = int("ACB2C1F5898E7578A8A861BDF1CA39E7EF41EAC0B6AAA49468DD70E2", 16)
    s1 = int("BE4FA99C9D261C5F387A3ACE025702F6FB7884DD07CE18CAD48654B8", 16)
    s2 = int("D3540E2B13E51605F5FEB8C87EE8E176E59213F31EA8B8FFDAD077E2", 16)

    print("\n[3] Vulnerabilitate: nonce reutilizat!")

    print("\n[4] Recuperare cheie...")
    s_priv = recover_private_key(m1, m2, r, s1, s2, q)

    print(f"\n    Cheie privata (dec): {s_priv}")
    print(f"    Cheie privata (hex): {hex(s_priv).upper()}")

    print("\n[5] Verificare...")
    if verify_private_key(curve, s_priv, xV, yV):
        print("    ✓ Cheie corecta!")
    else:
        print("    ✗ Eroare!")

    print("\n" + "=" * 65)
    print(f"FINAL: {hex(s_priv)[2:].upper()}")
    print("=" * 65)
