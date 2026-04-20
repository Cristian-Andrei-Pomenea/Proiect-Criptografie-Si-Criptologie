# ECDSA Private Key Recovery

Tool pentru recuperarea cheii private ECDSA, cu suport pentru doua atacuri distincte aplicate automat in cascada.

Dezvoltat initial ca solutie pentru **MITRE ICCS 2012 Multi-Day Challenge**, dar proiectat sa functioneze generic pe orice set de semnaturi ECDSA vulnerabile.

---

## Atacuri implementate

### 1. Nonce Reuse Attack
Daca acelasi nonce efemer `k` a fost folosit pentru a semna doua mesaje diferite, componentele `r` ale semnaturilor vor fi identice. In acest caz, cheia privata se recupereaza direct printr-o formula algebrica simpla:

```
d = (m2*s1 - m1*s2) / (r*(s2 - s1))  mod q
```

Detectia este automata — scriptul grupeaza semnaturile dupa valoarea `r` si exploateaza orice coliziune gasita.

### 2. Lattice Attack (HNP)
Daca nonce-ul nu e reutilizat dar este **slab** (primii `l` biti sunt zero sau cunoscuti), vulnerabilitatea se modeleaza ca un **Hidden Number Problem** si se rezolva prin constructia unei retele LLL:

- Necesita biblioteca `fpylll`
- Functioneaza cu minim 4 semnaturi si `l >= 4` biti slabi
- Configurat implicit pentru `l = 8` biti si maxim 8 semnaturi

Lattice attack-ul este incercat automat daca nonce reuse-ul nu produce rezultate.

---

## Fisiere

| Fisier | Descriere |
|---|---|
| `solve_ecdsa_base.py` | Solutie simpla, specifica challengeului MITRE |
| `solve_ecdsa_strong.py` | Tool generic cu detectie automata si fallback lattice |
| `parameters.der` | Parametrii curbei eliptice (format DER binar) |
| `public.oct` | Cheia publica (format octet necomprimat) |
| `signatures.txt` | Semnaturile ECDSA de analizat |

---

## Utilizare

### Varianta de baza
```bash
# Asigura-te ca parameters.der, public.oct si signatures.txt
# sunt in acelasi director cu scriptul
python3 solve_ecdsa_base.py
```

### Varianta generica
```bash
# Fara lattice (doar stdlib)
python3 solve_ecdsa_strong.py

# Cu lattice attack activat
pip install fpylll
python3 solve_ecdsa_strong.py
```

Semnaturile pot fi furnizate in doua formate, detectate automat:

**Text** (`signatures.txt`):
```
Signature 1:
Hash: DE37B3...
R: ACB2C1...
S: BE4FA9...
```

**JSON** (`signatures.json`):
```json
[
  {"hash": "DE37B3...", "r": "ACB2C1...", "s": "BE4FA9..."},
  {"hash": "28469B...", "r": "ACB2C1...", "s": "D3540E..."}
]
```

---

## Rezultat (challengeul MITRE)

```
[*] Running FULL AUTO attack
[+] Reuse detected → exploiting
[✔] PRIVATE KEY (reuse)

==============================================================
FINAL PRIVATE KEY:
8E88B0433C87D1269173487795C81553AD819A1123AE54854B3C0DA7
==============================================================
```

Verificare: `d * G == Q` ✓

---

## Dependente

| Librarie | Necesara pentru | Instalare |
|---|---|---|
| Python 3.9+ | tot | — |
| `fpylll` | Lattice attack | `pip install fpylll` |

Fara `fpylll`, scriptul ruleaza normal si sare automat peste lattice attack.

---

## Lectii de securitate

- **O singura reutilizare a nonce-ului expune complet cheia privata**, indiferent de dimensiunea curbei.
- Atacuri reale: Sony PlayStation 3 (2010) — nonce constant; Android Bitcoin wallets (2012) — PRNG defect.
- Solutia corecta: **RFC 6979** — nonce determinist derivat din mesaj si cheie privata via HMAC-DRBG.
