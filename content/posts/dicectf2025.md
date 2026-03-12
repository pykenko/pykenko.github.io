---
title: "Dice CTF 2026"
date: 2026-03-08
description: "Writeup for Dice CTF 2026"
tags: ["cryptography"]
categories: ["CTF-Writeups"]
showTableOfContents: true
draft: false
---
Team : @Blue Water
![leaderboard](/images/leaderboarddicectf.png)

### Crypto/dot
```
dot dot dot
```

we were given a lot of files but lets focus on the server code first

```python
#server.py
#!/usr/local/bin/python3
import secrets
from fastecdsa.curve import P256
from fastecdsa.encoding.sec1 import SEC1Encoder

import snarg
from add import int_to_bits

if __name__ == '__main__':
	n = 64

	with open('vk.bin', 'rb') as f:
		st = snarg.vk_state(f)

	streak = 0
	while True:
		a = secrets.randbits(n)
		b = secrets.randbits(n)
		print(f'what is {a} + {b}? (mod 2^64)')

		while True:
			c = int(input('answer: '))
			assert 0 <= c < (1 << 64)
			correct = c == (a + b) % (1 << n)

			proof_buf = bytes.fromhex(input('proof: '))
			assert len(proof_buf) == 2 * 33
			h1 = SEC1Encoder.decode_public_key(proof_buf[:33], P256)
			h2 = SEC1Encoder.decode_public_key(proof_buf[33:], P256)

			inputs = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c, n)
			proof = (h1, h2)
			valid = snarg.verify(inputs, st, proof)

			if valid and correct:
				print('correct! but that was obvious...')
				streak = 0
			elif valid and not correct:
				print('huh?')
				streak += 1
				if streak >= 20:
					print(open('flag.txt').read().strip())
					exit()
				break
			else:
				streak = 0
				print('wrong...')
```

you could see here

```python
if valid and correct:
	print('correct! but that was obvious...')
	streak = 0
elif valid and not correct:
	print('huh?')
	streak += 1
	if streak >= 20:
		print(open('flag.txt').read().strip())
		exit()
	break
```

you can see from the code that the challenge is asking us for `c = a + b mod 2^64` and the winning move is giving a valid proof with the wrong c 20 times

```python
def build_adder(n: int) -> Circuit:
    # inputs[0..n-1] = a, inputs[n..2n-1] = b, inputs[2n..3n-1] = c (LSB first)
    # single output wire constrained to 0 iff a+b == c (mod 2^n)
    circ = Circuit(3 * n)
    carry = Wire.constant(False)
    all_match = Wire.constant(True)

    for i in range(n):
        a = circ.inputs[i]
        b = circ.inputs[n + i]
        c = circ.inputs[2 * n + i]

        a_xor_b = circ.xor_gate(a, b)
        sum_bit = circ.xor_gate(a_xor_b, carry)
        carry = circ.or_gate(circ.and_gate(a, b), circ.and_gate(carry, a_xor_b))

        all_match = circ.and_gate(all_match, ~circ.xor_gate(sum_bit, c))

    circ.output_wire(~all_match)
    return circ
```

the checked relation is the adder circuit

lets understand how the snarg works

the setup builds CRS points as : `C_i = q_i * G + sk * H_i`

```python
def hash_to_point(i: int) -> Point:
    p = P256.p
    for ctr in range(256):
        x = int.from_bytes(hashlib.sha256(i.to_bytes(8, 'little') + bytes([ctr])).digest()) % p
        y_sq = (pow(x, 3, p) - 3 * x + P256.b) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if pow(y, 2, p) == y_sq:
            return Point(x, y, curve=P256)
    raise ValueError(f'hash_to_point failed for i={i}')

def compute_c(args: tuple[int, int, int]) -> bytes:
    i, qi, sk = args
    c = qi * P256.G + sk * hash_to_point(i)
    return SEC1Encoder.encode_public_key(c, compressed=True)
```

H_i is public (hash_to_point(i))
q_i is hidden query coefficient
sk is verifier secret

```python
def prove(circuit: Circuit, inputs: list[int], pk: BinaryIO) -> Proof:
    dpp_proof = dpp.prove(circuit, inputs)
    n = len(circuit.inputs)
    h1 = Point._identity_element()
    h2 = Point._identity_element()
    for i, t in enumerate(tqdm(dpp_proof[n:])):
        c_enc = pk.read(33)
        if t == 0:
            continue
        c = SEC1Encoder.decode_public_key(c_enc, P256)
        h1 += t * hash_to_point(i)
        h2 += t * c
    proof = (h1, h2)
    return proof
```

prover sends two points
`h1 = Σ t_i H_i`
`h2 = Σ t_i C_i`

```python
def verify(inputs: list[int], st: State, proof: Proof) -> bool:
    sk, q_inputs, table = st
    assert len(inputs) == len(q_inputs)
    assert all(x in (0, 1) for x in inputs)
    h1, h2 = proof
    p = h2 - sk * h1
    input_sum = sum(q_inputs[i] * inputs[i] for i in range(len(inputs)))
    p += input_sum * P256.G
    p_enc = SEC1Encoder.encode_public_key(p, compressed=True)
    return p_enc in table
```

and the verifier computes

`p = h2 - sk*h1 + input_sum*G`

the key cancellation is `h2 - sk*h1`: mask terms drop out leaving only the hidden dot product part

```python
def sample(circuit: Circuit, bound1: int, bound2: int) -> tuple[Vector, State]:
    n = trace_len(circuit)
    b = n * bound1 + 1
    q1, q2 = tensor_queries(circuit, bound1)
    q3, val = constraint_query(circuit, bound2)
    q = [q1[i] + b * (q2[i] - q3[i]) for i in range(proof_len(circuit))]
    st = (b, val)
    return (q, st)
```

`q` is sampled as : `q = q1 + B*(q2 - q3)`

```python
def tensor_queries(circuit: Circuit, bound: int) -> tuple[Vector, Vector]:
    n = trace_len(circuit)
    v = [random.randint(-bound, bound) for _ in range(n)]
    q1 = [0] * proof_len(circuit)
    q2 = [0] * proof_len(circuit)
    for i in range(n):
        q1[i] = v[i]
        for j in range(i + 1):
            q2[pair_index(circuit, i, j)] = v[i] * v[j] if i == j else 2 * v[i] * v[j]
    return (q1, q2)
```

this is where `q1` and `q2` are built in

```python
def constraint_query(circuit: Circuit, bound: int) -> tuple[Vector, int]:
    query = [0] * proof_len(circuit)
    val = 0
    constraints = chain(input_constraints(circuit), gate_constraints(circuit), output_constraints(circuit))
    for constraint in constraints:
        r = random.randint(-bound, bound)
        for idx, scalar in constraint.scalars:
            query[idx] += r * scalar
        val += r * constraint.constant
    return (query, val)
```

`q3` is random linear combination of input gate output constraints

delta = B*(2*w64*w0 + w128^2) + (w128 - 2*w192 + w193 - w194 + w196 + w200).

# exploit

1. build honest proof for correct `c0=(a+b) mod 2^64`
2. flip only bit 0 `c_wrong = c0 ^ 1`
3. apply a sparse mutation on committed coordinates so local linear constraints still balance
4. this induces scalar shift `delta`
5. add correction `tau*G` with `tau=-delta`, so verifier lands back on accepted scalar

# solver :

```python
#!/usr/bin/env python3
import argparse
import hashlib
import json
import math
import re
import socket
import time
from dataclasses import dataclass

from ecdsa import curves, ellipticcurve

import dpp
from add import build_adder, int_to_bits


HOST = "dot.chals.dicec.tf"
PORT = 1337
MASK64 = (1 << 64) - 1


@dataclass
class RecvResult:
    text: str
    got_token: bool


class DotContext:
    def __init__(self, crs_path: str = "crs.bin") -> None:
        self.curve = curves.NIST256p.curve
        self.G = curves.NIST256p.generator
        self.order = curves.NIST256p.order
        self.p = self.curve.p()
        self.a = self.curve.a()
        self.b = self.curve.b()
        self.INF = ellipticcurve.INFINITY

        self.circuit = build_adder(64)
        self.n_inputs = len(self.circuit.inputs)  # 192
        self.trace_len = dpp.trace_len(self.circuit)  # 636
        self.bound1 = 2**8
        self.B = self.trace_len * self.bound1 + 1  # 162817

        with open(crs_path, "rb") as f:
            self.crs_bytes = f.read()
        if len(self.crs_bytes) % 33 != 0:
            raise ValueError("invalid CRS length")

        self.hash_cache: dict[int, ellipticcurve.Point] = {}
        self.crs_cache: dict[int, ellipticcurve.Point] = {}

        # Non-zero committed deltas for flipping c bit 0 from 0->1 while preserving all linear constraints.
        # Indices below are GLOBAL proof indices (0..proof_len-1), not committed offsets.
        self.mut_plus_global: list[tuple[int, int]] = [
            (192, -2),   # trace[192]
            (193, 1),    # trace[193]
            (194, -1),   # trace[194]
            (196, 1),    # trace[196]
            (200, 1),    # trace[200]
            (2716, 1),   # pair(64, 0)
            (9020, 1),   # pair(128, 128)
        ]
        self.flip_input_idx = 128  # c bit 0 in input vector

        self.delta_h1_plus, self.delta_h2_plus = self._build_delta_points()

        # Pair usage by constraints (to locate free pair coordinates for equality oracles).
        self.used_pairs = self._build_used_pair_set()

    def _build_used_pair_set(self) -> set[tuple[int, int]]:
        used: set[tuple[int, int]] = set()
        for i in range(self.n_inputs):
            used.add((i, i))
        for gate in self.circuit.gates:
            l = gate.left.index
            r = gate.right.index
            used.add((max(l, r), min(l, r)))
        return used

    def _mod_sqrt(self, x: int) -> int | None:
        y = pow(x, (self.p + 1) // 4, self.p)
        if (y * y - x) % self.p != 0:
            return None
        return y

    def decode_comp(self, enc: bytes) -> ellipticcurve.Point:
        if len(enc) != 33 or enc[0] not in (2, 3):
            raise ValueError("bad compressed point")
        x = int.from_bytes(enc[1:], "big")
        yy = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        y = self._mod_sqrt(yy)
        if y is None:
            raise ValueError("point not on curve")
        if (y & 1) != (enc[0] & 1):
            y = (-y) % self.p
        return ellipticcurve.Point(self.curve, x, y, self.order)

    def enc_comp(self, P: ellipticcurve.Point) -> bytes:
        if P == self.INF:
            raise ValueError("cannot encode infinity")
        x = int(P.x())
        y = int(P.y())
        prefix = 3 if (y & 1) else 2
        return bytes([prefix]) + x.to_bytes(32, "big")

    def hash_to_point(self, i: int) -> ellipticcurve.Point:
        p = self.hash_cache.get(i)
        if p is not None:
            return p
        for ctr in range(256):
            x = int.from_bytes(
                hashlib.sha256(i.to_bytes(8, "little") + bytes([ctr])).digest(),
                "big",
            ) % self.p
            yy = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            y = self._mod_sqrt(yy)
            if y is not None:
                p = ellipticcurve.Point(self.curve, x, y, self.order)
                self.hash_cache[i] = p
                return p
        raise RuntimeError(f"hash_to_point failed for {i}")

    def crs_point(self, committed_idx: int) -> ellipticcurve.Point:
        p = self.crs_cache.get(committed_idx)
        if p is not None:
            return p
        off = committed_idx * 33
        enc = self.crs_bytes[off:off + 33]
        if len(enc) != 33:
            raise IndexError("CRS index out of range")
        p = self.decode_comp(enc)
        self.crs_cache[committed_idx] = p
        return p

    def global_to_committed(self, global_idx: int) -> int:
        return global_idx - self.n_inputs

    def pair_global(self, i: int, j: int) -> int:
        hi, lo = (i, j) if i >= j else (j, i)
        return self.trace_len + hi * (hi + 1) // 2 + lo

    def pair_is_free(self, i: int, j: int) -> bool:
        hi, lo = (i, j) if i >= j else (j, i)
        return (hi, lo) not in self.used_pairs

    def _build_delta_points(self) -> tuple[ellipticcurve.Point, ellipticcurve.Point]:
        h1 = self.INF
        h2 = self.INF
        for gidx, coeff in self.mut_plus_global:
            cidx = self.global_to_committed(gidx)
            h1 = h1 + (self.hash_to_point(cidx) * coeff)
            h2 = h2 + (self.crs_point(cidx) * coeff)
        return h1, h2

    def prove_points(self, a: int, b: int, c: int) -> tuple[ellipticcurve.Point, ellipticcurve.Point]:
        inputs = int_to_bits(a, 64) + int_to_bits(b, 64) + int_to_bits(c, 64)
        vec = dpp.prove(self.circuit, inputs)
        h1 = self.INF
        h2 = self.INF
        for i, t in enumerate(vec[self.n_inputs:]):
            if t == 0:
                continue
            h1 = h1 + (self.hash_to_point(i) * t)
            h2 = h2 + (self.crs_point(i) * t)
        return h1, h2

    def proof_hex(self, h1: ellipticcurve.Point, h2: ellipticcurve.Point) -> str:
        return (self.enc_comp(h1) + self.enc_comp(h2)).hex()


class OracleSession:
    def __init__(self, host: str, port: int, timeout: float = 20.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.buf = b""
        self.banner = ""
        self.question: tuple[int, int] | None = None

    def __enter__(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self.banner = self._recv_until_or_eof(b"answer: ").text
        self.question = self._parse_last_question(self.banner)
        if self.question is None:
            raise RuntimeError("failed to parse initial question")
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.sock is not None:
                self.sock.close()
        finally:
            self.sock = None

    def _recv_until_or_eof(self, token: bytes) -> RecvResult:
        assert self.sock is not None
        while token not in self.buf:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return RecvResult(self.buf.decode(errors="ignore"), False)
            if not chunk:
                out = self.buf
                self.buf = b""
                return RecvResult(out.decode(errors="ignore"), False)
            self.buf += chunk
        idx = self.buf.index(token) + len(token)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return RecvResult(out.decode(errors="ignore"), True)

    @staticmethod
    def _parse_last_question(text: str) -> tuple[int, int] | None:
        matches = re.findall(r"what is (\d+) \+ (\d+)\? \(mod 2\^64\)", text)
        if not matches:
            return None
        a, b = matches[-1]
        return (int(a), int(b))

    def submit(self, ans: int, proof_hex: str) -> RecvResult:
        assert self.sock is not None
        self.sock.sendall(f"{ans}\n".encode())
        _ = self._recv_until_or_eof(b"proof: ")
        self.sock.sendall((proof_hex + "\n").encode())
        return self._recv_until_or_eof(b"answer: ")


def centered_values(limit: int) -> list[int]:
    out = [0]
    for k in range(1, limit + 1):
        out.append(k)
        out.append(-k)
    return out


def recover_t_for_pair(
    dot: DotContext,
    host: str,
    port: int,
    cidx_pair: int,
    t_candidates: list[int],
    label: str,
) -> int:
    start = time.time()
    with OracleSession(host, port) as sess:
        a, b = sess.question
        c = (a + b) & MASK64
        print(f"[{label}] building baseline proof for a={a} b={b}")
        t0 = time.time()
        h1, h2 = dot.prove_points(a, b, c)
        print(f"[{label}] baseline proof in {time.time() - t0:.2f}s")

        h1_fixed = h1 + dot.hash_to_point(cidx_pair)
        h2_fixed = h2 + dot.crs_point(cidx_pair)

        for qn, t in enumerate(t_candidates, start=1):
            h2_q = h2_fixed + ((-dot.B * t) * dot.G)
            proof_hex = dot.proof_hex(h1_fixed, h2_q)
            resp = sess.submit(c, proof_hex).text
            if "correct! but that was obvious..." in resp:
                print(f"[{label}] found t={t} after {qn}/{len(t_candidates)} queries ({time.time() - start:.1f}s)")
                return t
    raise RuntimeError(f"[{label}] no candidate worked")


def anchor_candidates(dot: DotContext, targets: list[int]) -> list[int]:
    out: list[int] = []
    for anchor in range(192, dot.trace_len):
        ok = True
        for idx in targets:
            if idx == anchor:
                continue
            if not dot.pair_is_free(anchor, idx):
                ok = False
                break
        if ok:
            out.append(anchor)
    return out


def calibrate(dot: DotContext, host: str, port: int) -> dict:
    targets = [0, 64, 128, 192, 193, 194, 196, 200]
    cands = anchor_candidates(dot, targets)
    if not cands:
        raise RuntimeError("no suitable anchor found")
    print(f"[calib] anchor candidates: {len(cands)}")

    abs_anchor = 0
    anchor = -1
    square_candidates = [u * u for u in range(257)]
    for cand in cands:
        print(f"[calib] trying anchor {cand}")
        diag_global = dot.pair_global(cand, cand)
        diag_comm = dot.global_to_committed(diag_global)
        t_sq = recover_t_for_pair(dot, host, port, diag_comm, square_candidates, f"diag-{cand}")
        abs_cand = int(math.isqrt(t_sq))
        if abs_cand != 0:
            anchor = cand
            abs_anchor = abs_cand
            break
    if anchor == -1:
        raise RuntimeError("all tested anchors had v=0 (unlikely), rerun")
    print(f"[calib] chosen anchor trace index: {anchor}, |v[{anchor}]|={abs_anchor}")

    # Recover w_i = v_i * sign(v_anchor) for all needed indices through free off-diagonal pairs.
    w: dict[int, int] = {anchor: abs_anchor}
    uv = centered_values(256)
    t_candidates = [2 * abs_anchor * u for u in uv]
    for idx in targets:
        if idx == anchor:
            continue
        pg = dot.pair_global(idx, anchor)
        if not dot.pair_is_free(idx, anchor):
            raise RuntimeError(f"pair({max(idx, anchor)},{min(idx, anchor)}) unexpectedly not free")
        pc = dot.global_to_committed(pg)
        t_val = recover_t_for_pair(dot, host, port, pc, t_candidates, f"pair-{idx}-{anchor}")
        w[idx] = t_val // (2 * abs_anchor)
        print(f"[calib] w[{idx}]={w[idx]}")

    # Compute delta for +1 flip of c bit0.
    Q = 2 * w[64] * w[0] + w[128] * w[128]
    Lw = w[128] - 2 * w[192] + w[193] - w[194] + w[196] + w[200]
    delta_candidates = [dot.B * Q + Lw, dot.B * Q - Lw]
    print(f"[calib] delta candidates: {delta_candidates[0]} / {delta_candidates[1]}")

    return {
        "anchor": anchor,
        "abs_anchor": abs_anchor,
        "w": {str(k): int(v) for k, v in sorted(w.items())},
        "delta_candidates": [int(delta_candidates[0]), int(delta_candidates[1])],
    }


def test_delta_candidate(dot: DotContext, host: str, port: int, delta: int) -> bool:
    with OracleSession(host, port) as sess:
        a, b = sess.question
        c0 = (a + b) & MASK64
        bit0 = c0 & 1
        sign = 1 if bit0 == 0 else -1  # flip 0->1 uses +mutation; flip 1->0 uses -mutation
        c_wrong = c0 ^ 1

        print(f"[test] building baseline proof for candidate delta={delta}")
        h1, h2 = dot.prove_points(a, b, c0)
        h1m = h1 + (dot.delta_h1_plus * sign)
        tau = -sign * delta
        h2m = h2 + (dot.delta_h2_plus * sign) + (tau * dot.G)
        resp = sess.submit(c_wrong, dot.proof_hex(h1m, h2m)).text
        return "huh?" in resp


def exploit(dot: DotContext, host: str, port: int, delta: int) -> str | None:
    with OracleSession(host, port) as sess:
        q = sess.question
        for round_idx in range(1, 21):
            if q is None:
                raise RuntimeError("missing question state")
            a, b = q
            c0 = (a + b) & MASK64
            bit0 = c0 & 1
            sign = 1 if bit0 == 0 else -1
            c_wrong = c0 ^ 1

            print(f"[exploit] round {round_idx}/20 a={a} b={b} c_wrong={c_wrong}")
            t0 = time.time()
            h1, h2 = dot.prove_points(a, b, c0)
            print(f"[exploit] baseline proof in {time.time() - t0:.2f}s")
            h1m = h1 + (dot.delta_h1_plus * sign)
            tau = -sign * delta
            h2m = h2 + (dot.delta_h2_plus * sign) + (tau * dot.G)

            rr = sess.submit(c_wrong, dot.proof_hex(h1m, h2m))
            text = rr.text
            if "huh?" not in text:
                print("[exploit] failed response:")
                print(text)
                return None

            flag_match = re.search(r"dice\{[^}\n]+\}", text)
            if flag_match:
                return flag_match.group(0)

            q = OracleSession._parse_last_question(text)
            if q is None and round_idx < 20:
                print("[exploit] no next question after non-final round")
                print(text)
                return None

        return None


def main() -> None:
    ap = argparse.ArgumentParser(description="diceCTF dot solver")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--mode", choices=["auto", "calibrate", "exploit"], default="auto")
    ap.add_argument("--calib-out", default="calib_dot.json")
    ap.add_argument("--delta", type=int, default=None)
    args = ap.parse_args()

    dot = DotContext("crs.bin")

    if args.mode == "calibrate":
        calib = calibrate(dot, args.host, args.port)
        with open(args.calib_out, "w", encoding="utf-8") as f:
            json.dump(calib, f, indent=2)
        print(f"[calib] wrote {args.calib_out}")
        return

    if args.mode == "exploit":
        if args.delta is None:
            raise SystemExit("--delta is required in exploit mode")
        flag = exploit(dot, args.host, args.port, args.delta)
        if flag is None:
            raise SystemExit("exploit failed")
        print(flag)
        return

    # auto mode: calibrate, pick candidate delta, exploit.
    calib = calibrate(dot, args.host, args.port)
    with open(args.calib_out, "w", encoding="utf-8") as f:
        json.dump(calib, f, indent=2)
    print(f"[auto] wrote calibration to {args.calib_out}")

    d1, d2 = calib["delta_candidates"]
    ok1 = test_delta_candidate(dot, args.host, args.port, d1)
    ok2 = False if ok1 else test_delta_candidate(dot, args.host, args.port, d2)
    if ok1:
        delta = d1
    elif ok2:
        delta = d2
    else:
        raise SystemExit("neither delta candidate validated")
    print(f"[auto] selected delta={delta}")

    flag = exploit(dot, args.host, args.port, delta)
    if flag is None:
        raise SystemExit("exploit failed")
    print(flag)


if __name__ == "__main__":
    main()
```

```bash
renko@kenko:/mnt/d/cysec/ctf/dicectf2026/cryptography/dot/crypto_dot$ python3 solve_dot.py
[calib] chosen anchor trace index: 193
[diag-193] building baseline proof for a=1143924102721120520 b=6325762473948497649
[diag-193] baseline proof in 2.24s
[diag-193] found t=9 after 4/257 queries (4.9s)
[calib] |v[193]|=3
[pair-0-193] building baseline proof for a=14292119506489566517 b=9328380076037281372
[pair-0-193] baseline proof in 1.66s
[pair-0-193] found t=-480 after 161/513 queries (85.3s)
[calib] w[0]=-80
[pair-64-193] building baseline proof for a=7503877077099562488 b=15316753742228173668
[pair-64-193] baseline proof in 1.18s
[pair-64-193] found t=-330 after 111/513 queries (61.0s)
[calib] w[64]=-55
[pair-128-193] building baseline proof for a=264958254567826355 b=890884713356802596
[pair-128-193] baseline proof in 1.06s
[pair-128-193] found t=1236 after 412/513 queries (219.8s)
[calib] w[128]=206
[pair-192-193] building baseline proof for a=6744771575691568094 b=16837101583634646961
[pair-192-193] baseline proof in 1.07s
[pair-192-193] found t=-204 after 69/513 queries (36.5s)
[calib] w[192]=-34
[pair-194-193] building baseline proof for a=9981025517874141537 b=14208830074159424610
[pair-194-193] baseline proof in 0.92s
[pair-194-193] found t=-600 after 201/513 queries (108.5s)
[calib] w[194]=-100
[pair-196-193] building baseline proof for a=13680183852207508423 b=4367329207629035158
[pair-196-193] baseline proof in 0.93s
[pair-196-193] found t=-954 after 319/513 queries (160.5s)
[calib] w[196]=-159
[pair-200-193] building baseline proof for a=6728160738614538357 b=13511480285019320890
[pair-200-193] baseline proof in 0.75s
[pair-200-193] found t=-1428 after 477/513 queries (240.7s)
[calib] w[200]=-238
[calib] delta candidates: 8342091792 / 8342091832
[auto] wrote calibration to calib_dot.json
[test] building baseline proof for candidate delta=8342091792
[test] building baseline proof for candidate delta=8342091832
[auto] selected delta=8342091832
[exploit] round 1/20 a=5150555423284214392 b=6706125030925003821 c_wrong=11856680454209218212
[exploit] baseline proof in 0.70s
[exploit] round 2/20 a=7238142302456587014 b=17912208006496107503 c_wrong=6703606235243142900
[exploit] baseline proof in 0.67s
[exploit] round 3/20 a=9054218269958678656 b=6784083205767138826 c_wrong=15838301475725817483
[exploit] baseline proof in 0.64s
[exploit] round 4/20 a=3381916289642056776 b=13832282071887762720 c_wrong=17214198361529819497
[exploit] baseline proof in 0.62s
[exploit] round 5/20 a=583515946189994860 b=17319997006605803379 c_wrong=17903512952795798238
[exploit] baseline proof in 0.67s
[exploit] round 6/20 a=13382481024978367744 b=17137591210498223556 c_wrong=12073328161767039685
[exploit] baseline proof in 0.61s
[exploit] round 7/20 a=13269421222990451726 b=18202616238818622884 c_wrong=13025293388099522995
[exploit] baseline proof in 0.55s
[exploit] round 8/20 a=4506545153214207513 b=17596510309607786596 c_wrong=3656311389112442492
[exploit] baseline proof in 0.60s
[exploit] round 9/20 a=4009554230785737274 b=10613006504628255427 c_wrong=14622560735413992700
[exploit] baseline proof in 0.63s
[exploit] round 10/20 a=12386414385267413214 b=14062469589437438022 c_wrong=8002139900995299621
[exploit] baseline proof in 0.59s
[exploit] round 11/20 a=18231364426820024128 b=48385806432331343 c_wrong=18279750233252355470
[exploit] baseline proof in 0.65s
[exploit] round 12/20 a=2607002374806135356 b=15254685974214370368 c_wrong=17861688349020505725
[exploit] baseline proof in 0.62s
[exploit] round 13/20 a=17929260924834081429 b=2925700195429956088 c_wrong=2408217046554485900
[exploit] baseline proof in 0.56s
[exploit] round 14/20 a=4914734947681698909 b=9178684097835086250 c_wrong=14093419045516785158
[exploit] baseline proof in 0.56s
[exploit] round 15/20 a=16136399890751063408 b=3895971588966504817 c_wrong=1585627406008016608
[exploit] baseline proof in 0.51s
[exploit] round 16/20 a=8563137490026112027 b=7326843205279167543 c_wrong=15889980695305279571
[exploit] baseline proof in 0.57s
[exploit] round 17/20 a=15432286427297330236 b=13991167986850388735 c_wrong=10976710340438167354
[exploit] baseline proof in 0.60s
[exploit] round 18/20 a=10652795860390230935 b=8148724863567164824 c_wrong=354776650247844142
[exploit] baseline proof in 0.55s
[exploit] round 19/20 a=2688117725924471092 b=15076820742262794371 c_wrong=17764938468187265462
[exploit] baseline proof in 0.58s
[exploit] round 20/20 a=16866452301079276372 b=2490895111612926496 c_wrong=910603338982651253
[exploit] baseline proof in 0.48s
dice{operation_spot_by_odd_part_of_drug_city}
```

{{< alert icon="check-circle" cardColor="#10b981" >}}
**Flag found:** `dice{operation_spot_by_odd_part_of_drug_city}`
{{< /alert >}}