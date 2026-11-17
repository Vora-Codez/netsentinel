"""Tiny QR Code encoder (byte mode, error correction level M) that returns an SVG.

Used to show the two-factor setup code so a phone can scan it. Pure standard library, so it works
offline and inside the single-file exe. Follows ISO/IEC 18004, structured after Project Nayuki's
public-domain reference implementation.
"""

# Index = version (1-40); level M only.
_ECC_PER_BLOCK = (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26,
                  28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28)
_NUM_BLOCKS = (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21,
               23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49)
_FORMAT_BITS_M = 0


def _raw_modules(ver):
    n = (16 * ver + 128) * ver + 64
    if ver >= 2:
        align = ver // 7 + 2
        n -= (25 * align - 10) * align - 55
        if ver >= 7:
            n -= 36
    return n


def _data_codewords(ver):
    return _raw_modules(ver) // 8 - _ECC_PER_BLOCK[ver] * _NUM_BLOCKS[ver]


def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(len(result)):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < len(result):
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


class _Qr:
    def __init__(self, ver, codewords):
        self.ver = ver
        self.size = ver * 4 + 17
        self.mod = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]
        self._draw_function_patterns()
        self._draw_codewords(self._interleave(codewords))
        best = None
        for mask in range(8):
            self._apply_mask(mask)
            self._draw_format(mask)
            score = self._penalty()
            if best is None or score < best[0]:
                best = (score, mask)
            self._apply_mask(mask)                       # XOR again to undo
        self._apply_mask(best[1])
        self._draw_format(best[1])

    # -- function patterns -------------------------------------------------
    def _set_fn(self, x, y, dark):
        self.mod[y][x] = dark
        self.fn[y][x] = True

    def _draw_function_patterns(self):
        s = self.size
        for i in range(s):
            self._set_fn(6, i, i % 2 == 0)
            self._set_fn(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (s - 4, 3), (3, s - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < s and 0 <= y < s:
                        self._set_fn(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = self._alignment_positions()
        last = len(pos) - 1
        for i, a in enumerate(pos):
            for j, b in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set_fn(a + dx, b + dy, max(abs(dx), abs(dy)) != 1)
        self._draw_format(0)
        self._draw_version()

    def _alignment_positions(self):
        if self.ver == 1:
            return []
        n = self.ver // 7 + 2
        step = (self.ver * 8 + n * 3 + 5) // (n * 4 - 4) * 2
        return [6] + sorted(self.size - 7 - i * step for i in range(n - 1))

    def _draw_format(self, mask):
        data = _FORMAT_BITS_M << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1 != 0
        s = self.size
        for i in range(6):
            self._set_fn(8, i, bit(i))
        self._set_fn(8, 7, bit(6))
        self._set_fn(8, 8, bit(7))
        self._set_fn(7, 8, bit(8))
        for i in range(9, 15):
            self._set_fn(14 - i, 8, bit(i))
        for i in range(8):
            self._set_fn(s - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self._set_fn(8, s - 15 + i, bit(i))
        self._set_fn(8, s - 8, True)                       # the always-dark module

    def _draw_version(self):
        if self.ver < 7:
            return
        rem = self.ver
        for _ in range(12):
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
        bits = self.ver << 12 | rem
        for i in range(18):
            dark = (bits >> i) & 1 != 0
            a, b = self.size - 11 + i % 3, i // 3
            self._set_fn(a, b, dark)
            self._set_fn(b, a, dark)

    # -- data --------------------------------------------------------------
    def _interleave(self, data):
        nblocks, ecclen = _NUM_BLOCKS[self.ver], _ECC_PER_BLOCK[self.ver]
        raw = _raw_modules(self.ver) // 8
        nshort = nblocks - raw % nblocks
        shortlen = raw // nblocks
        div = _rs_divisor(ecclen)
        blocks, k = [], 0
        for i in range(nblocks):
            dat = data[k:k + shortlen - ecclen + (0 if i < nshort else 1)]
            k += len(dat)
            ecc = _rs_remainder(dat, div)
            if i < nshort:
                dat = dat + [0]
            blocks.append(dat + ecc)
        out = []
        for i in range(len(blocks[0])):
            for j, blk in enumerate(blocks):
                if i != shortlen - ecclen or j >= nshort:
                    out.append(blk[i])
        return out

    def _draw_codewords(self, data):
        i, s = 0, self.size
        right = s - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(s):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = s - 1 - vert if upward else vert
                    if not self.fn[y][x] and i < len(data) * 8:
                        self.mod[y][x] = (data[i >> 3] >> (7 - (i & 7))) & 1 != 0
                        i += 1
            right -= 2

    def _apply_mask(self, mask):
        conds = (lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
                 lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
                 lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
                 lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0)
        f = conds[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.fn[y][x] and f(x, y):
                    self.mod[y][x] = not self.mod[y][x]

    def _penalty(self):
        """ISO penalty: long runs, 2x2 blocks, finder-like patterns, dark/light balance."""
        s, m, score = self.size, self.mod, 0
        finder_a = (False,) * 4 + (True, False, True, True, True, False, True)
        finder_b = finder_a[::-1]
        for lines in (m, list(zip(*m))):
            for row in lines:
                padded = (False,) * 4 + tuple(row) + (False,) * 4
                for i in range(len(padded) - 10):
                    window = padded[i:i + 11]
                    if window == finder_a or window == finder_b:
                        score += 40
                run, prev = 0, None
                for v in row:
                    if v == prev:
                        run += 1
                    else:
                        if run >= 5:
                            score += run - 2
                        run, prev = 1, v
                if run >= 5:
                    score += run - 2
        for y in range(s - 1):
            for x in range(s - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(v for row in m for v in row)
        score += abs(dark * 20 - s * s * 10) // (s * s) * 10
        return score


def encode(text: str) -> _Qr:
    data = text.encode("utf-8")
    for ver in range(1, 41):
        cap = _data_codewords(ver)
        count_bits = 8 if ver < 10 else 16
        if 4 + count_bits + len(data) * 8 <= cap * 8:
            break
    else:
        raise ValueError("Text too long for a QR code.")
    bits = []
    add = lambda val, n: bits.extend((val >> i) & 1 for i in reversed(range(n)))
    add(0b0100, 4)
    add(len(data), count_bits)
    for b in data:
        add(b, 8)
    add(0, min(4, cap * 8 - len(bits)))
    add(0, (8 - len(bits) % 8) % 8)
    pad = 0xEC
    while len(bits) < cap * 8:
        add(pad, 8)
        pad ^= 0xEC ^ 0x11
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    return _Qr(ver, codewords)


def svg(text: str, border: int = 4) -> str:
    q = encode(text)
    n = q.size + border * 2
    path = "".join(f"M{x + border},{y + border}h1v1h-1z" for y in range(q.size) for x in range(q.size) if q.mod[y][x])
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" shape-rendering="crispEdges">'
            f'<rect width="100%" height="100%" fill="#ffffff"/><path d="{path}" fill="#000000"/></svg>')
