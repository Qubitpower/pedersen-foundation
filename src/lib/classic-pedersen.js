// Classic (1991-style) Pedersen commitment over a prime-order subgroup of Z_p*.
//
// p is the RFC 3526 "2048-bit MODP Group 14" prime, a safe prime (p = 2q + 1,
// q prime) published for Diffie-Hellman key exchange. We reuse it here purely
// because it is a real, citable, publicly verifiable safe prime — not because
// this demo needs IKE-grade parameters.
// https://www.rfc-editor.org/rfc/rfc3526 (see the 2048-bit MODP Group / Group 14)
const P_HEX = `
  FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
  29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
  EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
  E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
  EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
  C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
  83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
  670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
  E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
  DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
  15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
`.replace(/\s+/g, '');

const P_REAL = BigInt('0x' + P_HEX);

/**
 * Square-and-multiply modular exponentiation.
 * @param {bigint} base
 * @param {bigint} exp
 * @param {bigint} mod
 * @returns {bigint}
 */
export function modPow(base, exp, mod) {
  base %= mod;
  if (base < 0n) base += mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function bytesToBigInt(bytes) {
  let hex = '0x0';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex);
}

async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

/**
 * Nothing-up-my-sleeve field element: expand a domain-separated tag with
 * counter-mode SHA-256 until we have enough bytes to cover the modulus, then
 * reduce. byteLen defaults to 256 (covers our 2048-bit real group); it's
 * harmless overkill for the small toy group, just a few wasted hash calls.
 */
async function hashToFieldElement(tag, mod, byteLen = 256) {
  const blocks = [];
  let total = 0;
  let counter = 0;
  while (total < byteLen) {
    const input = new TextEncoder().encode(`${tag}#${counter}`);
    const block = await sha256(input);
    blocks.push(block);
    total += block.length;
    counter++;
  }
  const concatenated = new Uint8Array(total);
  let offset = 0;
  for (const block of blocks) {
    concatenated.set(block, offset);
    offset += block.length;
  }
  let x = bytesToBigInt(concatenated.slice(0, byteLen)) % mod;
  if (x < 2n) x += 2n;
  return x;
}

/**
 * Derive a generator of the order-q subgroup by hashing a public tag to a
 * field element and squaring it (squaring any element of Z_p* lands it in
 * the unique subgroup of index 2, which has order q since p = 2q + 1).
 * Retries with a different attempt suffix on the negligible chance the
 * squared value is the identity (only realistically reachable in the toy
 * group, where the field is tiny).
 */
async function deriveGenerator(tag, p) {
  let attempt = 0;
  while (true) {
    const x = await hashToFieldElement(`${tag}#attempt${attempt}`, p);
    const g = modPow(x, 2n, p);
    if (g !== 1n) return g;
    attempt++;
  }
}

/** Build an independent classic Pedersen group over Z_p* for a safe prime p. */
export function createGroup(p, label) {
  const Q = (p - 1n) / 2n;
  let generatorsPromise = null;

  function getGenerators() {
    if (!generatorsPromise) {
      generatorsPromise = Promise.all([
        deriveGenerator(`${label} generator g v1`, p),
        deriveGenerator(`${label} generator h v1`, p),
      ]).then(([g, h]) => ({ g, h }));
    }
    return generatorsPromise;
  }

  function randomExponent() {
    const bytes = new Uint8Array(256);
    crypto.getRandomValues(bytes);
    return bytesToBigInt(bytes) % Q;
  }

  async function commit(m, r) {
    const { g, h } = await getGenerators();
    return (modPow(g, m, p) * modPow(h, r, p)) % p;
  }

  async function verify(m, r, C) {
    const { g, h } = await getGenerators();
    return (modPow(g, m, p) * modPow(h, r, p)) % p === C;
  }

  return { P: p, Q, label, getGenerators, randomExponent, commit, verify };
}

/** The real, RFC-3526-backed group used by the site's main demos. */
export const REAL = createGroup(P_REAL, 'pedersen.foundation classic-demo');

/**
 * A deliberately tiny group (p = 23, q = 11) for the binding sandbox: small
 * enough to brute-force every (m, r) pair in the browser instantly, which is
 * the whole point — it makes concrete that binding is "just" a search
 * problem, one that happens to be astronomically large at real parameter
 * sizes. 23 is prime and (23-1)/2 = 11 is also prime, so it has the same
 * safe-prime structure as the real group, just scaled down.
 */
export const TOY = createGroup(23n, 'pedersen.foundation toy-demo');

// Backward-compatible flat exports (used by the homepage demo) bound to REAL.
export const P = REAL.P;
export const Q = REAL.Q;
export const getGenerators = REAL.getGenerators;
export const randomExponent = REAL.randomExponent;
export const commit = REAL.commit;
export const verify = REAL.verify;

/**
 * Modular inverse via the extended Euclidean algorithm.
 * @param {bigint} a
 * @param {bigint} m
 * @returns {bigint}
 */
export function modInverse(a, m) {
  a = ((a % m) + m) % m;
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return ((oldS % m) + m) % m;
}

export function toShortHex(n, chars = 48) {
  const hex = n.toString(16);
  return hex.length > chars ? `0x${hex.slice(0, chars)}…` : `0x${hex}`;
}
