// Modern (elliptic-curve) Pedersen commitment: Commit(m, r) = m*G + r*H.
//
// Curve: secp256k1, via the audited @noble/curves library. G is the curve's
// standard base point. H is produced with @noble/curves' built-in RFC 9380
// hash-to-curve implementation (secp256k1_hasher), which maps a domain-
// separated tag directly onto a curve point — nothing-up-my-sleeve by
// construction, no discrete log relative to G is knowable.
import { secp256k1, secp256k1_hasher } from '@noble/curves/secp256k1.js';

const G = secp256k1.Point.BASE;
export const N = secp256k1.Point.Fn.ORDER; // curve order

const DST = 'pedersen.foundation-ec-demo-v1';
const H = secp256k1_hasher.hashToCurve(
  new TextEncoder().encode('pedersen.foundation classic-demo generator H'),
  { DST }
);

export function getGenerators() {
  return { G, H };
}

/** Uniform random scalar in [0, N). */
export function randomExponent() {
  const bytes = new Uint8Array(48); // extra bytes over 32 to keep mod bias negligible
  crypto.getRandomValues(bytes);
  let hex = '0x0';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex) % N;
}

/** Commit(m, r) = m*G + r*H, as a curve point. */
export function commit(m, r) {
  return G.multiply(((m % N) + N) % N).add(H.multiply(((r % N) + N) % N));
}

/** Recompute m*G + r*H and compare against a previously issued commitment point. */
export function verify(m, r, C) {
  return commit(m, r).equals(C);
}

/** Compressed point hex, e.g. 0x02ab…  (33 bytes → 66 hex chars, unabridged). */
export function toHex(point) {
  return '0x' + point.toHex(true);
}
