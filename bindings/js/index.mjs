// zig-stark Binius zero-check STARK — wasm32 JS binding (ESM).
//
// Loads bindings/js/zig_stark_capi.wasm and exposes a high-level
// `proveColumns` / `verify` API over the generic constraint interface. The
// statement is encoded on the canonical wire format (u64 length prefixes,
// little-endian; see docs/wire.md and zig-capi.h).
//
// Memory: a JS-side bump allocator provides the module's malloc/free (the wasm
// stores an internal alignment header per block; free is a no-op because the
// bump is monotonic). Each module instance owns a growing linear memory, so
// for long-running processes prefer re-instantiating periodically or provide a
// reclaiming allocator.

export const ZS_OK = 0;
export const ZS_ERR = { generic: -1, invalid: -2, oom: -3, protocol: -4 };

const enc = new TextEncoder();

function u64(dv, o, v) {
  dv.setBigUint64(o, BigInt(v), true);
  return o + 8;
}
function u8(dv, o, v) {
  dv.setUint8(o, v);
  return o + 1;
}

export function encodeColumns(columns) {
  let size = 8;
  for (const c of columns) size += 8 + c.length;
  const buf = new ArrayBuffer(size);
  const dv = new DataView(buf);
  let o = 0;
  o = u64(dv, o, columns.length);
  for (const c of columns) {
    o = u64(dv, o, c.length);
    new Uint8Array(buf, o, c.length).set(c);
    o += c.length;
  }
  return new Uint8Array(buf);
}

export function encodeConstraints(constraints) {
  let size = 8;
  for (const c of constraints) {
    size += 8;
    for (const t of c.terms) size += 1 + 8 + 8 * t.factors.length;
  }
  const buf = new ArrayBuffer(size);
  const dv = new DataView(buf);
  let o = 0;
  o = u64(dv, o, constraints.length);
  for (const c of constraints) {
    o = u64(dv, o, c.terms.length);
    for (const t of c.terms) {
      o = u8(dv, o, t.coeff);
      o = u64(dv, o, t.factors.length);
      for (const f of t.factors) o = u64(dv, o, f);
    }
  }
  return new Uint8Array(buf);
}

export function encodePins(pins) {
  let size = 8;
  for (const p of pins) size += 8 + 8 + 1;
  const buf = new ArrayBuffer(size);
  const dv = new DataView(buf);
  let o = 0;
  o = u64(dv, o, pins.length);
  for (const p of pins) {
    o = u64(dv, o, p.col);
    o = u64(dv, o, p.point);
    o = u8(dv, o, p.value);
  }
  return new Uint8Array(buf);
}

function encodeRoots(roots) {
  const buf = new ArrayBuffer(8 + 32 * roots.length);
  const dv = new DataView(buf);
  let o = u64(dv, 0, roots.length);
  for (const r of roots) {
    new Uint8Array(buf, o, 32).set(r);
    o += 32;
  }
  return new Uint8Array(buf);
}

function decodeRoots(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = Number(dv.getBigUint64(0, true));
  const roots = [];
  let o = 8;
  for (let i = 0; i < count; i++) {
    roots.push(bytes.slice(o, o + 32));
    o += 32;
  }
  return roots;
}

export async function loadZigStark(wasmBytes) {
  let instance;
  let bump = 16; // never return 0: Zig treats 0 as the null pointer
  const malloc = (size) => {
    const memory = instance.exports.memory;
    const start = (bump + 7) & ~7;
    if (start + size > memory.buffer.byteLength) {
      const pages = Math.ceil((start + size - memory.buffer.byteLength) / 65536);
      memory.grow(pages);
    }
    bump = start + size;
    return start;
  };
  const free = () => {};

  const { instance: inst } = await WebAssembly.instantiate(wasmBytes, {
    env: { zig_stark_malloc: malloc, zig_stark_free: free },
  });
  instance = inst;

  const view = () => new Uint8Array(instance.exports.memory.buffer);
  const dv = () => new DataView(instance.exports.memory.buffer);
  const putBytes = (ptr, bytes) => view().set(bytes, ptr);

  function version() {
    const p = instance.exports.zs_version();
    const v = view();
    let s = '';
    for (let i = p; v[i] !== 0; i++) s += String.fromCharCode(v[i]);
    return s;
  }

  /** Prove a generic zero-check statement.
   * @param {{k: number, columns: Uint8Array[], constraints: {terms:{coeff:number,factors:number[]}[]}[], pins?: {col:number,point:number,value:number}[], domain?: string}} stmt
   * @returns {{proof: Uint8Array, roots: Uint8Array[]}} */
  function proveColumns({ k, columns, constraints, pins = [], domain = '' }) {
    const colB = encodeColumns(columns);
    const conB = encodeConstraints(constraints);
    const pinB = encodePins(pins);
    const domB = enc.encode(domain);
    const colPtr = malloc(colB.length); putBytes(colPtr, colB);
    const conPtr = malloc(conB.length); putBytes(conPtr, conB);
    const pinPtr = malloc(pinB.length); putBytes(pinPtr, pinB);
    const domPtr = malloc(domB.length); putBytes(domPtr, domB);

    const proofPtrSlot = malloc(4);
    const proofLenSlot = malloc(4);
    const rc = instance.exports.zs_binius_prove_wm(
      k, colPtr, colB.length, conPtr, conB.length, pinPtr, pinB.length, domPtr, domB.length,
      proofPtrSlot, proofLenSlot,
    );
    const rootsPtrSlot = malloc(4);
    const rootsLenSlot = malloc(4);
    const rc2 = instance.exports.zs_binius_commit_wm(k, colPtr, colB.length, rootsPtrSlot, rootsLenSlot);
    if (rc !== ZS_OK || rc2 !== ZS_OK) throw new Error(`prove failed (rc=${rc}, rc2=${rc2})`);

    const d = dv();
    const proofPtr = d.getUint32(proofPtrSlot, true);
    const proofLen = d.getUint32(proofLenSlot, true);
    const proof = view().slice(proofPtr, proofPtr + proofLen);
    const rootsPtr = d.getUint32(rootsPtrSlot, true);
    const rootsLen = d.getUint32(rootsLenSlot, true);
    const rootsBytes = view().slice(rootsPtr, rootsPtr + rootsLen);
    instance.exports.zs_free_wm(proofPtr, proofLen);
    instance.exports.zs_free_wm(rootsPtr, rootsLen);
    return { proof, roots: decodeRoots(rootsBytes) };
  }

  /** Verify a serialized proof.
   * @param {{k: number, roots: Uint8Array[], constraints: object[], pins?: object[], proof: Uint8Array, domain?: string}} stmt
   * @returns {boolean} */
  function verify({ k, roots, constraints, pins = [], proof, domain = '' }) {
    const rootsB = encodeRoots(roots);
    const conB = encodeConstraints(constraints);
    const pinB = encodePins(pins);
    const domB = enc.encode(domain);
    const rootsPtr = malloc(rootsB.length); putBytes(rootsPtr, rootsB);
    const conPtr = malloc(conB.length); putBytes(conPtr, conB);
    const pinPtr = malloc(pinB.length); putBytes(pinPtr, pinB);
    const proofPtr = malloc(proof.length); putBytes(proofPtr, proof);
    const domPtr = malloc(domB.length); putBytes(domPtr, domB);
    const okSlot = malloc(1);

    const rc = instance.exports.zs_binius_verify_wm(
      k, rootsPtr, rootsB.length, conPtr, conB.length, pinPtr, pinB.length,
      proofPtr, proof.length, domPtr, domB.length, okSlot,
    );
    if (rc !== ZS_OK) throw new Error(`verify failed (rc=${rc})`);
    return view()[okSlot] === 1;
  }

  return { instance, proveColumns, verify, version };
}

export default loadZigStark;
