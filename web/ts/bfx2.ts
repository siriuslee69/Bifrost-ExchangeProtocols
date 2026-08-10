/* --------------------------------------------------------
 * BFX2 TS Reference <- generic envelope + dynamic codec
 * ------------------------------------------------------ */

export const BFX_MAGIC = new Uint8Array([0x42, 0x46, 0x58, 0x32]); // B F X 2
export const BFX_FORMAT_VERSION = 1;

export enum BfxWireType {
  Unknown = 0x00,
  U8 = 0x01,
  U16 = 0x02,
  U32 = 0x03,
  U64 = 0x04,
  I8 = 0x05,
  I16 = 0x06,
  I32 = 0x07,
  I64 = 0x08,
  F32 = 0x09,
  F64 = 0x0a,
  Bool = 0x0b,
  Bytes = 0x0c,
  String = 0x0d,
  Enum = 0x0e,
  Object = 0x0f,
  Seq = 0x10,
  Option = 0x11,
}

export interface BfxHeader {
  schemaId: number;
  schemaVersion: number;
  flags: number;
  payloadLen: number;
  headerChecksum: number;
}

function writeU16LE(out: number[], v: number): void {
  out.push(v & 0xff, (v >>> 8) & 0xff);
}

function writeU32LE(out: number[], v: number): void {
  out.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
}

function readU16LE(bs: Uint8Array, o: number): number {
  return bs[o] | (bs[o + 1] << 8);
}

function readU32LE(bs: Uint8Array, o: number): number {
  return (bs[o] | (bs[o + 1] << 8) | (bs[o + 2] << 16) | (bs[o + 3] << 24)) >>> 0;
}

function crc32(bs: Uint8Array): number {
  let c = 0xffffffff >>> 0;
  for (let i = 0; i < bs.length; i += 1) {
    c ^= bs[i];
    for (let j = 0; j < 8; j += 1) {
      if ((c & 1) !== 0) {
        c = ((c >>> 1) ^ 0xedb88320) >>> 0;
      } else {
        c = (c >>> 1) >>> 0;
      }
    }
  }
  return (~c) >>> 0;
}

export function encodeBfxEnvelope(
  schemaId: number,
  schemaVersion: number,
  payload: Uint8Array,
  flags = 0
): Uint8Array {
  const hdrNoChecksum: number[] = [];
  hdrNoChecksum.push(...BFX_MAGIC);
  writeU16LE(hdrNoChecksum, BFX_FORMAT_VERSION);
  writeU16LE(hdrNoChecksum, schemaId);
  writeU16LE(hdrNoChecksum, schemaVersion);
  writeU16LE(hdrNoChecksum, flags);
  writeU32LE(hdrNoChecksum, payload.length);
  const cs = crc32(new Uint8Array(hdrNoChecksum));
  const out: number[] = [...hdrNoChecksum];
  writeU32LE(out, cs);
  out.push(...payload);
  return new Uint8Array(out);
}

export function decodeBfxEnvelope(bs: Uint8Array): { ok: boolean; header?: BfxHeader; payload?: Uint8Array; err?: string } {
  if (bs.length < 20) {
    return { ok: false, err: "bfx2: input shorter than header" };
  }
  for (let i = 0; i < BFX_MAGIC.length; i += 1) {
    if (bs[i] !== BFX_MAGIC[i]) {
      return { ok: false, err: "bfx2: invalid magic" };
    }
  }
  const formatVersion = readU16LE(bs, 4);
  if (formatVersion !== BFX_FORMAT_VERSION) {
    return { ok: false, err: "bfx2: unsupported format version" };
  }
  const schemaId = readU16LE(bs, 6);
  const schemaVersion = readU16LE(bs, 8);
  const flags = readU16LE(bs, 10);
  const payloadLen = readU32LE(bs, 12);
  const headerChecksum = readU32LE(bs, 16);
  const computed = crc32(bs.slice(0, 16));
  if (headerChecksum !== computed) {
    return { ok: false, err: "bfx2: header checksum mismatch" };
  }
  if (payloadLen !== bs.length - 20) {
    return { ok: false, err: "bfx2: payload length mismatch" };
  }
  return {
    ok: true,
    header: { schemaId, schemaVersion, flags, payloadLen, headerChecksum },
    payload: bs.slice(20),
  };
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function utf8Decode(bs: Uint8Array): string {
  return new TextDecoder().decode(bs);
}

function encodePacket(type: BfxWireType, raw: Uint8Array): Uint8Array {
  const out: number[] = [type];
  writeU32LE(out, raw.length);
  out.push(...raw);
  return new Uint8Array(out);
}

function parsePacket(bs: Uint8Array): { ok: boolean; type?: BfxWireType; raw?: Uint8Array; err?: string } {
  if (bs.length < 5) {
    return { ok: false, err: "bfx2: truncated packet" };
  }
  const type = bs[0] as BfxWireType;
  const len = readU32LE(bs, 1);
  if (len !== bs.length - 5) {
    return { ok: false, err: "bfx2: packet length mismatch" };
  }
  return { ok: true, type, raw: bs.slice(5) };
}

function fnv16(k: string): number {
  let h = 2166136261 >>> 0;
  const kb = utf8(k);
  for (let i = 0; i < kb.length; i += 1) {
    h ^= kb[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h & 0xffff;
}

function encodeRaw(v: unknown): { type: BfxWireType; raw: Uint8Array } {
  if (v === null || v === undefined) {
    return { type: BfxWireType.Option, raw: new Uint8Array([0]) };
  }
  if (typeof v === "boolean") {
    return { type: BfxWireType.Bool, raw: new Uint8Array([v ? 1 : 0]) };
  }
  if (typeof v === "number") {
    if (Number.isInteger(v)) {
      const b = new ArrayBuffer(8);
      new DataView(b).setBigInt64(0, BigInt(v), true);
      return { type: BfxWireType.I64, raw: new Uint8Array(b) };
    }
    const b = new ArrayBuffer(8);
    new DataView(b).setFloat64(0, v, true);
    return { type: BfxWireType.F64, raw: new Uint8Array(b) };
  }
  if (typeof v === "string") {
    return { type: BfxWireType.String, raw: utf8(v) };
  }
  if (v instanceof Uint8Array) {
    return { type: BfxWireType.Bytes, raw: v };
  }
  if (Array.isArray(v)) {
    const out: number[] = [];
    writeU32LE(out, v.length);
    for (const e of v) {
      const r = encodeRaw(e);
      const packet = encodePacket(r.type, r.raw);
      writeU32LE(out, packet.length);
      out.push(...packet);
    }
    return { type: BfxWireType.Seq, raw: new Uint8Array(out) };
  }
  const o = v as Record<string, unknown>;
  const fields = Object.keys(o).map((k) => {
    const r = encodeRaw(o[k]);
    return { id: fnv16(k), key: k, type: r.type, raw: r.raw };
  });
  fields.sort((a, b) => (a.id - b.id) || a.key.localeCompare(b.key));
  const out: number[] = [];
  writeU16LE(out, fields.length);
  for (const f of fields) {
    writeU16LE(out, f.id);
    out.push(f.type, 0);
    const kb = utf8(f.key);
    const vb: number[] = [];
    writeU16LE(vb, kb.length);
    vb.push(...kb, ...f.raw);
    writeU32LE(out, vb.length);
    out.push(...vb);
  }
  return { type: BfxWireType.Object, raw: new Uint8Array(out) };
}

export function encodeBfxValue(v: unknown): Uint8Array {
  const r = encodeRaw(v);
  return encodePacket(r.type, r.raw);
}

function decodeRaw(type: BfxWireType, raw: Uint8Array): unknown {
  switch (type) {
    case BfxWireType.Bool:
      if (raw.length !== 1) throw new Error("bfx2: bool length mismatch");
      return raw[0] !== 0;
    case BfxWireType.U8:
      if (raw.length !== 1) throw new Error("bfx2: u8 length mismatch");
      return raw[0];
    case BfxWireType.U16:
      if (raw.length !== 2) throw new Error("bfx2: u16 length mismatch");
      return readU16LE(raw, 0);
    case BfxWireType.U32:
      if (raw.length !== 4) throw new Error("bfx2: u32 length mismatch");
      return readU32LE(raw, 0);
    case BfxWireType.U64:
    case BfxWireType.Enum: {
      if (raw.length !== 8) throw new Error("bfx2: u64 length mismatch");
      const v = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getBigUint64(0, true);
      return Number(v);
    }
    case BfxWireType.I8:
      if (raw.length !== 1) throw new Error("bfx2: i8 length mismatch");
      return (raw[0] << 24) >> 24;
    case BfxWireType.I16:
      if (raw.length !== 2) throw new Error("bfx2: i16 length mismatch");
      return (readU16LE(raw, 0) << 16) >> 16;
    case BfxWireType.I32:
      if (raw.length !== 4) throw new Error("bfx2: i32 length mismatch");
      return readU32LE(raw, 0) | 0;
    case BfxWireType.I64: {
      if (raw.length !== 8) throw new Error("bfx2: i64 length mismatch");
      const v = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getBigInt64(0, true);
      return Number(v);
    }
    case BfxWireType.F32: {
      if (raw.length !== 4) throw new Error("bfx2: f32 length mismatch");
      return new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getFloat32(0, true);
    }
    case BfxWireType.F64: {
      if (raw.length !== 8) throw new Error("bfx2: f64 length mismatch");
      return new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getFloat64(0, true);
    }
    case BfxWireType.Bytes:
      return raw;
    case BfxWireType.String:
      return utf8Decode(raw);
    case BfxWireType.Option: {
      if (raw.length < 1) throw new Error("bfx2: option length mismatch");
      if (raw[0] === 0) return null;
      if (raw.length < 5) throw new Error("bfx2: option payload missing");
      const plen = readU32LE(raw, 1);
      if (plen !== raw.length - 5) throw new Error("bfx2: option packet length mismatch");
      const parsed = parsePacket(raw.slice(5));
      if (!parsed.ok || parsed.type === undefined || !parsed.raw) throw new Error(parsed.err ?? "bfx2: invalid option packet");
      return decodeRaw(parsed.type, parsed.raw);
    }
    case BfxWireType.Seq: {
      if (raw.length < 4) throw new Error("bfx2: seq length mismatch");
      const count = readU32LE(raw, 0);
      const out: unknown[] = [];
      let o = 4;
      for (let i = 0; i < count; i += 1) {
        if (o + 4 > raw.length) throw new Error("bfx2: seq entry truncated");
        const elen = readU32LE(raw, o);
        o += 4;
        if (o + elen > raw.length) throw new Error("bfx2: seq element overflow");
        const parsed = parsePacket(raw.slice(o, o + elen));
        if (!parsed.ok || parsed.type === undefined || !parsed.raw) throw new Error(parsed.err ?? "bfx2: invalid seq packet");
        out.push(decodeRaw(parsed.type, parsed.raw));
        o += elen;
      }
      return out;
    }
    case BfxWireType.Object: {
      if (raw.length < 2) throw new Error("bfx2: object length mismatch");
      const count = readU16LE(raw, 0);
      const out: Record<string, unknown> = {};
      let o = 2;
      for (let i = 0; i < count; i += 1) {
        if (o + 8 > raw.length) throw new Error("bfx2: object field truncated");
        const fieldType = raw[o + 2] as BfxWireType;
        const fieldReserved = raw[o + 3];
        const fieldLen = readU32LE(raw, o + 4);
        o += 8;
        if (fieldReserved !== 0) throw new Error("bfx2: invalid field reserved byte");
        if (o + fieldLen > raw.length) throw new Error("bfx2: object field overflow");
        const fieldRaw = raw.slice(o, o + fieldLen);
        if (fieldRaw.length < 2) throw new Error("bfx2: object key length missing");
        const keyLen = readU16LE(fieldRaw, 0);
        if (2 + keyLen > fieldRaw.length) throw new Error("bfx2: object key overflow");
        const key = utf8Decode(fieldRaw.slice(2, 2 + keyLen));
        const valueRaw = fieldRaw.slice(2 + keyLen);
        out[key] = decodeRaw(fieldType, valueRaw);
        o += fieldLen;
      }
      return out;
    }
    default:
      throw new Error(`bfx2: unsupported wire type ${type}`);
  }
}

export function decodeBfxValue(bs: Uint8Array): unknown {
  const parsed = parsePacket(bs);
  if (!parsed.ok || parsed.type === undefined || !parsed.raw) {
    throw new Error(parsed.err ?? "bfx2: decode failed");
  }
  return decodeRaw(parsed.type, parsed.raw);
}
