import BN from "bn.js";
import elliptic from "elliptic";
import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";

// Predefined H Point (Matches Server)
// This is an uncompressed point string
const H_POINT_HEX = "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a";
const { ec: EC } = elliptic;

export class Crypto {
  private ec: elliptic.ec;
  private keyPair: elliptic.ec.KeyPair;

  constructor(privateKeyHex?: string) {
    this.ec = new EC("secp256k1");
    if (privateKeyHex) {
      this.keyPair = this.ec.keyFromPrivate(privateKeyHex, "hex");
    }
    else {
      this.keyPair = this.ec.genKeyPair();
    }
  }

  public getPublicKey(compressed = true): Buffer {
    const pub = this.keyPair.getPublic(compressed, "array");
    return Buffer.from(pub);
  }

  public getPrivateKey(): Buffer {
    return this.keyPair.getPrivate().toBuffer(undefined, 32);
  }

  public hash(data: string | Buffer | Uint8Array): Buffer {
    return crypto.createHash("sha256").update(data).digest();
  }

  public sign(dataHash: Buffer): Buffer {
    const signature = this.keyPair.sign(dataHash, { canonical: true });
    const r = signature.r.toBuffer("be", 32);
    const s = signature.s.toBuffer("be", 32);
    return Buffer.concat([r, s]);
  }

  public verify(publicKeyBuf: Buffer, dataHash: Buffer, signatureBuf: Buffer): boolean {
    try {
      if (signatureBuf.length !== 64)
        return false;
      const r = signatureBuf.subarray(0, 32);
      const s = signatureBuf.subarray(32, 64);
      const key = this.ec.keyFromPublic(publicKeyBuf);
      return key.verify(dataHash, { r, s });
    }
    catch {
      return false;
    }
  }

  // --- PEM Parsers ---
  public static base64Decode(encoded: string): Uint8Array {
    return new Uint8Array(Buffer.from(encoded, "base64"));
  }

  public loadPrivateKeyFromPem(pem: string): Uint8Array {
    const start = pem.indexOf("-----BEGIN EC PRIVATE KEY-----");
    if (start === -1)
      return new Uint8Array(0);
    let lineStart = pem.indexOf("\n", start);
    if (lineStart === -1)
      return new Uint8Array(0);
    lineStart++;
    const end = pem.indexOf("-----END EC PRIVATE KEY-----", lineStart);
    if (end === -1)
      return new Uint8Array(0);
    let base64 = pem.substring(lineStart, end);
    base64 = base64.replace(/\n/g, "");
    const der = Crypto.base64Decode(base64);

    if (der.length < 32)
      return new Uint8Array(0);

    for (let i = 0; i < der.length - 33; i++) {
      if (der[i] === 0x04 && der[i + 1] === 0x20) {
        return der.slice(i + 2, i + 2 + 32);
      }
    }
    return new Uint8Array(0);
  }

  public loadPublicKeyFromPem(pem: string): Uint8Array {
    const start = pem.indexOf("-----BEGIN PUBLIC KEY-----");
    if (start === -1)
      return new Uint8Array(0);
    let lineStart = pem.indexOf("\n", start);
    if (lineStart === -1)
      return new Uint8Array(0);
    lineStart++;
    const end = pem.indexOf("-----END PUBLIC KEY-----", lineStart);
    if (end === -1)
      return new Uint8Array(0);
    let base64 = pem.substring(lineStart, end);
    base64 = base64.replace(/\n/g, "");
    const der = Crypto.base64Decode(base64);

    let pos = 0;
    if (der[pos++] !== 0x30)
      return new Uint8Array(0);

    if (der[pos]! & 0x80) {
      pos += (der[pos]! & 0x7F) + 1;
    }
    else {
      pos++;
    }

    if (der[pos] !== 0x30)
      return new Uint8Array(0);

    let algLen = 0;
    pos++;
    if (der[pos]! & 0x80) {
      const lenBytes = der[pos]! & 0x7F;
      pos++;
      for (let i = 0; i < lenBytes; i++) algLen = (algLen << 8) | der[pos++]!;
    }
    else {
      algLen = der[pos++]!;
    }
    pos += algLen;

    if (der[pos] !== 0x03)
      return new Uint8Array(0);
    pos++;

    if (der[pos]! & 0x80) {
      pos += (der[pos]! & 0x7F) + 1;
    }
    else {
      pos++;
    }
    pos++;

    return der.slice(pos, pos + 65);
  }

  // --- RANGE PROOF MATH ---

  private decomposeFourSquares(target: number): number[] {
    const findSquares = (n: number, count: number): number[] | null => {
      if (count === 1) {
        const root = Math.round(Math.sqrt(n));
        return (root * root === n) ? [root] : null;
      }
      const start = Math.floor(Math.sqrt(n));
      for (let i = start; i >= 0; i--) {
        const rem = n - (i * i);
        const res = findSquares(rem, count - 1);
        if (res)
          return [i, ...res];
      }
      return null;
    };
    const res = findSquares(target, 4);
    if (!res)
      throw new Error("Four Square Decomposition Failed");
    return res;
  }

  public generateRangeProof(x: number, min: number, max: number) {
    const G = this.ec.g;
    const H = this.ec.keyFromPublic(H_POINT_HEX, "hex").getPublic();

    const x_bn = new BN(x);
    const min_bn = new BN(min);
    const max_bn = new BN(max);

    const r = this.ec.genKeyPair().getPrivate();

    // c1 = (b-x)G - rH
    const term1 = G.mul(max_bn.sub(x_bn));
    const term2 = H.mul(r);
    const c1 = term1.add(term2.neg());

    // c2 = (x-a)G + rH
    const term3 = G.mul(x_bn.sub(min_bn));
    const c2 = term3.add(term2);

    const squares = this.decomposeFourSquares(x);
    const n = this.ec.curve.n!;

    const r0 = this.ec.genKeyPair().getPrivate();
    const r1 = this.ec.genKeyPair().getPrivate();
    const r2 = this.ec.genKeyPair().getPrivate();

    const r_sum_3 = r0.add(r1).add(r2);
    const r3 = r.sub(r_sum_3).umod(n);

    const r_factors = [r0, r1, r2, r3];
    const sq_commitments: Buffer[] = [];

    for (let i = 0; i < 4; i++) {
      const s_val = new BN(squares[i]!);
      const s_sq = s_val.mul(s_val);

      const Ci = G.mul(s_sq).add(H.mul(r_factors[i]!));
      sq_commitments.push(Buffer.from(Ci.encode("array", true)));
    }

    return {
      c1: Buffer.from(c1.encode("array", true)),
      c2: Buffer.from(c2.encode("array", true)),
      squares: sq_commitments,
    };
  }
}
