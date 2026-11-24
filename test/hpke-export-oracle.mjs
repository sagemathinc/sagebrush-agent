// An independent oracle for HPKE Export (RFC 9180 §5.3) beyond the CFRG vector's 32-byte exports: HKDF-Expand written
// out here over Node's own HMAC-SHA256, from the vector's exporter_secret, so every block of a long output is checked,
// the last one included. Used by the Node-backend and WebCrypto-backend tests (test/fleet-sealed, fleet-webcrypto).
import { createHmac } from "node:crypto";

// (I2OSP(L, 2) || "HPKE-v1" || "HPKE" || kem 0x0020 || kdf 0x0001 || aead 0x0002 || "sec" || exporter context)
function expected(exporterSecret, ctx, L) {
  const info = Buffer.concat([Buffer.from([L >>> 8, L & 255]), Buffer.from("HPKE-v1HPKE"), Buffer.from([0, 0x20, 0, 1, 0, 2]), Buffer.from("sec"), ctx]);
  const blocks = [];
  let t = Buffer.alloc(0);
  for (let i = 1; i <= Math.ceil(L / 32); i++) {
    t = createHmac("sha256", exporterSecret).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    blocks.push(t);
  }
  return new Uint8Array(Buffer.concat(blocks).subarray(0, L));
}

export const LENGTHS = [1, 31, 32, 33, 63, 64, 65, 8159, 8160];
export const CONTEXTS = [new Uint8Array(0), new TextEncoder().encode("TestContext"), new Uint8Array(300).fill(0xa5)];

/** Every length and context, from the sender, the recipient and both single-shot helpers: the outputs that differ. */
export async function checkExportOracle(core, V) {
  const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
  const R = await core.deriveKeyPair(hex(V.ikmR)), E = await core.deriveKeyPair(hex(V.ikmE));
  const S = await core.setupSender(R.raw, hex(V.info), E), O = await core.setupRecipient(R, hex(V.enc), hex(V.info));
  const secret = hex(V.exporter_secret), bad = [];
  let n = 0;
  const eq = (a, b) => a instanceof Uint8Array && a.length === b.length && a.every((x, i) => x === b[i]);
  for (const L of LENGTHS) {
    for (const [c, ctx] of CONTEXTS.entries()) {
      const want = expected(secret, ctx, L);
      const got = {
        sender: await S.export(ctx, L),
        recipient: await O.export(ctx, L),
        sendExport: (await core.hpkeSendExport(R.raw, hex(V.info), ctx, L, E)).secret,
        receiveExport: await core.hpkeReceiveExport(R, hex(V.enc), hex(V.info), ctx, L),
      };
      for (const [side, b] of Object.entries(got)) {
        n++;
        if (!eq(b, want)) bad.push(`${side} L=${L} context ${c}`);
        // (the last block on its own too: a fault confined to the final, partial or full, block)
        else if (!eq(b.subarray(Math.max(0, L - 32)), want.subarray(Math.max(0, L - 32)))) bad.push(`${side} L=${L} context ${c}: last block`);
      }
    }
  }
  return { bad, n };
}
