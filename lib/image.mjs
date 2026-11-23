// An image the page read from the workspace, checked before Claude sees it (#1791, step 1): the page sends only the file's
// bytes as base64; its type and size come from the bytes here, from the header alone (no decode). One image per
// workspace_read. The base64 is never logged or put in an error: a refusal names a fixed reason only.

export const IMAGE_BYTES_MAX = 3_750_000; // (3.75 MB: its base64 is at most 5,000,000 characters, within the API's 5 MB per image whichever way "MB" is read)
export const IMAGE_SIDE_MAX = 8000; // (pixels, each side: the API's limit)
export const IMAGE_AREA_MAX = 25_000_000; // (pixels in all: the sides alone would allow 64 million)
const B64_MAX = 4 * Math.ceil(IMAGE_BYTES_MAX / 3);
const JPEG_STEPS_MAX = 4096; // (markers read before the frame header, at most)

/** The reasons an image is refused, fixed words only (never anything of the file). */
export const IMAGE_REASONS = Object.freeze(["shape", "base64", "too_large", "type", "truncated", "header", "size"]);

const fail = (reason) => ({ ok: false, reason });

// The pinned Claude Code's own words when the API refused an image it was given (read from a run against a stand-in API
// answering 400: "Could not process image", too many bytes, too many pixels). It removes such an image from the
// conversation itself, so the next message works. Only these, whole: any other error is said as before.
const REJECTED_TEXTS = [
  "API Error: an image in the conversation could not be processed and was removed. Re-read the file with a different approach if you still need it.",
  "Image was too large. Try resizing the image or using a different approach.",
  "Image was too large. Double press esc to go back and try again with a smaller image.",
];
export const IMAGE_REJECTED_TEXT = "Claude couldn't use that image. Try a smaller PNG, JPEG, GIF or WebP image, then send your message again.";
/** "image_unreadable" when Claude Code's text is its own for an image the API refused, else null. */
export function imageRejected(text) {
  return REJECTED_TEXTS.includes(String(text ?? "").trim()) ? "image_unreadable" : null;
}

/**
 * The page's `image` field: exactly { base64 } with a canonical, padded standard base64 string. Returns
 * { ok: true, data, mimeType, width, height } or { ok: false, reason } (one of IMAGE_REASONS).
 */
export function checkImage(image) {
  if (!image || typeof image !== "object" || Array.isArray(image)) return fail("shape");
  const keys = Object.keys(image);
  if (keys.length !== 1 || keys[0] !== "base64" || typeof image.base64 !== "string") return fail("shape");
  const b64 = image.base64;
  if (b64.length > B64_MAX) return fail("too_large");
  if (b64.length === 0 || b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return fail("base64");
  const bytes = Buffer.from(b64, "base64");
  if (bytes.length > IMAGE_BYTES_MAX) return fail("too_large");
  if (bytes.toString("base64") !== b64) return fail("base64");
  const h = imageHeader(bytes);
  if (!h.ok) return h;
  if (h.width < 1 || h.height < 1 || h.width > IMAGE_SIDE_MAX || h.height > IMAGE_SIDE_MAX || h.width * h.height > IMAGE_AREA_MAX) return fail("size");
  return { ok: true, data: b64, mimeType: h.mimeType, width: h.width, height: h.height };
}

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const ascii = (b, at, s) => b.length >= at + s.length && b.toString("latin1", at, at + s.length) === s;

/** The type and pixel size from the header alone: { ok, mimeType, width, height } or { ok: false, reason }. */
export function imageHeader(b) {
  if (b.length >= 8 && b.subarray(0, 8).equals(PNG_SIG)) return png(b);
  if (ascii(b, 0, "GIF87a") || ascii(b, 0, "GIF89a")) return gif(b);
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return jpeg(b);
  if (ascii(b, 0, "RIFF") && ascii(b, 8, "WEBP")) return webp(b);
  return fail("type");
}

// PNG: the signature, then the first chunk, IHDR, of length exactly 13.
function png(b) {
  if (b.length < 8 + 8 + 13) return fail("truncated");
  if (b.readUInt32BE(8) !== 13 || !ascii(b, 12, "IHDR")) return fail("header");
  return { ok: true, mimeType: "image/png", width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
}

// GIF: the logical screen's width and height.
function gif(b) {
  if (b.length < 10) return fail("truncated");
  return { ok: true, mimeType: "image/gif", width: b.readUInt16LE(6), height: b.readUInt16LE(8) };
}

// JPEG: one forward scan of the markers, each length checked, until a frame header (SOFn). A scan, an end, or a marker
// that isn't one before any frame header is refused.
const SOF = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
function jpeg(b) {
  let i = 2;
  for (let step = 0; step < JPEG_STEPS_MAX; step++) {
    if (i + 2 > b.length) return fail("truncated");
    if (b[i] !== 0xff) return fail("header");
    let m = b[i + 1];
    while (m === 0xff) { i++; if (i + 2 > b.length) return fail("truncated"); m = b[i + 1]; } // (fill bytes)
    if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; } // (no length)
    if (m === 0xd8 || m === 0xd9 || m === 0xda || m === 0x00) return fail("header");
    if (i + 4 > b.length) return fail("truncated");
    const len = b.readUInt16BE(i + 2);
    if (len < 2) return fail("header");
    if (i + 2 + len > b.length) return fail("truncated"); // (every segment, the frame header too, whole within the file)
    if (SOF.has(m)) {
      if (len < 8) return fail("header");
      return { ok: true, mimeType: "image/jpeg", width: b.readUInt16BE(i + 7), height: b.readUInt16BE(i + 5) };
    }
    i += 2 + len;
  }
  return fail("header");
}

// WebP: RIFF, its declared length within the file, WEBP, then a VP8, VP8L or VP8X header with its dimensions.
function webp(b) {
  if (b.length < 20) return fail("truncated");
  const riff = b.readUInt32LE(4);
  if (riff < 4 + 8 || 8 + riff > b.length) return fail("header");
  const chunk = b.toString("latin1", 12, 16);
  const size = b.readUInt32LE(16);
  if (20 + size > 8 + riff) return fail("header");
  if (chunk === "VP8 ") {
    if (size < 10) return fail("header");
    if (b[23] !== 0x9d || b[24] !== 0x01 || b[25] !== 0x2a) return fail("header");
    return { ok: true, mimeType: "image/webp", width: b.readUInt16LE(26) & 0x3fff, height: b.readUInt16LE(28) & 0x3fff };
  }
  if (chunk === "VP8L") {
    if (size < 5 || b[20] !== 0x2f) return fail("header");
    const v = b.readUInt32LE(21);
    return { ok: true, mimeType: "image/webp", width: (v & 0x3fff) + 1, height: ((v >>> 14) & 0x3fff) + 1 };
  }
  if (chunk === "VP8X") {
    if (size < 10) return fail("header");
    return { ok: true, mimeType: "image/webp", width: b.readUIntLE(24, 3) + 1, height: b.readUIntLE(27, 3) + 1 };
  }
  return fail("header");
}
