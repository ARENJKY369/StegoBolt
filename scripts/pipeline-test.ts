// Node pipeline test — validates lib/lsbcore, lib/crypto and the inline
// worker source with the exact same code paths the browser runs.
// Run: node --experimental-strip-types scripts/pipeline-test.ts
import assert from 'node:assert';
import { embedIntoPixels, extractFromPixels, capacityBytes, randomizeLsb, pixelDiffStats } from '../lib/lsbcore.ts';
import { sealPayload, openPayload, textEnc, textDec, CIPHER } from '../lib/crypto.ts';

const W = 140;
const H = 90;
const px = new Uint8Array(W * H * 4);
for (let i = 0; i < px.length; i++) px[i] = (i * 37) & 0xff; // deterministic pseudo-image
px.forEach((_, i) => {
  if ((i & 3) === 3) px[i] = 255; // opaque alpha
});

const secret = 'The eagle lands at midnight — ref #4471.\nMulti-line ✓ émojis 🎯 中文.';
const pass = 'correct horse battery staple';

async function main() {
  // ---- 1. main-thread embed/extract with AES-256-GCM ----
  const plain = textEnc.encode(secret);
  const sealed = await sealPayload(plain, CIPHER.AES_256_GCM, pass);
  const carrier = px.slice();
  const res = embedIntoPixels(carrier, sealed, CIPHER.AES_256_GCM);
  console.log('embed ok · bits', res.bitsUsed, '/ capacity', res.capacityBits);

  const got = extractFromPixels(carrier);
  assert.equal(got.flags, CIPHER.AES_256_GCM);
  const opened = await openPayload(got.payload, got.flags, pass);
  assert.equal(textDec.decode(opened), secret);
  console.log('GCM round-trip ok');

  // wrong password must fail the GCM tag
  let threw = false;
  try {
    await openPayload(got.payload, got.flags, 'wrong-passphrase');
  } catch {
    threw = true;
  }
  assert.ok(threw, 'wrong passphrase must throw');
  console.log('tamper/wrong-key rejection ok');

  // capacity headroom + capacity guard
  assert.ok(capacityBytes(carrier.length) > sealed.length);
  let capThrew = false;
  try {
    embedIntoPixels(new Uint8Array(16), new Uint8Array(64), 0);
  } catch (e) {
    capThrew = e instanceof Error && e.message.startsWith('CAPACITY_EXCEEDED');
  }
  assert.ok(capThrew, 'capacity guard must fire');
  console.log('capacity guard ok');

  // NOT_STEGO detection on a pristine carrier
  let notStego = false;
  try {
    extractFromPixels(px);
  } catch (e) {
    notStego = e instanceof Error && e.message.startsWith('NOT_STEGO');
  }
  assert.ok(notStego, 'clean image must report NOT_STEGO');
  console.log('NOT_STEGO detection ok');

  // ---- 2. raw (unencrypted) mode ----
  const rawSealed = await sealPayload(plain, CIPHER.RAW, '');
  const rawCarrier = px.slice();
  embedIntoPixels(rawCarrier, rawSealed, CIPHER.RAW);
  const raw = extractFromPixels(rawCarrier);
  assert.equal(textDec.decode(await openPayload(raw.payload, raw.flags, '')), secret);
  console.log('RAW round-trip ok');

  // ---- 3. noise randomization actually mutates ~half the low bits ----
  const noisy = px.slice();
  const touched = randomizeLsb(noisy);
  const stats = pixelDiffStats(px, noisy);
  assert.ok(touched === W * H * 3, 'touch count');
  assert.ok(stats.changed > touched * 0.4 && stats.changed < touched * 0.6, `~50% bits flipped, got ${stats.changed}/${touched}`);
  assert.ok(stats.psnr > 40, 'PSNR of ±1 LSB noise should stay >40dB');
  console.log(`noise floor ok · changed ${stats.changed} · PSNR ${stats.psnr.toFixed(1)} dB`);

  // ---- 4. inline worker source: identical semantics, executed standalone ----
  const { readFileSync } = await import('node:fs');
  const fileText = readFileSync(new URL('../lib/worker.ts', import.meta.url), 'utf8');
  const mm = fileText.match(/const WORKER_SRC = String.raw`([\s\S]*?)`;/);
  if (!mm) throw new Error('could not extract WORKER_SRC');
  const src = mm[1];
  let last: any = null;
  const fakeSelf = {
    onmessage: null as null | ((e: any) => void),
    postMessage: (msg: any) => (last = msg),
  };
  // eslint-disable-next-line no-new-func
  new Function('self', 'crypto', src)(fakeSelf, globalThis.crypto);
  fakeSelf.onmessage!({
    data: {
      id: 1,
      type: 'embed',
      input: { pixels: px.slice().buffer, payload: sealed.slice().buffer, flags: CIPHER.AES_256_GCM },
    },
  });
  assert.ok(last?.ok, 'worker embed ok');
  const workerPixels = new Uint8Array(last.output.pixels);
  assert.ok(workerPixels.every((v, i) => v === carrier[i]), 'worker output matches main-thread output byte-for-byte');
  console.log('worker embed parity ok');

  fakeSelf.onmessage!({ data: { id: 2, type: 'extract', input: { pixels: carrier.slice().buffer } } });
  assert.ok(last?.ok, 'worker extract ok');
  const wPayload = new Uint8Array(last.output.payload);
  assert.equal(textDec.decode(await openPayload(wPayload, last.output.flags, pass)), secret);
  console.log('worker extract parity ok');

  fakeSelf.onmessage!({ data: { id: 3, type: 'noise', input: { pixels: px.slice().buffer } } });
  assert.ok(last?.ok && last.output.touched === W * H * 3, 'worker noise ok');
  console.log('worker noise ok');

  fakeSelf.onmessage!({ data: { id: 4, type: 'extract', input: { pixels: new Uint8Array(64 * 64 * 4).fill(128).buffer } } });
  assert.ok(last && last.ok === false && last.error.startsWith('NOT_STEGO'), 'worker NOT_STEGO error path');
  console.log('worker error path ok');

  // ---- 5. steganalysis can flag an SBV2 carrier, passes clean images ----
  const { analyzeLsbPlane, detectSbv2Magic, threatAssessment, measureQuality, renderLsbPlane } = await import('../lib/analysis.ts');
  const sStego = analyzeLsbPlane(carrier, W, H);
  assert.ok(detectSbv2Magic(carrier), 'scanner must find SBV2 magic in the stego object');
  const vStego = threatAssessment(sStego, true);
  assert.ok(vStego.score >= 24 && vStego.level !== 'LOW', `stego threat must be elevated, got ${vStego.score}`);
  const sClean = analyzeLsbPlane(px, W, H);
  assert.ok(!detectSbv2Magic(px), 'clean image must not carry the magic');
  const vClean = threatAssessment(sClean, false);
  assert.ok(vClean.score < 60, `clean-image threat should not be critical, got ${vClean.score}`);
  const q = measureQuality(px, carrier, 1056, W * H * 3);
  assert.ok(q.psnrDb > 45 && q.ssimApprox > 0.999, `embedding must stay imperceptible (PSNR ${q.psnrDb}, SSIM ${q.ssimApprox})`);
  const plane = renderLsbPlane(carrier, W, H);
  assert.equal(plane.length, W * H * 4);
  console.log(`analysis ok · stego threat ${vStego.score} (${vStego.level}) · clean ${vClean.score} · embed PSNR ${q.psnrDb.toFixed(1)} dB · SSIM ${q.ssimApprox.toFixed(5)}`);

  console.log('\nALL PIPELINE TESTS PASSED ✔');
}

main().catch((e) => {
  console.error('PIPELINE TEST FAILED ✖', e);
  process.exit(1);
});
