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

  // ---- 4b. randomized worker↔main-thread parity fuzz (mirror-drift guard) ----
  // Deterministic PRNG so any drift failure is reproducible.
  let seed = 0x9e3779b9;
  const rnd = (n: number) => {
    seed ^= seed << 13; seed >>>= 0;
    seed ^= seed >>> 17;
    seed ^= seed << 5; seed >>>= 0;
    return seed % n;
  };
  const FUZZ_CASES = 12;
  for (let c = 0; c < FUZZ_CASES; c++) {
    const fw = 8 + rnd(40);
    const fh = 8 + rnd(30);
    const fpx = new Uint8Array(fw * fh * 4);
    for (let i = 0; i < fpx.length; i++) fpx[i] = rnd(256);
    fpx.forEach((_, i) => {
      if ((i & 3) === 3) fpx[i] = 255;
    });
    const flags = [CIPHER.RAW, CIPHER.AES_256_GCM, CIPHER.AES_256_CTR][rnd(3)];
    const capBytes = Math.floor((fw * fh * 3) / 8) - 64; // leave room for salt|iv|tag|header
    const len = capBytes <= 0 ? 0 : rnd(Math.min(700, capBytes) + 1);
    const fplain = new Uint8Array(len);
    for (let i = 0; i < len; i++) fplain[i] = rnd(256);
    const fpass = `fuzz-pass-${c}-${rnd(1e6)}`;
    const fsealed = await sealPayload(fplain, flags, flags === CIPHER.RAW ? '' : fpass);

    // main-thread embed
    const mainCarrier = fpx.slice();
    embedIntoPixels(mainCarrier, fsealed, flags);
    // worker embed — same inputs
    fakeSelf.onmessage!({
      data: {
        id: 100 + c,
        type: 'embed',
        input: { pixels: fpx.slice().buffer, payload: fsealed.slice().buffer, flags },
      },
    });
    assert.ok(last?.ok, `fuzz ${c}: worker embed ok`);
    const wPx = new Uint8Array(last.output.pixels);
    assert.equal(wPx.length, mainCarrier.length, `fuzz ${c}: same length`);
    for (let i = 0; i < wPx.length; i++) {
      assert.equal(wPx[i], mainCarrier[i], `fuzz ${c}: byte ${i} drifted (flags=${flags})`);
    }

    // extract parity: worker output must equal main-thread output
    const mainGot = extractFromPixels(mainCarrier.slice());
    fakeSelf.onmessage!({ data: { id: 200 + c, type: 'extract', input: { pixels: mainCarrier.slice().buffer } } });
    assert.ok(last?.ok, `fuzz ${c}: worker extract ok`);
    assert.equal(last.output.flags, mainGot.flags, `fuzz ${c}: flags parity`);
    const wGot = new Uint8Array(last.output.payload);
    assert.equal(wGot.length, mainGot.payload.length, `fuzz ${c}: payload length parity`);
    for (let i = 0; i < wGot.length; i++) {
      assert.equal(wGot[i], mainGot.payload[i], `fuzz ${c}: payload byte ${i} drifted`);
    }
    const fopened = await openPayload(mainGot.payload, mainGot.flags, flags === CIPHER.RAW ? '' : fpass);
    for (let i = 0; i < fplain.length; i++) {
      assert.equal(fopened[i], fplain[i], `fuzz ${c}: plaintext byte ${i} corrupted`);
    }
    assert.equal(fopened.length, fplain.length, `fuzz ${c}: plaintext length`);
  }
  console.log(`worker↔main parity fuzz ok · ${FUZZ_CASES} randomized cases`);

  // noise parity: crypto-random LSBs cannot match byte-for-byte across runs —
  // the shared contract is the touch count and the (upper bits + alpha preserved).
  {
    const nz = new Uint8Array(33 * 17 * 4);
    for (let i = 0; i < nz.length; i++) nz[i] = (i * 91) & 0xff;
    nz.forEach((_, i) => {
      if ((i & 3) === 3) nz[i] = 255;
    });
    const mainNoise = nz.slice();
    const touchedMain = randomizeLsb(mainNoise);
    fakeSelf.onmessage!({ data: { id: 300, type: 'noise', input: { pixels: nz.slice().buffer } } });
    assert.ok(last?.ok && last.output.touched === touchedMain, 'noise touch parity');
    const wNoise = new Uint8Array(last.output.pixels);
    assert.equal(wNoise.length, nz.length, 'noise length parity');
    for (let i = 0; i < wNoise.length; i++) {
      if ((i & 3) === 3) {
        assert.equal(wNoise[i], nz[i], `alpha ${i} must be preserved`);
      } else {
        assert.equal(wNoise[i] & 0xfe, nz[i] & 0xfe, `upper bits ${i} must be preserved`);
      }
    }
    console.log('worker noise contract ok');
  }

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
