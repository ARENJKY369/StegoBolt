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

  // ---- 5. forensic-scan calibration & false-positive regressions ----------
  // These fixtures model the reported false positive (a clean photograph with
  // "chi-square evidence 100.0%" / "ELEVATED") and prove that only a validated
  // SBV2 container may be described as confirmed.
  const { analyzeLsbPlane, detectSbv2Magic, inspectSbv2Container, threatAssessment, assessEngineScan, measureQuality, renderLsbPlane } = await import('../lib/analysis.ts');
  const F = await import('./scan-fixtures.ts');

  const FW = 320;
  const FH = 240;

  const FORBIDDEN_CLAIMS = [
    /contains an embedded message/i,
    /embedded message is present/i,
    /likely embedding/i,
    /likely a recompressed or lightly modified/i,
    /assume data is embedded/i,
    /data is embedded/i,
  ];
  const assertCautiousWording = (summary: string, where: string) => {
    for (const re of FORBIDDEN_CLAIMS) {
      assert.ok(!re.test(summary), `${where}: careless wording in summary — "${summary}"`);
    }
  };

  // 5a. clean natural-looking photograph -----------------------------------
  const cleanPhoto = F.cleanNaturalPhoto(FW, FH);
  const sCleanPhoto = analyzeLsbPlane(cleanPhoto, FW, FH);
  const vCleanPhoto = threatAssessment(sCleanPhoto, inspectSbv2Container(cleanPhoto));
  assert.equal(vCleanPhoto.level, 'LOW', `clean photo must be LOW, got ${vCleanPhoto.level} (${vCleanPhoto.score})`);
  assert.ok(vCleanPhoto.score < 25, `clean photo score must stay below ELEVATED, got ${vCleanPhoto.score}`);
  assert.equal(vCleanPhoto.confidence, 'CLEAN');
  assert.match(vCleanPhoto.summary, /No StegoBolt container detected/);
  assert.match(vCleanPhoto.summary, /no direct evidence of an embedded message/i);
  assert.ok(!/confirmed/i.test(vCleanPhoto.summary), 'clean photo must not be called confirmed');
  assert.ok(!detectSbv2Magic(cleanPhoto), 'clean photo must carry no SBV2 magic');
  assertCautiousWording(vCleanPhoto.summary, 'clean photo');
  // the old inverted mapping reported this as ~100 % chi-square evidence
  assert.ok(sCleanPhoto.chiEqualization < 0.2, `clean photo equalisation evidence must stay low, got ${sCleanPhoto.chiEqualization}`);
  assert.ok(sCleanPhoto.pValue < 0.5, `clean photo pairs are imbalanced, p must be small, got ${sCleanPhoto.pValue}`);
  console.log(`clean-photo regression ok · ${vCleanPhoto.score}/100 ${vCleanPhoto.level}/${vCleanPhoto.confidence} · pair p=${sCleanPhoto.pValue.toExponential(2)} · equalisation ${(sCleanPhoto.chiEqualization * 100).toFixed(1)}%`);

  // 5b. clean recompressed JPEG -------------------------------------------
  const jpeg = F.recompressedJpeg(FW, FH);
  const sJpeg = analyzeLsbPlane(jpeg, FW, FH);
  const vJpeg = threatAssessment(sJpeg, inspectSbv2Container(jpeg));
  assert.equal(vJpeg.level, 'LOW', `recompressed JPEG must be LOW, got ${vJpeg.level} (${vJpeg.score})`);
  assert.ok(vJpeg.score < 25, `recompressed JPEG score must stay below ELEVATED, got ${vJpeg.score}`);
  assertCautiousWording(vJpeg.summary, 'recompressed JPEG');
  assert.ok(!detectSbv2Magic(jpeg), 'recompressed JPEG must carry no SBV2 magic');
  console.log(`recompressed-jpeg regression ok · ${vJpeg.score}/100 ${vJpeg.level}/${vJpeg.confidence}`);

  // 5c. clean synthetic image with natural channel imbalance --------------
  // Mirrors the reported carrier: LSB ones ratio ≈ 0.597 while SPA alone may
  // look "high". A single detector must never lift the verdict.
  const imbalanced = F.cleanChannelImbalance(FW, FH);
  const sImbalanced = analyzeLsbPlane(imbalanced, FW, FH);
  const vImbalanced = threatAssessment(sImbalanced, inspectSbv2Container(imbalanced));
  assert.ok(sImbalanced.onesRatio > 0.55 && sImbalanced.onesRatio < 0.65, `fixture must reproduce the reported ones ratio, got ${sImbalanced.onesRatio}`);
  assert.equal(vImbalanced.level, 'LOW', `channel-imbalanced clean image must be LOW, got ${vImbalanced.level} (${vImbalanced.score})`);
  assert.equal(vImbalanced.confidence, 'CLEAN');
  assert.ok(sImbalanced.chiEqualization < 0.2, 'imbalanced pairs must not read as equalisation evidence');
  assertCautiousWording(vImbalanced.summary, 'channel imbalance');
  const syntheticBias = F.syntheticChannelBias(FW, FH);
  const vSynthetic = threatAssessment(analyzeLsbPlane(syntheticBias, FW, FH), inspectSbv2Container(syntheticBias));
  assert.equal(vSynthetic.level, 'LOW', `clean synthetic image must be LOW, got ${vSynthetic.level} (${vSynthetic.score})`);
  assertCautiousWording(vSynthetic.summary, 'synthetic channel bias');
  console.log(`channel-bias regression ok · ones ${sImbalanced.onesRatio.toFixed(3)} · SPA ${(sImbalanced.spaEmbeddingRatio * 100).toFixed(1)}% (single detector, capped) · ${vImbalanced.score}/100 ${vImbalanced.level}`);

  // 5d. known local SBV2 stego carrier must still be detected -------------
  const stegoPhotos = F.sbv2Stego(cleanPhoto, FW, FH, 96);
  const inspStego = inspectSbv2Container(stegoPhotos);
  assert.ok(inspStego.confirmed, `known SBV2 carrier must validate its header (${inspStego.status})`);
  const sStego = analyzeLsbPlane(stegoPhotos, FW, FH);
  const vStego = threatAssessment(sStego, inspStego);
  assert.equal(vStego.level, 'CRITICAL', `SBV2 carrier must be CRITICAL, got ${vStego.level} (${vStego.score})`);
  assert.equal(vStego.confidence, 'CONFIRMED');
  assert.ok(vStego.score >= 90, `SBV2 carrier score must stay high, got ${vStego.score}`);
  assert.match(vStego.summary, /Confirmed StegoBolt container detected/);
  assert.ok(detectSbv2Magic(stegoPhotos), 'boolean magic probe must still work');
  // ... and the boolean compatibility path still confirms a carrier.
  assert.equal(threatAssessment(sStego, true).level, 'CRITICAL', 'boolean signature path must confirm');
  console.log(`sbv2-stego regression ok · ${vStego.score}/100 ${vStego.level}/${vStego.confidence} · ${inspStego.detail}`);

  // 5e. full-plane LSB replacement without SBV2 framing -------------------
  // Strong multi-signal suspicion: both detector families agree, yet the
  // wording must stay "suspicion" because no container signature exists.
  const fullPlane = F.fullPlaneLsbNoise(cleanPhoto);
  const sFull = analyzeLsbPlane(fullPlane, FW, FH);
  const vFull = threatAssessment(sFull, inspectSbv2Container(fullPlane));
  assert.equal(vFull.level, 'HIGH', `full-plane random LSB must reach HIGH, got ${vFull.level} (${vFull.score})`);
  assert.equal(vFull.confidence, 'SUSPICIOUS');
  assert.match(vFull.summary, /No StegoBolt container signature was found/);
  assert.match(vFull.summary, /statistical suspicion/);
  assert.ok(!/Confirmed StegoBolt container/i.test(vFull.summary), 'unsignatured carrier must not be called confirmed');
  assertCautiousWording(vFull.summary, 'full-plane LSB replacement');
  assert.ok(sFull.chiEqualization > 0.4 && sFull.spaEvidence > 0.4, 'both detector families must agree on full-plane embedding');
  console.log(`statistical-suspicion regression ok · ${vFull.score}/100 ${vFull.level}/${vFull.confidence} · equalisation ${(sFull.chiEqualization * 100).toFixed(0)}% · SPA ${(sFull.spaEvidence * 100).toFixed(0)}%`);

  // 5f. wrong / corrupted signatures --------------------------------------
  const corrupted = F.corruptedSbv2(stegoPhotos);
  const inspCorrupt = inspectSbv2Container(corrupted);
  assert.ok(inspCorrupt.found && !inspCorrupt.confirmed, 'corrupted header must be found but not confirmed');
  assert.equal(inspCorrupt.status, 'bad-version');
  const vCorrupt = threatAssessment(analyzeLsbPlane(corrupted, FW, FH), inspCorrupt);
  assert.equal(vCorrupt.level, 'HIGH', `damaged framing must be HIGH, got ${vCorrupt.level} (${vCorrupt.score})`);
  assert.equal(vCorrupt.confidence, 'SUSPICIOUS');
  assert.match(vCorrupt.summary, /Damaged StegoBolt container framing/);
  assert.ok(!/Confirmed StegoBolt container detected/i.test(vCorrupt.summary), 'damaged framing must not be reported as confirmed');
  assertCautiousWording(vCorrupt.summary, 'corrupted signature');
  // A clean image whose first bits spell "SBV3" is not an SBV2 container.
  const wrongMagic = cleanPhoto.slice();
  const sbv3 = [0x53, 0x42, 0x56, 0x33];
  for (let b = 0; b < 32; b++) {
    const bit = (sbv3[b >> 3] >> (7 - (b & 7))) & 1;
    const p = Math.floor(b / 3);
    wrongMagic[p * 4 + (b % 3)] = (wrongMagic[p * 4 + (b % 3)] & 0xfe) | bit;
  }
  const inspWrong = inspectSbv2Container(wrongMagic);
  assert.equal(inspWrong.status, 'absent', `wrong magic must stay absent, got ${inspWrong.status}`);
  assert.equal(threatAssessment(analyzeLsbPlane(wrongMagic, FW, FH), inspWrong).confidence, 'CLEAN');
  console.log('signature-regression ok · corrupted header → damaged framing (HIGH/SUSPICIOUS) · wrong magic → absent');

  // 5g. tiny carriers cannot produce confident statistics ----------------
  const tiny = F.cleanNaturalPhoto(16, 16);
  const vTiny = threatAssessment(analyzeLsbPlane(tiny, 16, 16), inspectSbv2Container(tiny));
  assert.equal(vTiny.level, 'LOW');
  assert.equal(vTiny.confidence, 'INCONCLUSIVE');
  assert.match(vTiny.summary, /too small for reliable statistics/);
  assertCautiousWording(vTiny.summary, 'tiny carrier');
  console.log(`small-sample regression ok · ${vTiny.score}/100 ${vTiny.level}/${vTiny.confidence}`);

  // 5h. engine-report normalisation across the six medium families --------
  // Every family is exercised through the same code path the UI uses, so a
  // non-image carrier can never borrow image LSB wording or confidence.
  const cleanReport = (medium: string, sampleBased: boolean) => ({
    medium,
    threatScore: 8,
    containerSignatureFound: false,
    chiSquareProbability: 4.7e-11,
    spaEmbeddingRatio: 0,
    lsbOnesRatio: 0.5,
    lsbEntropy: 0.99,
    sampleBased,
    sampleSize: sampleBased ? 230400 : 0,
    indicators: ['No statistical evidence of steganographic embedding'],
  });
  const confirmedReport = (medium: string) => ({
    ...cleanReport(medium, false),
    threatScore: 96,
    containerSignatureFound: true,
    level: 'CRITICAL',
    confidence: 'CONFIRMED',
    summary: 'Confirmed StegoBolt container detected: a valid SBV2-J container header is present in this carrier.',
    analysisBasis: `${medium} structural SBV2-J container`,
  });
  const families: [string, boolean][] = [
    ['Image', true],
    ['Audio', true],
    ['Audio', false], // FLAC padding layer — structural only
    ['Video', false],
    ['Document', false],
    ['Text', false],
    ['Network', false],
  ];
  for (const [medium, sampleBased] of families) {
    const clean = assessEngineScan(cleanReport(medium, sampleBased));
    assert.equal(clean.level, 'LOW', `${medium}: clean carrier must be LOW, got ${clean.level} (${clean.score})`);
    assert.notEqual(clean.confidence, 'CONFIRMED', `${medium}: clean carrier must not be confirmed`);
    assertCautiousWording(clean.summary, `${medium} clean`);
    assert.match(clean.summary, /No StegoBolt container/i, `${medium}: summary must state the container is absent`);
    const stego = assessEngineScan(confirmedReport(medium));
    assert.equal(stego.level, 'CRITICAL', `${medium}: signed carrier must be CRITICAL`);
    assert.equal(stego.confidence, 'CONFIRMED');
    assert.match(stego.summary, /Confirmed StegoBolt container detected/);
  }
  // Structural-only media must ignore image LSB statistics entirely.
  const structuralNoise = assessEngineScan({
    ...cleanReport('Document', false),
    chiSquareProbability: 1,
    spaEmbeddingRatio: 0.95,
    lsbOnesRatio: 0.5,
    threatScore: 0,
  });
  assert.equal(structuralNoise.level, 'LOW', 'structural media must not be graded by LSB statistics');
  assert.notEqual(structuralNoise.confidence, 'CONFIRMED');
  // Old engines without calibrated fields still get the fallback classification.
  const legacyClean = assessEngineScan({ ...cleanReport('Image', true) });
  assert.equal(legacyClean.level, 'LOW', 'legacy clean engine report must be LOW');
  const legacySigned = assessEngineScan({ ...cleanReport('Network', false), containerSignatureFound: true, threatScore: 60 });
  assert.equal(legacySigned.level, 'CRITICAL', 'legacy signed report must confirm');
  assert.match(legacySigned.summary, /Confirmed StegoBolt container detected/);
  console.log('engine-report regression ok · Image/Audio/Video/Document/Text/Network clean + confirmed paths');

  // ---- quality metrics stay intact --------------------------------------
  const q = measureQuality(px, carrier, 1056, W * H * 3);
  assert.ok(q.psnrDb > 45 && q.ssimApprox > 0.999, `embedding must stay imperceptible (PSNR ${q.psnrDb}, SSIM ${q.ssimApprox})`);
  const plane = renderLsbPlane(carrier, W, H);
  assert.equal(plane.length, W * H * 4);
  // the legacy random-pixel carrier is still a valid SBV2 object
  assert.ok(detectSbv2Magic(carrier), 'legacy carrier magic must be detected');
  console.log(`quality metrics ok · PSNR ${q.psnrDb.toFixed(1)} dB · SSIM ${q.ssimApprox.toFixed(5)}`);

  console.log('\nALL PIPELINE TESTS PASSED ✔');
}

main().catch((e) => {
  console.error('PIPELINE TEST FAILED ✖', e);
  process.exit(1);
});
