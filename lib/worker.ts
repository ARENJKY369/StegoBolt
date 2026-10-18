'use client';

/**
 * Inline Blob Web Worker for off-main-thread LSB operations (embed / extract /
 * noise randomization). No external worker file is fetched — the entire worker
 * program ships as a self-contained string, keeping the app zero-network.
 * Falls back transparently to the mirrored main-thread implementation in
 * lib/lsbcore.ts if workers are blocked by the embedding context.
 */

import { embedIntoPixels, extractFromPixels, randomizeLsb, LsbError, type ExtractedBits } from './lsbcore';

export type JobType = 'embed' | 'extract' | 'noise';

export interface JobInput {
  pixels: ArrayBuffer; // detached into the worker
  payload?: ArrayBuffer;
  flags?: number;
}

export interface EmbedOutput {
  pixels: ArrayBuffer;
  bitsUsed: number;
  capacityBits: number;
}

export interface NoiseOutput {
  pixels: ArrayBuffer;
  touched: number;
}

export type ExtractOutput = Omit<ExtractedBits, 'payload'> & { payload: ArrayBuffer };

export const WORKER_SRC = String.raw`
'use strict';
var MAGIC=[0x53,0x42,0x56,0x32], VERSION=2, HDR=10;
function cap(d){ return Math.floor(d.length/4)*3; }
function g2b(bits){ var o=new Uint8Array((bits.length+7)>>3); for(var i=0;i<bits.length;i++){ o[i>>3]|=(bits[i]&1)<<(7-(i&7)); } return o; }
function b2g(bytes){ var o=new Uint8Array(bytes.length*8); for(var i=0;i<bytes.length;i++){ for(var b=0;b<8;b++){ o[i*8+b]=(bytes[i]>>(7-b))&1; } } return o; }
function gb(d,n){ var p=(n/3)|0; return d[p*4+(n-p*3)]&1; }
function embed(inp){
  var d=new Uint8Array(inp.pixels), pay=new Uint8Array(inp.payload), flags=inp.flags|0;
  var h=new Uint8Array(HDR); h.set(MAGIC,0); h[4]=VERSION; h[5]=flags;
  var L=pay.length; h[6]=(L>>>24)&255; h[7]=(L>>>16)&255; h[8]=(L>>>8)&255; h[9]=L&255;
  var cont=new Uint8Array(HDR+L); cont.set(h,0); cont.set(pay,HDR);
  var bits=b2g(cont); var c=cap(d);
  if(bits.length>c) throw new Error('CAPACITY_EXCEEDED: payload needs '+bits.length+' bits, carrier offers '+c);
  var bi=0, P=Math.floor(d.length/4);
  outer: for(var p=0;p<P;p++){ var base=p*4; for(var ch=0;ch<3;ch++){ var bit=bits[bi]; d[base+ch]=(d[base+ch]&0xfe)|bit; bi++; if(bi>=bits.length) break outer; } }
  return { pixels:d.buffer, bitsUsed:bits.length, capacityBits:c };
}
function extract(inp){
  var d=new Uint8Array(inp.pixels), c=cap(d);
  if(c<HDR*8) throw new Error('TOO_SMALL: carrier has no room for an SBV2 header');
  var hb=new Uint8Array(HDR*8); for(var i=0;i<HDR*8;i++) hb[i]=gb(d,i);
  var hd=g2b(hb);
  if(hd[0]!==MAGIC[0]||hd[1]!==MAGIC[1]||hd[2]!==MAGIC[2]||hd[3]!==MAGIC[3]) throw new Error('NOT_STEGO: no SBV2 container in the LSB plane');
  if(hd[4]!==VERSION) throw new Error('BAD_VERSION: container v'+hd[4]+' unsupported');
  var flags=hd[5];
  var len=((hd[6]<<24)|(hd[7]<<16)|(hd[8]<<8)|hd[9])>>>0;
  if(len===0||len>33554432) throw new Error('BAD_LENGTH: declared payload '+len+' bytes');
  var bits=HDR*8+len*8; if(bits>c) throw new Error('TRUNCATED: carrier was resized or recompressed lossily');
  var all=new Uint8Array(bits); for(var j=0;j<bits;j++) all[j]=gb(d,j);
  var payload=g2b(all).slice(HDR,HDR+len);
  return { payload:payload.buffer, flags:flags, version:hd[4], bitsUsed:bits };
}
function noise(inp){
  var d=new Uint8Array(inp.pixels); var P=Math.floor(d.length/4); var touched=0;
  var pool=crypto.getRandomValues(new Uint8Array(65536)); var pi=0;
  for(var p=0;p<P;p++){ var base=p*4; for(var ch=0;ch<3;ch++){ if(pi>=pool.length){ pool=crypto.getRandomValues(new Uint8Array(65536)); pi=0; } d[base+ch]=(d[base+ch]&0xfe)|(pool[pi++]&1); touched++; } }
  return { pixels:d.buffer, touched:touched };
}
function transfers(o){ var t=[]; if(o.pixels) t.push(o.pixels); if(o.payload) t.push(o.payload); return t; }
self.onmessage=function(e){
  var m=e.data;
  try{
    var out=null;
    if(m.type==='embed') out=embed(m.input);
    else if(m.type==='extract') out=extract(m.input);
    else if(m.type==='noise') out=noise(m.input);
    else throw new Error('UNKNOWN_JOB');
    self.postMessage({ id:m.id, ok:true, output:out }, transfers(out));
  }catch(err){
    self.postMessage({ id:m.id, ok:false, error:String((err&&err.message)||err) });
  }
};
`;

let workerPromise: Promise<Worker | null> | null = null;
export let workerMode: 'worker' | 'main-thread' = 'main-thread';
export function getWorkerMode() {
  return workerMode;
}

function buildWorker(): Promise<Worker | null> {
  if (typeof window === 'undefined' || typeof Worker === 'undefined') return Promise.resolve(null);
  try {
    const blob = new Blob([WORKER_SRC], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    const w = new Worker(url);
    // prime: quick echo of a trivial job keeps URL alive
    w.onerror = () => {
      try {
        w.terminate();
      } catch {
        /* noop */
      }
      workerPromise = Promise.resolve(null);
      workerMode = 'main-thread';
    };
    return Promise.resolve(w);
  } catch {
    return Promise.resolve(null);
  }
}

function getWorker(): Promise<Worker | null> {
  if (!workerPromise) workerPromise = buildWorker();
  return workerPromise;
}

function parseError(message: string): LsbError {
  const [code, ...rest] = message.split(': ');
  return new LsbError(code, rest.join(': ') || undefined);
}

interface Pending {
  resolve: (v: MessageEvent) => void;
  reject: (e: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
}

let seq = 1;
const pending = new Map<number, Pending>();

function dispatch<T>(w: Worker, type: JobType, input: JobInput, timeoutMs = 60_000): Promise<T> {
  const id = seq++;
  return new Promise<T>((resolve, reject) => {
    const prevOnMsg = w.onmessage;
    const handler = (ev: MessageEvent) => {
      const data = ev.data as { id: number; ok: boolean; output?: T; error?: string };
      if (data.id !== id) {
        prevOnMsg?.call(w, ev);
        return;
      }
      const p = pending.get(id);
      if (p) {
        clearTimeout(p.timer);
        pending.delete(id);
      }
      if (data.ok) resolve(data.output as T);
      else reject(parseError(data.error || 'WORKER_FAILURE'));
    };
    w.onmessage = handler;
    const timer = setTimeout(() => {
      if (pending.delete(id)) {
        w.onmessage = prevOnMsg;
        reject(new LsbError('WORKER_TIMEOUT', 'LSB worker did not respond within 60s'));
      }
    }, timeoutMs);
    pending.set(id, { resolve: handler as never, reject, timer });
    w.postMessage({ id, type, input }, [input.pixels]);
  });
}

/* ---------------- public API ---------------- */

/** Run one trivial job so getWorkerMode() reflects reality before the first user op. */
export function primeWorker(): void {
  if (typeof window === 'undefined') return;
  void workerNoiseAsyncProbe().catch(() => undefined);
}

async function workerNoiseAsyncProbe(): Promise<void> {
  const probe = new Uint8Array(16);
  try {
    await workerNoise(probe);
  } catch {
    /* probe is best-effort */
  }
}

export async function workerEmbed(data: Uint8Array, payload: Uint8Array, flags: number): Promise<EmbedOutput> {
  const copy = data.slice(); // keep caller's buffer intact; the copy gets transferred
  const w = await getWorker();
  if (w) {
    try {
      workerMode = 'worker';
      return await dispatch<EmbedOutput>(w, 'embed', { pixels: copy.buffer as ArrayBuffer, payload: payload.slice().buffer as ArrayBuffer, flags });
    } catch (err) {
      if (err instanceof LsbError) throw err; // semantic errors are identical on both paths
      throw err;
    }
  }
  workerMode = 'main-thread';
  const res = embedIntoPixels(copy, payload, flags);
  return { pixels: copy.buffer as ArrayBuffer, ...res };
}

export async function workerExtract(data: Uint8Array): Promise<ExtractOutput> {
  const copy = data.slice();
  const w = await getWorker();
  if (w) {
    workerMode = 'worker';
    return await dispatch<ExtractOutput>(w, 'extract', { pixels: copy.buffer as ArrayBuffer });
  }
  workerMode = 'main-thread';
  const res = extractFromPixels(copy);
  return { ...res, payload: res.payload.slice().buffer as ArrayBuffer };
}

export async function workerNoise(data: Uint8Array): Promise<NoiseOutput> {
  const copy = data.slice();
  const w = await getWorker();
  if (w) {
    workerMode = 'worker';
    return await dispatch<NoiseOutput>(w, 'noise', { pixels: copy.buffer as ArrayBuffer });
  }
  workerMode = 'main-thread';
  const touched = randomizeLsb(copy);
  return { pixels: copy.buffer as ArrayBuffer, touched };
}
