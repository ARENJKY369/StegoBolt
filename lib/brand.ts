/**
 * StegoBolt brand assets — plain constants (server- and client-safe).
 *
 * The mark: a security shield (zero-knowledge) carrying a lightning bolt
 * knocked out in negative space (Bolt), with two pixel squares trailing
 * from the strike — the hidden LSB payload.
 */

export const FAVICON_SVG =
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 40 40'>" +
  "<rect width='40' height='40' rx='9' fill='#0a0e13'/>" +
  "<path d='M20 6.5 L31.6 10.7 L31.6 20.6 C31.6 26.7 27.3 31.3 20 34.3 C12.7 31.3 8.4 26.7 8.4 20.6 L8.4 10.7 Z' fill='#22c55e'/>" +
  "<path d='M23 13.1 L15.5 23.3 L19.5 23.3 L18.1 29.6 L25.6 19.4 L21.6 19.4 Z' fill='#0a0e13'/>" +
  "<rect x='26.3' y='22.2' width='2.3' height='2.3' rx='0.55' fill='#ffffff' opacity='0.92'/>" +
  "<rect x='28.6' y='25.5' width='1.6' height='1.6' rx='0.4' fill='#ffffff' opacity='0.55'/>" +
  '</svg>';

/** Single-pass percent encoding: `#` → %23 exactly once, so fills stay valid. */
export const FAVICON_URL = `data:image/svg+xml,${encodeURIComponent(FAVICON_SVG)}`;
