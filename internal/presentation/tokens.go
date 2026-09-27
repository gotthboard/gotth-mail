// Package presentation contains host-owned presentation bytes shared by Mail surfaces.
package presentation

// LightColors and DarkColors are only the reviewed scalar colors. Layout and
// authentication remain owned by each surface. Trailing delimiters are part of
// the exact legacy webmail byte contract.
const LightColors = "--bg:#f4f6f9;--surface:#fff;--surface-2:#edf2f7;--text:#172033;--muted:#596579;--line:#c6cfdb;--accent:#175ea8;--accent-2:#0d4d8d;--focus:#ffb000;--danger:#a3212b;"
const DarkColors = "--bg:#111722;--surface:#182230;--surface-2:#202d3d;--text:#eef4fb;--muted:#b0bfd0;--line:#405064;--accent:#69adf0;--accent-2:#8bc2f5;--focus:#ffd166;--danger:#ff8e96;"
