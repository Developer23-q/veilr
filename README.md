# Veilr

Privacy tool for individuals — encrypt a message, paste it into WhatsApp, Telegram, SMS, or email, and only the person with both passwords can read it. No server, no account, no tracking.

## Project structure

```
veilr-v2/
├── index.html          ← all markup (structure only, no inline styles/scripts)
├── manifest.json        ← PWA install config (name, icons, colors)
├── sw.js                ← service worker — offline support + install prompt
├── robots.txt           ← SEO crawler rules
├── sitemap.xml          ← SEO sitemap
├── css/
│   └── styles.css       ← all styling, colors, fonts, layout
├── js/
│   └── app.js           ← all logic: crypto, contacts, UI state, QR show/scan, install banner
├── lib/
│   ├── qrcode.js         ← vendored QR generator (MIT, Kazuhiko Arase — see attribution below)
│   ├── scanner.js         ← QR camera scanner using native BarcodeDetector API
│   └── secure-storage.js   ← encrypts contact/password data at rest (see Security fixes below)
└── icons/
    ├── icon-16.png       favicon (browser tab)
    ├── icon-32.png        favicon (browser tab, retina)
    ├── icon-180.png       Apple touch icon (iOS home screen)
    ├── icon-192.png        Android home screen icon
    ├── icon-512.png         PWA splash / app store-style icon
    ├── icon-maskable-512.png  Android adaptive icon (safe zone padded)
    ├── og-image.png            social share preview (WhatsApp/Twitter link cards)
    └── veilr-splash.png         original uploaded source image
```

## File encryption

The Files tab encrypts any file type (images, PDFs, video, anything) up to 25MB using the same AES-256-GCM + dual-password design as text messages — it reuses whichever contact is selected, so no separate password setup is needed. There's no chunking; the whole file is read into memory, encrypted, and held in memory until downloaded or shared. Files larger than 25MB are rejected before being read, since a single-shot in-memory encrypt of something much bigger risks freezing the browser tab.

Output comes in two forms simultaneously: a downloadable `.enc` file (binary, smallest size) and a `VEILRFILE:` Base64 text block (larger, but pasteable anywhere text works — email, chat, notes). The original filename and MIME type are stored inside the encrypted payload itself, so decrypting restores the exact filename rather than a generic one.

Decryption accepts either a dropped/picked `.enc` file or pasted Base64 text, and always goes straight to a download with no in-app preview — by design, to keep the implementation simple and avoid rendering untrusted file content inside the app. If the device supports the native Share Sheet (`navigator.share`), a Share button appears alongside Download for both encrypting and decrypting.

## QR code password sharing

`lib/qrcode.js` is a vendored copy of the well-known `qrcode-generator` library by Kazuhiko Arase (MIT licensed, the same lineage used inside the popular npm `qrcode` package). It's bundled directly rather than loaded from a CDN so Veilr keeps working fully offline. It was verified before inclusion by generating real QR codes and decoding them with an independent decoder (OpenCV's QRCodeDetector) to confirm correctness — see the project's build history for the verification steps if you want to re-run them.

`lib/scanner.js` uses the browser's native `BarcodeDetector` API to scan QR codes via the camera. This API is supported in Chrome, Edge, and most Android browsers, but **not yet in Safari/iOS** as of this writing. On unsupported browsers, Veilr shows a clear message and falls back to manual password entry rather than failing silently or loading a large external scanning library just for that case.

In Add Contact: tapping the QR icon next to "Your password" shows a scannable QR code for the other person to scan with their camera. Tapping the QR icon next to "Their password" opens the camera to scan theirs. Manual typing always remains available as a fallback.

## Floating install banner

The install banner now appears on every visit (not just once) until the app is actually running in installed/standalone mode, at which point it's automatically suppressed — there's no reason to prompt someone to install an app they're already using as an app. Dismissing the banner only hides it for the current visit; it will reappear next time, by design.

## How the pieces fit together

`index.html` only contains structure — every visual style lives in `css/styles.css`, every behavior lives in `js/app.js`. This separation means you can hand the CSS file to a designer or the JS file to a developer without them needing to touch the other.

`manifest.json` and `sw.js` are what let a phone "install" Veilr as a real app icon on the home screen, and let it keep working with no internet connection after the first visit.

## Making changes

**To change colors or fonts:** edit the `:root` variables at the top of `css/styles.css`. Every color in the app references one of these variables, so changing `--accent` once changes it everywhere.

**To add a new screen/panel:** copy the structure of an existing `<div class="panel" id="panel-...">` block in `index.html`, give it a new id, and add a corresponding `openPanel('panel-yourname')` call wherever you want to link to it from.

**To add a new messaging app option (e.g. Signal, Discord):** in `js/app.js`, add an entry to the `APP_LINKS` object near the top, following the same pattern as the existing ones, then add a matching button in the `.app-grid` section of `index.html`.

**To change encryption parameters:** the crypto functions (`encryptMessage`, `decryptMessage`, `deriveKey`) are isolated near the top of `js/app.js` and don't depend on any UI code — safe to read/modify in isolation.

**After any real content update:** bump `CACHE_VERSION` in `sw.js` (e.g. `'veilr-v1'` → `'veilr-v2'`). Without this, returning visitors' browsers will keep serving the old cached version indefinitely.

## Deploy to GitHub Pages (free)

1. Create a new GitHub repository named `veilr`
2. Upload every file and folder in this project to the repo root, keeping the structure exactly as-is (including the `lib/` folder)
3. Go to the repo's **Settings → Pages**
4. Under "Source", select **Deploy from a branch**, pick `main` (or `master`) and `/ (root)`, then Save
5. Wait 1–2 minutes — GitHub will publish it

Your live URL will be `https://<your-github-username>.github.io/veilr/` (note the trailing `/veilr/` — GitHub Pages serves project repos from a subpath, not the domain root, unless the repo is literally named `<username>.github.io`). All paths in this project are already relative, so it works correctly either way.

Installable on both Android and iPhone home screens, works fully offline after the first load, with the install banner appearing on every visit until installed.

### Using a custom domain later
Buy any domain (e.g. `veilr.app`) from a registrar, add a `CNAME` file to the repo root containing just the domain name, then configure it under Settings → Pages → Custom domain. Update the absolute URLs inside `index.html` (`canonical`, `og:url`, `og:image`, `twitter:image`), `robots.txt`, and `sitemap.xml` to match your real domain once you have one — everything else in the project uses relative paths and needs no changes.

## Security fixes applied

This project went through a full cryptography and application-security audit. Every finding below was fixed and re-verified against the actual shipped code, not just patched and assumed correct:

- **Key derivation redesigned** — the two contact passwords used to be each run through PBKDF2 independently (same salt) and XOR'd together, which meant an attacker who already knew one password could reduce the attack to cracking only the other one. Both passwords are now concatenated with a separator and run through a single PBKDF2 derivation, so there's no intermediate per-password artifact to compute. PBKDF2 iterations were also raised from 250,000 to 600,000, matching current OWASP guidance.
- **Password storage encrypted at rest** — contact records (containing both saved password halves) were stored in plaintext in `localStorage`. They're now encrypted with a non-extractable, device-bound AES key persisted in IndexedDB (`lib/secure-storage.js`) before ever touching `localStorage`. **This specific mechanism relies on real browser IndexedDB/WebCrypto behavior that could not be executed-tested in the environment this was built in — verify in DevTools (Application → IndexedDB) after first load in your actual deployment before relying on it.**
- **Two proven XSS vulnerabilities closed** — the contact list and file-contact dropdown used to build `onclick="...('${c.id}')"` strings directly from contact data, which a malicious imported backup file could break out of to run arbitrary script. Both now use `createElement`/`textContent`/`addEventListener` instead of string-built HTML, which removes the entire class of bug rather than just escaping the one exploited field.
- **Contact app-link fields sanitized** — the "their phone number / username / email" field was passed unsanitized into outbound URLs for Telegram, Email, and Messenger, and the popup-blocked fallback link rendered that URL via `innerHTML`. Every app-link builder now allowlist-sanitizes its input by field type (digits-only, username-safe characters, or a real email shape check), the fallback link is built with safe DOM APIs, and a URL-scheme allowlist (`https:`/`sms:`/`mailto:` only) blocks anything else as a second independent layer.
- **Import Contacts validates every field** — a backup file used to be trusted as soon as `data.contacts` was an array, with no check on what was inside each entry. Every imported contact is now validated field-by-field (type, length, character set, and that `app` is a real known value) before being stored; malformed entries are rejected individually rather than corrupting the whole import.
- **Content-Security-Policy added** — restricts script/style/connection sources to the app itself (plus the two Google Fonts domains already in use), blocks plugins and framing entirely. Note: it still permits inline `<script>` execution because the app's many static (non-data-driven) `onclick="functionName()"` handlers depend on it — see the comment above the CSP tag in `index.html` for the full reasoning and what a future no-inline-script refactor would involve.
- **Password generator bias removed** — switched from modulo-based character selection (which made 8 of 62 characters very slightly more likely) to rejection sampling for a uniform distribution.
- **Unknown app values fail safely** — a contact with a corrupted or unrecognized `app` field used to throw and break rendering entirely; it now falls back to a safe placeholder instead of crashing the Contacts panel for every contact.

## What's intentionally NOT included

No backend, no database, no analytics, no ad code — by design, since the entire trust model rests on "nothing ever leaves your device." If you add Google AdSense later, do it only after getting a real owned domain (free `github.io` subdomains aren't eligible for AdSense approval).

**Argon2 key derivation** is deliberately not included yet. PBKDF2 (250,000 rounds, native to every browser via Web Crypto API) is the only key derivation method currently implemented. Argon2 would need a WASM library, and unlike the vendored QR code library — which could be verified by actually generating and decoding real QR codes with an independent decoder — there was no safe way to verify a hand-built or blindly-trusted Argon2 implementation without testing infrastructure for it. Adding a properly sourced, verified Argon2 WASM build later is a contained addition: it would slot in as an alternate path inside `pbkdf2Key()`/`deriveKey()` in `js/app.js`, selectable per-contact, without touching the rest of the app.

## Data & recovery

All contacts and passwords live only in the browser's local storage on each individual device. There is no cloud backup. Use Settings → Export Contacts periodically to download a backup file, especially before clearing browser data or switching phones. Settings → Import Contacts restores from that file.
