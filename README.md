# Veilr

Privacy tool for individuals — encrypt a message, paste it into WhatsApp, Telegram, SMS, or email, and only the person with both passwords can read it. No server, no account, no tracking.

## Project structure

```
veilr-final-build/
├── index.html          ← all markup (structure only, no inline styles/scripts)
├── manifest.json        ← PWA install config (name, icons, colors)
├── sw.js                ← service worker — offline support + install prompt
├── robots.txt           ← SEO crawler rules
├── sitemap.xml          ← SEO sitemap
├── css/
│   └── styles.css       ← all styling, colors, fonts, layout
├── js/
│   └── app.js           ← all logic: crypto, contacts, UI state
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

## How the pieces fit together

`index.html` only contains structure — every visual style lives in `css/styles.css`, every behavior lives in `js/app.js`. This separation means you can hand the CSS file to a designer or the JS file to a developer without them needing to touch the other.

`manifest.json` and `sw.js` are what let a phone "install" Veilr as a real app icon on the home screen, and let it keep working with no internet connection after the first visit.

## Making changes

**To change colors or fonts:** edit the `:root` variables at the top of `css/styles.css`. Every color in the app references one of these variables, so changing `--accent` once changes it everywhere.

**To add a new screen/panel:** copy the structure of an existing `<div class="panel" id="panel-...">` block in `index.html`, give it a new id, and add a corresponding `openPanel('panel-yourname')` call wherever you want to link to it from.

**To add a new messaging app option (e.g. Signal, Discord):** in `js/app.js`, add an entry to the `APP_LINKS` object near the top, following the same pattern as the existing ones, then add a matching button in the `.app-grid` section of `index.html`.

**To change encryption parameters:** the crypto functions (`encryptMessage`, `decryptMessage`, `deriveKey`) are isolated near the top of `js/app.js` and don't depend on any UI code — safe to read/modify in isolation.

**After any real content update:** bump `CACHE_VERSION` in `sw.js` (e.g. `'veilr-v1'` → `'veilr-v2'`). Without this, returning visitors' browsers will keep serving the old cached version indefinitely.

## Deploy to GitHub + Vercel (free)

1. Create a new GitHub repository (e.g. `veilr`)
2. Upload every file and folder in this project, keeping the structure exactly as-is
3. Go to vercel.com → sign in with GitHub → "Add New Project" → select the `veilr` repo
4. Leave all settings on default — no framework, no build command needed
5. Click Deploy

Live in under a minute at a `https://veilr.vercel.app`-style URL. Installable on both Android and iPhone home screens, works fully offline after the first load.

### Using a custom domain later
Buy any domain (e.g. `veilr.app`) from a registrar, then in Vercel go to your project → Settings → Domains → add it. Update the URLs inside `index.html` (`canonical`, `og:url`), `robots.txt`, and `sitemap.xml` to match your real domain once you have one.

## What's intentionally NOT included

No backend, no database, no analytics, no ad code — by design, since the entire trust model rests on "nothing ever leaves your device." If you add Google AdSense later, do it only after getting a real owned domain (Vercel's free `.vercel.app` subdomains aren't eligible for AdSense approval).

## Data & recovery

All contacts and passwords live only in the browser's local storage on each individual device. There is no cloud backup. Use Settings → Export Contacts periodically to download a backup file, especially before clearing browser data or switching phones. Settings → Import Contacts restores from that file.
