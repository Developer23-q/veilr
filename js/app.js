// ══════════════════════════════════════════════════════
// CRYPTO ENGINE — AES-256-GCM, dual password
//
// SECURITY NOTE: both passwords are combined into a SINGLE PBKDF2 input
// (concatenated with a NUL separator) before key derivation. This is
// deliberate: an earlier design derived each password independently with
// PBKDF2 then XOR'd the results, which let an attacker who already knows
// ONE password reduce the attack to cracking only the other password
// (since the salt travels with the ciphertext). Concatenating first means
// there is only one derived secret, and an attacker must know the EXACT
// pair — both passwords AND their order — to ever compute it.
// ══════════════════════════════════════════════════════
const ENC = new TextEncoder();
const DEC = new TextDecoder();
const PREFIX = 'VEILR2:';
const PBKDF2_ITERATIONS = 600000; // raised to current OWASP guidance (was 250,000)

async function deriveKey(pwA, pwB, salt) {
  // NUL byte separator prevents ambiguity like "ab"+"c" vs "a"+"bc" colliding.
  const combinedInput = ENC.encode(pwA + '\u0000' + pwB);
  const mat = await crypto.subtle.importKey('raw', combinedInput, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    mat, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

function b64enc(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }

function b64dec(str){
  // Strip whitespace/newlines that can get introduced when text is
  // copy-pasted across apps (SMS reassembly, email line-wrapping, etc.)
  const cleaned = str.replace(/\s+/g, '');
  // Valid base64 length must be a multiple of 4. If it isn't, the text
  // was almost certainly cut off mid-copy rather than actually corrupted.
  if (cleaned.length === 0 || cleaned.length % 4 !== 0) {
    throw new Error('TRUNCATED');
  }
  // Valid base64 alphabet only (letters, digits, +, /, and = padding at the end)
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) {
    throw new Error('TRUNCATED');
  }
  try {
    return Uint8Array.from(atob(cleaned), c=>c.charCodeAt(0));
  } catch(e) {
    throw new Error('TRUNCATED');
  }
}

function concatBytes(arrs){ const n=arrs.reduce((a,b)=>a+b.length,0); const out=new Uint8Array(n); let o=0; for(const a of arrs){out.set(a,o);o+=a.length;} return out; }

async function encryptMessage(msg, pwA, pwB) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(pwA, pwB, salt);
  const ct   = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, ENC.encode(msg));
  const packed = concatBytes([salt, iv, new Uint8Array(ct)]);
  return PREFIX + b64enc(packed.buffer);
}

async function decryptMessage(raw, pwA, pwB) {
  if (!raw.startsWith(PREFIX)) throw new Error('NOT_VEILR');

  let packed;
  try {
    packed = b64dec(raw.slice(PREFIX.length));
  } catch(e) {
    throw new Error('TRUNCATED');
  }

  // Minimum valid payload = 16 (salt) + 12 (iv) + 16 (GCM auth tag, smallest
  // possible ciphertext for an empty message) = 44 bytes. Anything shorter
  // is definitely a cut-off copy, not a real Veilr message.
  if (packed.length < 44) throw new Error('TRUNCATED');

  const salt = packed.slice(0,16);
  const iv   = packed.slice(16,28);
  const ct   = packed.slice(28);
  const key  = await deriveKey(pwA, pwB, salt);
  try {
    const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    return DEC.decode(plain);
  } catch(e) { throw new Error('WRONG_PW'); }
}

// ══════════════════════════════════════════════════════
// FILE CRYPTO — same AES-256-GCM + dual-password design as text,
// extended with a small metadata header so the original filename
// and MIME type survive the round trip.
//
// Binary layout: "VEILRF1" (7 bytes) + 16 salt + 12 iv + ciphertext
// Plaintext-before-encryption layout: 2-byte metaLen + metaJSON + fileBytes
// ══════════════════════════════════════════════════════
const FILE_MAGIC = 'VEILRF1';
const FILE_TEXT_PREFIX = 'VEILRFILE:';
const MAX_FILE_BYTES = 25 * 1024 * 1024; // 25MB cap — no chunking, by design

async function encryptFileBytes(fileBytes, filename, mimeType, pwA, pwB) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pwA, pwB, salt);

  const meta = JSON.stringify({ n: filename, t: mimeType || 'application/octet-stream' });
  const metaBytes = ENC.encode(meta);
  const metaLenBuf = new Uint8Array(2);
  new DataView(metaLenBuf.buffer).setUint16(0, metaBytes.length, false);

  const plainCombined = concatBytes([metaLenBuf, metaBytes, fileBytes]);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainCombined);

  const magicBytes = ENC.encode(FILE_MAGIC);
  return concatBytes([magicBytes, salt, iv, new Uint8Array(ct)]);
}

async function decryptFileBytes(packedBytes, pwA, pwB) {
  if (packedBytes.length < 7 + 16 + 12 + 16) throw new Error('TRUNCATED');

  const magic = DEC.decode(packedBytes.slice(0, 7));
  if (magic !== FILE_MAGIC) throw new Error('NOT_VEILR_FILE');

  const salt = packedBytes.slice(7, 23);
  const iv = packedBytes.slice(23, 35);
  const ct = packedBytes.slice(35);
  const key = await deriveKey(pwA, pwB, salt);

  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  } catch (e) {
    throw new Error('WRONG_PW');
  }

  if (plain.length < 2) throw new Error('TRUNCATED');
  const metaLen = new DataView(plain.buffer, plain.byteOffset, 2).getUint16(0, false);
  if (plain.length < 2 + metaLen) throw new Error('TRUNCATED');

  const metaBytes = plain.slice(2, 2 + metaLen);
  let meta;
  try {
    meta = JSON.parse(DEC.decode(metaBytes));
  } catch (e) {
    throw new Error('TRUNCATED');
  }
  const fileBytes = plain.slice(2 + metaLen);
  return { filename: meta.n || 'decrypted-file', mimeType: meta.t || 'application/octet-stream', fileBytes };
}

// ══════════════════════════════════════════════════════
// STORAGE
//
// SECURITY: contact records (which contain both halves of every saved
// password) are encrypted at rest via VeilrSecureStorage before they
// ever reach localStorage — see lib/secure-storage.js for the full
// design rationale and its documented verification caveat.
//
// To avoid a large, risky refactor of every synchronous call site that
// reads/writes contacts throughout this file, persisted data is mirrored
// into an in-memory cache (_contactsCache) that is loaded once,
// asynchronously, at startup via initSecureStorage(). All the existing
// getContacts()/setContacts() call sites continue to work exactly as
// before — they read/write the in-memory cache synchronously — while
// setContacts() also kicks off an async encrypted write-through to
// localStorage in the background.
// ══════════════════════════════════════════════════════
let _contactsCache = [];
let _secureStorageReady = false;

async function initSecureStorage() {
  try {
    const raw = localStorage.getItem('veilr_contacts_enc');
    if (raw) {
      _contactsCache = await VeilrSecureStorage.decryptFromStorage(raw, []);
    } else {
      // First run on this device, or migrating from an older plaintext version.
      const legacyPlain = localStorage.getItem('veilr_contacts');
      if (legacyPlain) {
        try {
          _contactsCache = JSON.parse(legacyPlain);
          // Immediately re-encrypt and remove the old plaintext copy.
          await persistContactsCache();
          localStorage.removeItem('veilr_contacts');
        } catch (e) {
          _contactsCache = [];
        }
      }
    }
  } catch (e) {
    // INDEXEDDB_UNAVAILABLE or similar — fail closed to an empty contact
    // list rather than silently falling back to plaintext storage.
    _contactsCache = [];
  }
  _secureStorageReady = true;
  renderHome();
  if (document.getElementById('panel-contacts').classList.contains('open')) {
    renderContactsPanel();
  }
}

async function persistContactsCache() {
  try {
    const encrypted = await VeilrSecureStorage.encryptForStorage(_contactsCache);
    localStorage.setItem('veilr_contacts_enc', encrypted);
  } catch (e) {
    // If encryption genuinely fails (e.g. IndexedDB unavailable), data stays
    // in-memory for this session only rather than being written as plaintext.
  }
}

function getContacts() { return _contactsCache; }
function setContacts(arr) {
  _contactsCache = arr;
  persistContactsCache(); // fire-and-forget; cache is already updated synchronously above
}
function getLastActive(){ return localStorage.getItem('veilr_last_active'); }
function setLastActive(id){ localStorage.setItem('veilr_last_active', id); }
function getClipTime(){ return parseInt(localStorage.getItem('veilr_clip_time')||'30'); }
function setClipTime(v){ localStorage.setItem('veilr_clip_time', String(v)); }

// SECURITY: every build() function strips to an explicit allowlist of safe
// characters for its field type BEFORE constructing the URL. This is the
// primary fix for the contact "app target" XSS finding — previously
// telegram/email/messenger passed the raw value straight into the URL with
// no sanitization at all, and a value like '"><img src=x onerror=...>'
// would survive into the generated link. encodeURIComponent alone is not
// enough here since the goal is rejecting structurally invalid usernames/
// emails outright, not just escaping characters for transport.
function sanitizePhoneOrDigits(t) {
  return String(t || '').replace(/[^0-9+]/g, '').slice(0, 20);
}
function sanitizeUsername(t) {
  // Letters, digits, underscore, dot — covers Telegram/Messenger username rules.
  return String(t || '').replace(/[^A-Za-z0-9_.]/g, '').slice(0, 64);
}
function sanitizeEmail(t) {
  const cleaned = String(t || '').trim().slice(0, 254);
  // Conservative email shape check — rejects anything that isn't a plausible
  // address rather than trying to fully validate per RFC 5322.
  return /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(cleaned) ? cleaned : '';
}

const APP_LINKS = {
  whatsapp:  {name:'WHATSAPP',  label:'Their phone number',  icon:'💬', build:(t)=>{ const d=sanitizePhoneOrDigits(t); return d ? `https://wa.me/${d}` : null; }},
  telegram:  {name:'TELEGRAM',  label:'Their @username',      icon:'✈️', build:(t)=>{ const u=sanitizeUsername(t); return u ? `https://t.me/${u}` : null; }},
  sms:       {name:'MESSAGES',  label:'Their phone number',  icon:'💭', build:(t)=>{ const d=sanitizePhoneOrDigits(t); return d ? `sms:${d}` : null; }},
  email:     {name:'EMAIL',     label:'Their email address', icon:'✉️', build:(t)=>{ const e=sanitizeEmail(t); return e ? `mailto:${e}` : null; }},
  messenger: {name:'MESSENGER', label:'Their Messenger username', icon:'🔵', build:(t)=>{ const u=sanitizeUsername(t); return u ? `https://m.me/${u}` : null; }},
};

// ══════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════
let activeContactId = null;
let pendingDeleteId = null;
let editingContactId = null;
let lastLockedCipher = null;

function activeContact() {
  return getContacts().find(c => c.id === activeContactId) || null;
}

// ══════════════════════════════════════════════════════
// HOME RENDER
// ══════════════════════════════════════════════════════
function renderHome() {
  const contacts = getContacts();
  const empty = document.getElementById('home-empty');
  const active = document.getElementById('home-active');
  const actionRow = document.getElementById('action-row');

  if (contacts.length === 0) {
    empty.style.display = 'flex';
    active.style.display = 'none';
    actionRow.style.display = 'none';
    document.getElementById('cb-name').textContent = 'No contact selected';
    document.getElementById('cb-avatar').textContent = '?';
    return;
  }

  if (!activeContactId || !activeContact()) {
    const last = getLastActive();
    activeContactId = contacts.find(c=>c.id===last) ? last : contacts[0].id;
  }

  const c = activeContact();
  empty.style.display = 'none';
  active.style.display = 'flex';
  actionRow.style.display = 'flex';
  document.getElementById('cb-name').textContent = c.name;
  document.getElementById('cb-avatar').textContent = c.name.charAt(0).toUpperCase();
  document.getElementById('send-app-name').textContent = safeAppLink(c.app).name;

  resetSmartbox();
}

function resetSmartbox() {
  const box = document.getElementById('smartbox');
  box.value = '';
  box.classList.remove('cipher-mode','error-mode');
  box.placeholder = 'Type a message to lock, or paste a Veilr message to unlock…';
  document.getElementById('status-line').textContent = '';
  document.getElementById('status-line').className = 'status-line idle';
  document.getElementById('btn-lock').style.display = 'flex';
  document.getElementById('btn-send').style.display = 'none';
  document.getElementById('btn-new').style.display = 'none';
  lastLockedCipher = null;
}

function goHome() {
  document.querySelectorAll('.panel.open').forEach(p=>p.classList.remove('open'));
  setActiveNav(0);
  renderHome();
}

function setActiveNav(i) {
  document.querySelectorAll('.nav-item').forEach((n,idx)=>n.classList.toggle('active', idx===i));
}

// ══════════════════════════════════════════════════════
// SMART BOX — type to lock, paste to auto-decrypt
// ══════════════════════════════════════════════════════
let suppressNextInput = false;

async function onTyping() {
  const box = document.getElementById('smartbox');
  const val = box.value;

  if (suppressNextInput) { suppressNextInput = false; return; }

  // Detect a pasted/typed Veilr cipher
  if (val.trim().startsWith(PREFIX)) {
    await tryAutoDecrypt(val.trim());
    return;
  }

  // Normal typing state
  box.classList.remove('cipher-mode','error-mode');
  document.getElementById('status-line').textContent = '';
  document.getElementById('status-line').className = 'status-line idle';
  document.getElementById('btn-lock').style.display = val.trim() ? 'flex' : 'flex';
  document.getElementById('btn-send').style.display = 'none';
  lastLockedCipher = null;
}

async function tryAutoDecrypt(cipherText) {
  const c = activeContact();
  const box = document.getElementById('smartbox');
  const status = document.getElementById('status-line');

  if (!c) {
    status.textContent = 'Select a contact first to decrypt.';
    status.className = 'status-line err';
    return;
  }

  status.textContent = '⏳ Decrypting…';
  status.className = 'status-line idle';

  try {
    const plain = await decryptMessage(cipherText, c.pwMine, c.pwTheirs);
    suppressNextInput = true;
    box.value = plain;
    box.classList.remove('cipher-mode','error-mode');
    status.innerHTML = '✓ Decrypted · verified, not tampered';
    status.className = 'status-line ok';
    document.getElementById('btn-lock').style.display = 'flex';
    document.getElementById('btn-send').style.display = 'none';
    document.getElementById('btn-new').style.display = 'flex';

    // Clipboard auto-clear — verify it actually worked
    const copied = await safeCopyToClipboard(plain);
    if (copied) {
      scheduleClipboardWipe();
    } else {
      showToast('Decrypted — clipboard copy was blocked, copy manually if needed');
    }
  } catch(e) {
    box.classList.add('error-mode');
    if (e.message === 'WRONG_PW') {
      status.textContent = `✗ Can't decrypt — wrong password for "${c.name}", or the text wasn't copied completely`;
    } else if (e.message === 'TRUNCATED') {
      status.textContent = '✗ This message looks incomplete — make sure you copied the entire encrypted text, then paste it again';
    } else {
      status.textContent = '✗ This text is damaged or not a valid Veilr message';
    }
    status.className = 'status-line err';
  }
}

async function doLock() {
  const c = activeContact();
  const box = document.getElementById('smartbox');
  const status = document.getElementById('status-line');
  const msg = box.value.trim();

  if (!c) { status.textContent = 'Select a contact first.'; status.className='status-line err'; return; }
  if (!msg) { status.textContent = 'Type a message first.'; status.className='status-line err'; return; }
  if (msg.startsWith(PREFIX)) return; // already cipher, ignore

  status.textContent = '⏳ Locking…';
  status.className = 'status-line idle';

  try {
    const cipher = await encryptMessage(msg, c.pwMine, c.pwTheirs);
    suppressNextInput = true;
    box.value = cipher;
    box.classList.add('cipher-mode');
    lastLockedCipher = cipher;

    const copied = await safeCopyToClipboard(cipher);

    document.getElementById('btn-send').style.display = 'flex';
    document.getElementById('btn-new').style.display = 'flex';

    if (copied) {
      status.textContent = '✓ Locked & copied';
      status.className = 'status-line ok';
      showToast('Copied to clipboard');
    } else {
      status.innerHTML = '✓ Locked — <strong>tap to copy manually</strong>, clipboard access was blocked';
      status.className = 'status-line err';
      showToast('Could not auto-copy — tap the box and copy manually');
    }
  } catch(e) {
    status.textContent = 'Encryption failed: '+e.message;
    status.className = 'status-line err';
  }
}

// Verifies a clipboard write actually landed, instead of trusting a silent promise.
// Some mobile browsers resolve writeText() successfully but don't actually
// update the system clipboard (permission quietly denied in background).
async function safeCopyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    // Verify by reading back, where supported. If read is blocked
    // (common on iOS Safari for privacy reasons) we can't verify —
    // assume success rather than falsely reporting failure.
    try {
      const check = await navigator.clipboard.readText();
      return check === text;
    } catch {
      return true; // write likely succeeded; read permission just isn't granted
    }
  } catch (e) {
    return false;
  }
}

function doSend() {
  const c = activeContact();
  if (!c || !lastLockedCipher) return;
  if (!c.appTarget) {
    showToast('No contact info saved for this app');
    return;
  }
  const url = safeAppLink(c.app).build(c.appTarget);
  if (!url || !isSafeOutboundUrl(url)) {
    showToast('This contact\u2019s saved info looks invalid \u2014 edit the contact and re-enter it');
    return;
  }

  // window.open must be called synchronously in direct response to the
  // click for browsers to allow it. If it returns null/undefined, the
  // popup was blocked — fall back to a visible link the user can tap themselves.
  const win = window.open(url, '_blank');
  if (!win) {
    showSendFallback(url);
  }
}

// SECURITY: only allow the small set of URL schemes Veilr actually generates
// (https/sms/mailto). This is a defense-in-depth backstop in case a future
// app-link definition or imported contact data ever produces something like
// "javascript:" — window.open() and the anchor below would otherwise happily
// execute it. Genuine app links never need any other scheme.
function isSafeOutboundUrl(url) {
  if (typeof url !== 'string' || url.length === 0) return false;
  try {
    const parsed = new URL(url, window.location.href);
    return ['https:', 'sms:', 'mailto:'].includes(parsed.protocol);
  } catch (e) {
    return false;
  }
}

function showSendFallback(url) {
  const status = document.getElementById('status-line');
  status.textContent = "Couldn't open automatically — ";
  const a = document.createElement('a');
  a.href = url;              // assigning to .href never parses the value as markup/script
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.textContent = 'tap here to open';
  a.style.color = 'var(--blue)';
  a.style.textDecoration = 'underline';
  status.appendChild(a);
  status.className = 'status-line err';
  showToast('Popup blocked — use the link shown');
}

// ══════════════════════════════════════════════════════
// CLIPBOARD AUTO-WIPE
// ══════════════════════════════════════════════════════
let clipWipeTimeout = null;
function scheduleClipboardWipe() {
  if (clipWipeTimeout) clearTimeout(clipWipeTimeout);
  const secs = getClipTime();
  if (secs <= 0) return;
  clipWipeTimeout = setTimeout(()=>{
    navigator.clipboard.writeText('').catch(()=>{});
  }, secs*1000);
}

// ══════════════════════════════════════════════════════
// CONTACTS PANEL
// ══════════════════════════════════════════════════════
// SECURITY NOTE: contact rows are built with createElement/textContent and
// data-* attributes read via addEventListener, never via onclick="...('${c.id}')"
// string interpolation. The previous design built onclick handlers as raw
// strings, which let a crafted contact id (e.g. from a malicious imported
// backup file) break out of the attribute and execute arbitrary JS. Using
// the DOM API for both content and event wiring closes that class of bug
// structurally — there is no string position where untrusted data is ever
// parsed as code, regardless of what characters it contains.
function safeAppLink(appKey) {
  return APP_LINKS[appKey] || { name: 'UNKNOWN', icon: '❓', label: 'Contact info', build: () => null };
}

function renderContactsPanel() {
  const contacts = getContacts();
  const body = document.getElementById('contacts-body');
  body.textContent = ''; // clear safely, no innerHTML

  if (contacts.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    const icon = document.createElement('div'); icon.className = 'empty-icon'; icon.textContent = '👥';
    const title = document.createElement('div'); title.className = 'empty-title'; title.textContent = 'No contacts yet';
    const sub = document.createElement('div'); sub.className = 'empty-sub'; sub.textContent = 'Tap + to add the first person you want to message privately.';
    empty.append(icon, title, sub);
    body.appendChild(empty);
    return;
  }

  for (const c of contacts) {
    const link = safeAppLink(c.app);
    const safeName = typeof c.name === 'string' && c.name.length ? c.name : '(unnamed)';

    const item = document.createElement('div');
    item.className = 'contact-item';
    item.dataset.contactId = String(c.id);

    const avatar = document.createElement('div');
    avatar.className = 'ci-avatar';
    avatar.textContent = safeName.charAt(0).toUpperCase();

    const info = document.createElement('div');
    info.className = 'ci-info';
    const nameEl = document.createElement('div'); nameEl.className = 'ci-name'; nameEl.textContent = safeName;
    const appEl = document.createElement('div'); appEl.className = 'ci-app'; appEl.textContent = `${link.icon} via ${link.name}`;
    info.append(nameEl, appEl);

    const actions = document.createElement('div');
    actions.className = 'ci-actions';
    const editBtn = document.createElement('button');
    editBtn.className = 'ci-btn'; editBtn.textContent = '✎'; editBtn.setAttribute('aria-label', 'Edit contact');
    const delBtn = document.createElement('button');
    delBtn.className = 'ci-btn del'; delBtn.textContent = '🗑'; delBtn.setAttribute('aria-label', 'Delete contact');
    actions.append(editBtn, delBtn);

    item.append(avatar, info, actions);
    body.appendChild(item);

    // Event wiring via addEventListener + dataset — never via string-built onclick.
    item.addEventListener('click', () => selectContact(c.id));
    editBtn.addEventListener('click', (e) => { e.stopPropagation(); editContact(c.id); });
    delBtn.addEventListener('click', (e) => { e.stopPropagation(); askDelete(c.id); });
  }
}

function selectContact(id) {
  activeContactId = id;
  setLastActive(id);
  closePanel('panel-contacts');
  renderHome();
}

function askDelete(id) {
  pendingDeleteId = id;
  openModal('modal-delete');
}

function executeDelete() {
  let contacts = getContacts();
  contacts = contacts.filter(c => c.id !== pendingDeleteId);
  setContacts(contacts);
  if (activeContactId === pendingDeleteId) activeContactId = null;
  pendingDeleteId = null;
  closeModal('modal-delete');
  renderContactsPanel();
  renderHome();
}

// ══════════════════════════════════════════════════════
// ADD / EDIT CONTACT
// ══════════════════════════════════════════════════════
let selectedApp = 'whatsapp';

function openAddContact() {
  editingContactId = null;
  document.getElementById('add-contact-title').textContent = 'Add Contact';
  document.getElementById('c-name').value = '';
  document.getElementById('c-pw-mine').value = '';
  document.getElementById('c-pw-theirs').value = '';
  document.getElementById('c-app-target').value = '';
  selectedApp = 'whatsapp';
  document.querySelectorAll('.app-pick').forEach(el=>el.classList.toggle('active', el.dataset.app==='whatsapp'));
  document.getElementById('app-target-label').textContent = APP_LINKS.whatsapp.label;
  document.getElementById('app-target-field').querySelector('input').placeholder = '+1 555 123 4567';
  document.getElementById('sms-length-hint').style.display = 'none';
  setChecked(false);
  openPanel('panel-add-contact');
}

function editContact(id) {
  const c = getContacts().find(x=>x.id===id);
  if (!c) return;
  editingContactId = id;
  document.getElementById('add-contact-title').textContent = 'Edit Contact';
  document.getElementById('c-name').value = c.name;
  document.getElementById('c-pw-mine').value = c.pwMine;
  document.getElementById('c-pw-theirs').value = c.pwTheirs;
  document.getElementById('c-app-target').value = c.appTarget || '';
  selectedApp = c.app;
  document.querySelectorAll('.app-pick').forEach(el=>el.classList.toggle('active', el.dataset.app===c.app));
  document.getElementById('app-target-label').textContent = safeAppLink(c.app).label;
  document.getElementById('sms-length-hint').style.display = (c.app === 'sms') ? 'block' : 'none';
  setChecked(true);
  openPanel('panel-add-contact');
}

function pickApp(el) {
  document.querySelectorAll('.app-pick').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');
  selectedApp = el.dataset.app;
  document.getElementById('app-target-label').textContent = safeAppLink(selectedApp).label;
  const smsHint = document.getElementById('sms-length-hint');
  if (smsHint) smsHint.style.display = (selectedApp === 'sms') ? 'block' : 'none';
}

function genPassword() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*';
  // Rejection sampling: 256 % 62 != 0, so a plain modulo would make the first
  // 8 characters in the set slightly more likely than the rest. Discarding
  // bytes that fall in the biased remainder range keeps the distribution
  // uniform — the security difference is negligible at this length and
  // CSPRNG source, but there's no reason to accept an avoidable bias.
  const maxValid = 256 - (256 % chars.length);
  let pw = '';
  while (pw.length < 30) {
    const batch = crypto.getRandomValues(new Uint8Array(40)); // oversample to avoid many re-draws
    for (let i = 0; i < batch.length && pw.length < 30; i++) {
      if (batch[i] < maxValid) pw += chars[batch[i] % chars.length];
    }
  }
  document.getElementById('c-pw-mine').value = pw;
}

async function copyField(id, btnId) {
  const val = document.getElementById(id).value;
  if (!val) return;
  const btn = document.getElementById(btnId);
  const copied = await safeCopyToClipboard(val);
  if (copied) {
    btn.classList.add('copied');
    btn.textContent = '✓';
    setTimeout(()=>{ btn.classList.remove('copied'); btn.textContent='📋'; }, 1500);
    showToast('Password copied');
  } else {
    showToast('Copy blocked — select and copy the text manually');
  }
}

function toggleCheck() {
  const box = document.getElementById('purpose-check');
  setChecked(!box.classList.contains('checked'));
}
function setChecked(val) {
  const box = document.getElementById('purpose-check');
  box.classList.toggle('checked', val);
  document.getElementById('save-contact-btn').disabled = !val;
  const row = document.getElementById('purpose-check-row');
  if (row) row.setAttribute('aria-checked', String(val));
}

function saveContact() {
  if (!_secureStorageReady) {
    showToast('Still loading — please wait a moment and try again');
    return;
  }
  const name = document.getElementById('c-name').value.trim();
  const pwMine = document.getElementById('c-pw-mine').value.trim();
  const pwTheirs = document.getElementById('c-pw-theirs').value.trim();
  const appTarget = document.getElementById('c-app-target').value.trim();

  if (!name) { showToast('Enter a name'); return; }
  if (!pwMine) { showToast('Generate your password'); return; }
  if (!pwTheirs) { showToast("Enter their password"); return; }
  if (pwTheirs.length < 6) { showToast('Their password looks too short — double check it'); return; }
  if (!document.getElementById('purpose-check').classList.contains('checked')) { return; }

  let contacts = getContacts();

  if (editingContactId) {
    const existing = contacts.find(c=>c.id===editingContactId);
    const passwordsChanged = existing && (existing.pwMine !== pwMine || existing.pwTheirs !== pwTheirs);
    if (passwordsChanged && !confirm('Changing the password means old encrypted messages with this contact can no longer be decrypted. Continue?')) {
      return;
    }
    const idx = contacts.findIndex(c=>c.id===editingContactId);
    if (idx>-1) contacts[idx] = {...contacts[idx], name, pwMine, pwTheirs, app:selectedApp, appTarget};
  } else {
    const id = 'c_'+Date.now()+'_'+Math.random().toString(36).slice(2,7);
    contacts.push({id, name, pwMine, pwTheirs, app:selectedApp, appTarget});
    activeContactId = id;
    setLastActive(id);
  }

  setContacts(contacts);
  closePanel('panel-add-contact');
  renderContactsPanel();
  renderHome();
  showToast(editingContactId ? 'Contact updated' : 'Contact saved');
}

// ══════════════════════════════════════════════════════
// SETTINGS
// ══════════════════════════════════════════════════════
function cycleClipTime() {
  const opts = [10,30,60,0];
  const cur = getClipTime();
  const idx = opts.indexOf(cur);
  const next = opts[(idx+1)%opts.length];
  setClipTime(next);
  document.getElementById('clip-time-val').textContent = (next===0?'Off':next+'s') + ' ▾';
}

function exportContacts() {
  const data = JSON.stringify({contacts:getContacts(), exportedAt:Date.now()});
  const blob = new Blob([data], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'veilr-backup.json';
  a.click();
  URL.revokeObjectURL(url);
  showToast('Backup downloaded');
}

// SECURITY: validates one imported contact object field-by-field. This is
// the actual fix for the "malicious backup file" finding — even though
// renderContactsPanel() no longer interpolates contact fields into
// executable HTML/JS contexts (it uses textContent/dataset now), an
// imported file is still untrusted input feeding directly into crypto
// functions (pwMine/pwTheirs) and UI lookups (app). Validating shape and
// content here means a malformed or hostile backup file is rejected
// outright rather than silently accepted and only neutralized downstream.
function validateImportedContact(c) {
  if (typeof c !== 'object' || c === null) return null;

  const id = typeof c.id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(c.id)
    ? c.id
    : 'c_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);

  if (typeof c.name !== 'string' || c.name.trim().length === 0 || c.name.length > 100) return null;
  if (typeof c.pwMine !== 'string' || c.pwMine.length < 4 || c.pwMine.length > 256) return null;
  if (typeof c.pwTheirs !== 'string' || c.pwTheirs.length < 4 || c.pwTheirs.length > 256) return null;
  if (typeof c.app !== 'string' || !Object.prototype.hasOwnProperty.call(APP_LINKS, c.app)) return null;
  if (c.appTarget != null && (typeof c.appTarget !== 'string' || c.appTarget.length > 254)) return null;

  return {
    id,
    name: c.name.trim().slice(0, 100),
    pwMine: c.pwMine,
    pwTheirs: c.pwTheirs,
    app: c.app,
    appTarget: typeof c.appTarget === 'string' ? c.appTarget.slice(0, 254) : ''
  };
}

function importContacts(evt) {
  if (!_secureStorageReady) {
    showToast('Still loading — please wait a moment and try again');
    evt.target.value = '';
    return;
  }
  const file = evt.target.files[0];
  if (!file) return;

  // Cap import file size — an oversized "backup" is itself a low-effort DoS vector.
  if (file.size > 2 * 1024 * 1024) {
    showToast('That file is too large to be a real Veilr backup');
    evt.target.value = '';
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      if (!Array.isArray(data.contacts)) {
        showToast('Invalid backup file — no contacts found');
        return;
      }

      const validated = [];
      let rejected = 0;
      for (const raw of data.contacts.slice(0, 500)) { // hard cap, avoid pathological huge arrays
        const clean = validateImportedContact(raw);
        if (clean) validated.push(clean); else rejected++;
      }

      if (validated.length === 0) {
        showToast('No valid contacts found in that file');
        return;
      }

      setContacts(validated);
      renderContactsPanel();
      renderHome();
      showToast(rejected > 0
        ? `Imported ${validated.length} contact(s) — ${rejected} entr${rejected===1?'y':'ies'} skipped as invalid`
        : `Imported ${validated.length} contact(s)`);
    } catch (e) {
      showToast('Invalid backup file');
    }
  };
  reader.readAsText(file);
  evt.target.value = '';
}

function confirmDeleteAll() { openModal('modal-wipe'); }
function executeWipeAll() {
  localStorage.clear();
  _contactsCache = []; // must also clear the in-memory cache, not just localStorage
  activeContactId = null;
  closeModal('modal-wipe');
  renderContactsPanel();
  renderHome();
  showToast('All data deleted');
}

// ══════════════════════════════════════════════════════
// PANEL / MODAL NAVIGATION
// ══════════════════════════════════════════════════════
function openPanel(id) {
  document.getElementById(id).classList.add('open');
  if (id==='panel-files') { renderFilesPanel(); setActiveNav(1); }
  if (id==='panel-contacts') { renderContactsPanel(); setActiveNav(2); }
  if (id==='panel-info') setActiveNav(3);
  if (id==='panel-settings') setActiveNav(4);
}
function closePanel(id) {
  document.getElementById(id).classList.remove('open');
  if (id==='panel-add-contact') openPanel('panel-contacts');
}
function openModal(id){ document.getElementById(id).classList.add('show'); }
function closeModal(id){ document.getElementById(id).classList.remove('show'); }

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2000);
}

function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

document.querySelectorAll('.modal-bg').forEach(bg=>{
  bg.addEventListener('click', e=>{ if(e.target===bg) bg.classList.remove('show'); });
});

// ══════════════════════════════════════════════════════
// KEYBOARD ACCESSIBILITY — Enter/Space activates role=button/checkbox
// ══════════════════════════════════════════════════════
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const el = e.target;
  if (el && (el.getAttribute('role')==='button' || el.getAttribute('role')==='checkbox')) {
    e.preventDefault();
    el.click();
  }
});

// ══════════════════════════════════════════════════════
// CROSS-TAB SYNC — keeps multiple open tabs consistent
// ══════════════════════════════════════════════════════
window.addEventListener('storage', (e) => {
  if (e.key === 'veilr_contacts') {
    renderContactsPanel();
    renderHome();
  }
});

// ══════════════════════════════════════════════════════
// BACKUP REMINDER — nudge after 3+ contacts, once per week
// ══════════════════════════════════════════════════════
function maybeShowBackupReminder() {
  const contacts = getContacts();
  if (contacts.length < 3) return;
  const last = parseInt(localStorage.getItem('veilr_last_backup_nudge')||'0');
  const weekMs = 7*24*60*60*1000;
  if (Date.now() - last < weekMs) return;
  localStorage.setItem('veilr_last_backup_nudge', String(Date.now()));
  setTimeout(()=> showToast('Tip: back up your contacts in Settings → Export'), 1500);
}

// ══════════════════════════════════════════════════════
// NEW MESSAGE RESET (explicit, after a Lock or Decrypt)
// ══════════════════════════════════════════════════════
function newMessage() {
  resetSmartbox();
  document.getElementById('smartbox').focus();
}

// ══════════════════════════════════════════════════════
// QR CODE — SHOW (your password → QR for the other person to scan)
// ══════════════════════════════════════════════════════
function showPasswordQR() {
  const pw = document.getElementById('c-pw-mine').value.trim();
  if (!pw) { showToast('Generate your password first'); return; }
  if (typeof VeilrQR === 'undefined') { showToast('QR library failed to load'); return; }

  const wrap = document.getElementById('qr-show-canvas-wrap');
  wrap.innerHTML = '';
  try {
    const canvas = VeilrQR.renderToCanvas(pw, {
      cellSize: 7, margin: 3, dark: '#0a0c0f', light: '#ffffff', level: 'M'
    });
    canvas.style.borderRadius = '8px';
    canvas.style.maxWidth = '100%';
    wrap.appendChild(canvas);
    openModal('modal-qr-show');
  } catch (e) {
    showToast('Could not generate QR code: ' + e.message);
  }
}

// ══════════════════════════════════════════════════════
// QR CODE — SCAN (camera scan of their password QR)
// ══════════════════════════════════════════════════════
let _scanStop = null;
let _scanTargetFieldId = null;

function openScanQR(targetFieldId) {
  _scanTargetFieldId = targetFieldId;
  const statusEl = document.getElementById('qr-scan-status');
  const videoEl = document.getElementById('qr-scan-video');

  if (typeof VeilrScanner === 'undefined' || !VeilrScanner.isScannerSupported()) {
    statusEl.textContent = 'Camera QR scanning isn\u2019t supported in this browser yet. Please type the password manually instead.';
    openModal('modal-qr-scan');
    // Hide the video box visually since there's nothing to show
    videoEl.style.display = 'none';
    return;
  }
  videoEl.style.display = 'block';
  statusEl.textContent = 'Point your camera at their QR code.';
  openModal('modal-qr-scan');

  VeilrScanner.startScan(
    videoEl,
    (text) => {
      // Success
      const field = document.getElementById(_scanTargetFieldId);
      if (field) field.value = text;
      closeScanQR();
      showToast('Password scanned successfully');
    },
    (err) => {
      if (err && err.message === 'UNSUPPORTED') {
        statusEl.textContent = 'Camera QR scanning isn\u2019t supported in this browser. Please type the password manually instead.';
      } else if (err && err.name === 'NotAllowedError') {
        statusEl.textContent = 'Camera access was denied. Allow camera permission to scan, or type the password manually.';
      } else {
        statusEl.textContent = 'Could not access the camera. Please type the password manually.';
      }
      videoEl.style.display = 'none';
    }
  ).then((stopFn) => { _scanStop = stopFn; });
}

function closeScanQR() {
  if (_scanStop) { _scanStop(); _scanStop = null; }
  closeModal('modal-qr-scan');
  document.getElementById('qr-scan-video').style.display = 'block';
}

// ══════════════════════════════════════════════════════
// FILES PANEL — encrypt/decrypt any file with the active contact's
// dual password. Reuses the same contact store as text messages.
// ══════════════════════════════════════════════════════
let selectedFile = null;       // { name, type, size, bytes: Uint8Array }
let fileOutputBytes = null;    // encrypted .enc bytes, ready to download/share
let fileOutputName = null;     // suggested filename for the encrypted download
let decryptedFileBytes = null; // result of a successful decrypt, ready to download
let decryptedFileName = null;
let decryptedFileMime = null;

function renderFilesPanel() {
  const contacts = getContacts();
  const select = document.getElementById('file-contact');
  const noContactHint = document.getElementById('file-no-contact-hint');

  select.textContent = ''; // clear safely

  if (contacts.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '— no contacts yet —';
    select.appendChild(opt);
    select.disabled = true;
    noContactHint.style.display = 'block';
    document.getElementById('file-dropzone').style.pointerEvents = 'none';
    document.getElementById('file-dropzone').style.opacity = '0.5';
    return;
  }

  select.disabled = false;
  noContactHint.style.display = 'none';
  document.getElementById('file-dropzone').style.pointerEvents = 'auto';
  document.getElementById('file-dropzone').style.opacity = '1';

  const lastUsed = getLastActive();
  for (const c of contacts) {
    const opt = document.createElement('option');
    opt.value = c.id;          // assigning .value never parses content as markup
    opt.textContent = c.name;  // assigning .textContent never parses content as markup
    if (c.id === lastUsed) opt.selected = true;
    select.appendChild(opt);
  }
}

function onFileContactChange() {
  clearFileMessages();
}

function activeFileContact() {
  const id = document.getElementById('file-contact').value;
  return getContacts().find(c => c.id === id) || null;
}

function onDragOver(e) {
  e.preventDefault();
  document.getElementById('file-dropzone').classList.add('drag-over');
}
function onDragLeave(e) {
  e.preventDefault();
  document.getElementById('file-dropzone').classList.remove('drag-over');
}
function onDrop(e) {
  e.preventDefault();
  document.getElementById('file-dropzone').classList.remove('drag-over');
  const file = e.dataTransfer.files && e.dataTransfer.files[0];
  if (file) handleFileSelected(file);
}
function onFilePicked(e) {
  const file = e.target.files && e.target.files[0];
  if (file) handleFileSelected(file);
  e.target.value = ''; // allow re-picking the same file later
}

async function handleFileSelected(file) {
  clearFileMessages();
  hideFileOutput();

  if (file.size > MAX_FILE_BYTES) {
    showFileAlert('error', `File is too large (${formatBytes(file.size)}). Maximum supported size is ${formatBytes(MAX_FILE_BYTES)}.`);
    return;
  }

  const isEncFile = file.name.toLowerCase().endsWith('.enc');

  try {
    const buf = await file.arrayBuffer();
    selectedFile = {
      name: file.name,
      type: file.type || 'application/octet-stream',
      size: file.size,
      bytes: new Uint8Array(buf),
      isEncFile
    };
  } catch (e) {
    showFileAlert('error', 'Could not read that file: ' + e.message);
    return;
  }

  document.getElementById('file-chip-name').textContent = file.name;
  document.getElementById('file-chip-size').textContent = formatBytes(file.size);
  document.getElementById('file-chip-icon').textContent = pickFileIcon(file.name, file.type);
  document.getElementById('file-selected-info').style.display = 'block';

  const lockBtn = document.getElementById('btn-file-lock');
  const unlockBtn = document.getElementById('btn-file-unlock');
  document.getElementById('file-action-row').style.display = 'flex';

  if (isEncFile) {
    lockBtn.style.display = 'none';
    unlockBtn.style.display = 'flex';
  } else {
    lockBtn.style.display = 'flex';
    unlockBtn.style.display = 'none';
  }
}

function clearSelectedFile() {
  selectedFile = null;
  document.getElementById('file-selected-info').style.display = 'none';
  document.getElementById('file-action-row').style.display = 'none';
  hideFileOutput();
  clearFileMessages();
}

function pickFileIcon(name, type) {
  const lower = name.toLowerCase();
  if (lower.endsWith('.enc')) return '🔐';
  if (type.startsWith('image/')) return '🖼️';
  if (type === 'application/pdf' || lower.endsWith('.pdf')) return '📕';
  if (type.startsWith('video/')) return '🎬';
  if (type.startsWith('audio/')) return '🎵';
  if (type.startsWith('text/')) return '📝';
  return '📄';
}

function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  return (n/(1024*1024)).toFixed(1) + ' MB';
}

async function doEncryptFile() {
  const c = activeFileContact();
  if (!c) { showFileAlert('error', 'Select a contact first.'); return; }
  if (!selectedFile) { showFileAlert('error', 'Choose a file first.'); return; }

  showFileProgress('Encrypting…', 30);
  try {
    const encrypted = await encryptFileBytes(selectedFile.bytes, selectedFile.name, selectedFile.type, c.pwMine, c.pwTheirs);
    showFileProgress('Encrypting…', 90);

    fileOutputBytes = encrypted;
    fileOutputName = selectedFile.name + '.enc';

    // Base64 text variant, capped — huge files make impractical text blobs,
    // but we still offer it since the size cap (25MB) keeps this reasonable.
    const b64 = FILE_TEXT_PREFIX + b64enc(encrypted.buffer);
    document.getElementById('file-b64-output').value = b64;

    document.getElementById('file-output-label').textContent = 'ENCRYPTED FILE READY';
    document.getElementById('btn-file-download').textContent = '⬇ DOWNLOAD .enc FILE';
    document.getElementById('btn-file-share').style.display = (navigator.share ? 'flex' : 'none');
    showFileOutput();
    hideFileProgress();
    showFileAlert('success', '✓ File encrypted. Download it, copy the text, or share it directly.');
  } catch (e) {
    hideFileProgress();
    showFileAlert('error', 'Encryption failed: ' + e.message);
  }
}

async function doDecryptFile() {
  const c = activeFileContact();
  if (!c) { showFileAlert('error', 'Select a contact first.'); return; }
  if (!selectedFile) { showFileAlert('error', 'Choose a file first.'); return; }

  showFileProgress('Decrypting…', 30);
  try {
    const result = await decryptFileBytes(selectedFile.bytes, c.pwMine, c.pwTheirs);
    showFileProgress('Decrypting…', 90);

    decryptedFileBytes = result.fileBytes;
    decryptedFileName = result.filename;
    decryptedFileMime = result.mimeType;

    document.getElementById('file-output-label').textContent = 'DECRYPTED — READY TO DOWNLOAD';
    document.getElementById('btn-file-download').textContent = '⬇ DOWNLOAD ' + truncateMiddle(result.filename, 28);
    document.getElementById('btn-file-share').style.display = (navigator.share && navigator.canShare ? 'flex' : 'none');
    document.getElementById('file-b64-output').value = '';
    document.querySelector('#file-output .field').style.display = 'none'; // hide base64 box for decrypted output
    showFileOutput();
    hideFileProgress();
    showFileAlert('success', `✓ Decrypted successfully — verified, not tampered.`);
  } catch (e) {
    hideFileProgress();
    if (e.message === 'WRONG_PW') {
      showFileAlert('error', `✗ Can't decrypt — wrong password for "${c.name}", or the file wasn't copied completely.`);
    } else if (e.message === 'NOT_VEILR_FILE') {
      showFileAlert('error', '✗ This doesn\u2019t look like a Veilr-encrypted file.');
    } else {
      showFileAlert('error', '✗ This file looks incomplete or damaged.');
    }
  }
}

function downloadFileOutput() {
  let bytes, name, mime;
  if (decryptedFileBytes) {
    bytes = decryptedFileBytes; name = decryptedFileName; mime = decryptedFileMime;
  } else if (fileOutputBytes) {
    bytes = fileOutputBytes; name = fileOutputName; mime = 'application/octet-stream';
  } else {
    return;
  }
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function shareFileOutput() {
  let bytes, name, mime;
  if (decryptedFileBytes) {
    bytes = decryptedFileBytes; name = decryptedFileName; mime = decryptedFileMime;
  } else if (fileOutputBytes) {
    bytes = fileOutputBytes; name = fileOutputName; mime = 'application/octet-stream';
  } else {
    return;
  }

  if (!navigator.share) { showToast('Sharing isn\u2019t supported on this device'); return; }

  try {
    const file = new File([bytes], name, { type: mime });
    if (navigator.canShare && !navigator.canShare({ files: [file] })) {
      showToast('This file can\u2019t be shared directly — use Download instead');
      return;
    }
    await navigator.share({ files: [file], title: name });
  } catch (e) {
    if (e.name !== 'AbortError') showToast('Could not open the share sheet');
  }
}

function copyFileBase64() {
  const val = document.getElementById('file-b64-output').value;
  if (!val) { showToast('Nothing to copy'); return; }
  safeCopyToClipboard(val).then((ok) => {
    const btn = document.getElementById('copy-file-b64-btn');
    if (ok) {
      btn.textContent = 'COPIED ✓';
      setTimeout(() => { btn.textContent = 'COPY'; }, 1500);
      showToast('Copied to clipboard');
    } else {
      showToast('Copy blocked — select the text manually');
    }
  });
}

function showFileProgress(label, pct) {
  document.getElementById('file-progress-wrap').style.display = 'block';
  document.getElementById('file-progress-label').textContent = label;
  document.getElementById('file-progress-fill').style.width = pct + '%';
}
function hideFileProgress() {
  document.getElementById('file-progress-wrap').style.display = 'none';
  document.getElementById('file-progress-fill').style.width = '0%';
}
function showFileOutput() {
  document.querySelector('#file-output .field').style.display = 'block';
  document.getElementById('file-output').classList.add('show');
}
function hideFileOutput() {
  document.getElementById('file-output').classList.remove('show');
  fileOutputBytes = null; fileOutputName = null;
  decryptedFileBytes = null; decryptedFileName = null; decryptedFileMime = null;
}
function showFileAlert(type, msg) {
  clearFileMessages();
  const el = document.getElementById(type === 'error' ? 'file-err' : 'file-ok');
  el.textContent = msg;
  el.classList.add('show');
}
function clearFileMessages() {
  document.getElementById('file-err').classList.remove('show');
  document.getElementById('file-ok').classList.remove('show');
}
function truncateMiddle(str, max) {
  if (str.length <= max) return str;
  const half = Math.floor((max - 3) / 2);
  return str.slice(0, half) + '...' + str.slice(str.length - half);
}

// ══════════════════════════════════════════════════════
// PWA INSTALL BANNER — shown every visit, per product decision,
// but never shown if the app is already running installed
// (checking that isn't nagging, it's just not showing an install
// prompt for an app you're already using as an app).
// ══════════════════════════════════════════════════════
let _deferredInstallPrompt = null;

function isRunningInstalled() {
  return window.matchMedia('(display-mode: standalone)').matches ||
         window.navigator.standalone === true; // iOS Safari home-screen check
}

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  _deferredInstallPrompt = e;
  if (!isRunningInstalled()) {
    showInstallBanner();
  }
});

function showInstallBanner() {
  const banner = document.getElementById('install-banner');
  if (banner) banner.classList.add('show');
}

function dismissInstallBanner() {
  const banner = document.getElementById('install-banner');
  if (banner) banner.classList.remove('show');
  // Intentionally not persisted to storage — shows again next visit,
  // matching the "every time user enters the site" requirement.
}

function doInstall() {
  const banner = document.getElementById('install-banner');
  if (banner) banner.classList.remove('show');
  if (_deferredInstallPrompt) {
    _deferredInstallPrompt.prompt();
    _deferredInstallPrompt.userChoice.then(() => { _deferredInstallPrompt = null; });
  } else if (window.navigator.standalone === undefined && /iPhone|iPad|iPod/.test(navigator.userAgent)) {
    // iOS Safari has no programmatic install prompt — guide the user manually
    showToast('On iPhone: tap Share, then "Add to Home Screen"');
  } else {
    showToast('Install option not available in this browser yet');
  }
}

window.addEventListener('appinstalled', () => {
  const banner = document.getElementById('install-banner');
  if (banner) banner.classList.remove('show');
  _deferredInstallPrompt = null;
});

// ══════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════
document.getElementById('clip-time-val').textContent = (getClipTime()===0?'Off':getClipTime()+'s') + ' ▾';
initSecureStorage(); // loads contacts asynchronously, then calls renderHome() itself
maybeShowBackupReminder();

// Show banner immediately for browsers that support standalone detection
// but don't fire beforeinstallprompt reliably (e.g. iOS Safari) —
// still respects "never show if already installed."
if (!isRunningInstalled() && /iPhone|iPad|iPod/.test(navigator.userAgent)) {
  setTimeout(showInstallBanner, 1200);
}

// Service worker — enables offline support + installability
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(()=>{});
  });
}
