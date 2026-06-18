// ══════════════════════════════════════════════════════
// CRYPTO ENGINE — AES-256-GCM, dual password
// ══════════════════════════════════════════════════════
const ENC = new TextEncoder();
const DEC = new TextDecoder();
const PREFIX = 'VEILR2:';

async function pbkdf2Key(password, salt) {
  const mat = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:250000, hash:'SHA-256'},
    mat, {name:'AES-GCM', length:256}, true, ['encrypt','decrypt']
  );
}

async function deriveKey(pwA, pwB, salt) {
  const kA = await pbkdf2Key(pwA, salt);
  const kB = await pbkdf2Key(pwB, salt);
  const rawA = new Uint8Array(await crypto.subtle.exportKey('raw', kA));
  const rawB = new Uint8Array(await crypto.subtle.exportKey('raw', kB));
  const combined = new Uint8Array(32);
  for (let i=0;i<32;i++) combined[i] = rawA[i] ^ rawB[i];
  return crypto.subtle.importKey('raw', combined, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
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
// STORAGE
// ══════════════════════════════════════════════════════
function getContacts(){ try{ return JSON.parse(localStorage.getItem('veilr_contacts')||'[]'); }catch{ return []; } }
function setContacts(arr){ localStorage.setItem('veilr_contacts', JSON.stringify(arr)); }
function getLastActive(){ return localStorage.getItem('veilr_last_active'); }
function setLastActive(id){ localStorage.setItem('veilr_last_active', id); }
function getClipTime(){ return parseInt(localStorage.getItem('veilr_clip_time')||'30'); }
function setClipTime(v){ localStorage.setItem('veilr_clip_time', String(v)); }

const APP_LINKS = {
  whatsapp:  {name:'WHATSAPP',  label:'Their phone number',  icon:'💬', build:(t)=>`https://wa.me/${t.replace(/[^0-9+]/g,'')}`},
  telegram:  {name:'TELEGRAM',  label:'Their @username',      icon:'✈️', build:(t)=>`https://t.me/${t.replace('@','')}`},
  sms:       {name:'MESSAGES',  label:'Their phone number',  icon:'💭', build:(t)=>`sms:${t.replace(/[^0-9+]/g,'')}`},
  email:     {name:'EMAIL',     label:'Their email address', icon:'✉️', build:(t)=>`mailto:${t}`},
  messenger: {name:'MESSENGER', label:'Their Messenger username', icon:'🔵', build:(t)=>`https://m.me/${t}`},
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
  document.getElementById('send-app-name').textContent = APP_LINKS[c.app].name;

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
      status.textContent = `✗ Can't decrypt — password mismatch with "${c.name}"`;
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
  const url = APP_LINKS[c.app].build(c.appTarget);

  // window.open must be called synchronously in direct response to the
  // click for browsers to allow it. If it returns null/undefined, the
  // popup was blocked — fall back to a visible link the user can tap themselves.
  const win = window.open(url, '_blank');
  if (!win) {
    showSendFallback(url);
  }
}

function showSendFallback(url) {
  const status = document.getElementById('status-line');
  status.innerHTML = `Couldn't open automatically — <a href="${url}" target="_blank" style="color:var(--blue);text-decoration:underline;">tap here to open</a>`;
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
function renderContactsPanel() {
  const contacts = getContacts();
  const body = document.getElementById('contacts-body');
  if (contacts.length===0) {
    body.innerHTML = `<div class="empty"><div class="empty-icon">👥</div><div class="empty-title">No contacts yet</div><div class="empty-sub">Tap + to add the first person you want to message privately.</div></div>`;
    return;
  }
  body.innerHTML = contacts.map(c => `
    <div class="contact-item" onclick="selectContact('${c.id}')">
      <div class="ci-avatar">${esc(c.name.charAt(0).toUpperCase())}</div>
      <div class="ci-info">
        <div class="ci-name">${esc(c.name)}</div>
        <div class="ci-app">${APP_LINKS[c.app].icon} via ${APP_LINKS[c.app].name}</div>
      </div>
      <div class="ci-actions">
        <button class="ci-btn" onclick="event.stopPropagation();editContact('${c.id}')">✎</button>
        <button class="ci-btn del" onclick="event.stopPropagation();askDelete('${c.id}')">🗑</button>
      </div>
    </div>
  `).join('');
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
  document.getElementById('app-target-label').textContent = APP_LINKS[c.app].label;
  setChecked(true);
  openPanel('panel-add-contact');
}

function pickApp(el) {
  document.querySelectorAll('.app-pick').forEach(e=>e.classList.remove('active'));
  el.classList.add('active');
  selectedApp = el.dataset.app;
  document.getElementById('app-target-label').textContent = APP_LINKS[selectedApp].label;
}

function genPassword() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*';
  const arr = crypto.getRandomValues(new Uint8Array(30));
  const pw = Array.from(arr, b => chars[b % chars.length]).join('');
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

function importContacts(evt) {
  const file = evt.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      if (Array.isArray(data.contacts)) {
        setContacts(data.contacts);
        renderContactsPanel();
        renderHome();
        showToast('Contacts imported');
      }
    } catch(e) { showToast('Invalid backup file'); }
  };
  reader.readAsText(file);
  evt.target.value = '';
}

function confirmDeleteAll() { openModal('modal-wipe'); }
function executeWipeAll() {
  localStorage.clear();
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
  if (id==='panel-contacts') { renderContactsPanel(); setActiveNav(1); }
  if (id==='panel-info') setActiveNav(2);
  if (id==='panel-settings') setActiveNav(3);
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
// INIT
// ══════════════════════════════════════════════════════
document.getElementById('clip-time-val').textContent = (getClipTime()===0?'Off':getClipTime()+'s') + ' ▾';
renderHome();
maybeShowBackupReminder();

// Service worker — enables offline support + installability
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(()=>{});
  });
}
