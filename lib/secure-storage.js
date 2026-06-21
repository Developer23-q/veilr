/*!
 * Veilr Secure Storage
 *
 * SECURITY DESIGN — fix for "passwords stored in plaintext in localStorage":
 *
 * Contact records (which contain both halves of each conversation's
 * password) are now encrypted with AES-256-GCM before being written to
 * localStorage. The AES key used for this is generated once per device
 * with `extractable: false` and persisted in IndexedDB — IndexedDB's
 * structured-clone algorithm has native support for storing CryptoKey
 * objects, including non-extractable ones, per the Web Crypto API spec.
 *
 * What this achieves: a static dump of localStorage (e.g. from a stolen
 * device's storage files, a browser extension with storage-only access,
 * or any code path that ISN'T running inside this page's live JS context)
 * gets ciphertext, not plaintext passwords.
 *
 * What this does NOT achieve, and should not be oversold as achieving:
 * a successful XSS attack running live inside this page can still call
 * the same decrypt function this code calls, because the key — while
 * never exportable as raw bytes — is still usable by any script running
 * on the page. This is a real, meaningful improvement (closes the
 * "static storage dump" attack and the "different extension/script with
 * only storage access" attack) but is not a substitute for fixing XSS at
 * its source, which is handled separately elsewhere in this codebase.
 *
 * VERIFICATION NOTE: the IndexedDB + non-extractable-CryptoKey persistence
 * mechanism this relies on is standard, spec-compliant browser behavior,
 * but could not be executed and verified inside the sandboxed tool
 * environment this code was written in (no real IndexedDB/WebCrypto
 * integration available there). It has been written precisely to the
 * Web Crypto API and IndexedDB specifications. Test this in a real
 * browser (open DevTools → Application → IndexedDB after first load,
 * confirm a 'veilr-keys' database with a stored CryptoKey exists, and
 * confirm contacts still load correctly after a page refresh) before
 * relying on it in production.
 */
(function (global) {
  'use strict';

  const DB_NAME = 'veilr-keystore';
  const DB_VERSION = 1;
  const STORE_NAME = 'keys';
  const KEY_RECORD_ID = 'device-storage-key';

  let _cachedKey = null; // in-memory only for the current page session

  function openDb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(STORE_NAME);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function idbGet(db, key) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  function idbSet(db, key, value) {
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const req = tx.objectStore(STORE_NAME).put(value, key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  /**
   * Get the device's storage-encryption key, creating one if this is the
   * first run. The key is non-extractable: this script (and any other
   * script on the page, including injected ones) can ask it to encrypt
   * or decrypt, but can never read its raw bytes back out via exportKey().
   */
  async function getOrCreateDeviceKey() {
    if (_cachedKey) return _cachedKey;

    if (!('indexedDB' in global)) {
      // No IndexedDB available (very old browser, or a restricted context).
      // Fail closed rather than silently falling back to plaintext.
      throw new Error('INDEXEDDB_UNAVAILABLE');
    }

    const db = await openDb();
    let key = await idbGet(db, KEY_RECORD_ID);

    if (!key) {
      key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false, // extractable: false — this is the entire point
        ['encrypt', 'decrypt']
      );
      await idbSet(db, KEY_RECORD_ID, key);
    }

    _cachedKey = key;
    return key;
  }

  const ENC = new TextEncoder();
  const DEC = new TextDecoder();

  function b64encLocal(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function b64decLocal(str) { return Uint8Array.from(atob(str), (c) => c.charCodeAt(0)); }

  /**
   * Encrypt a JS value (will be JSON-stringified) for storage.
   * Returns a string safe to put directly into localStorage.
   */
  async function encryptForStorage(value) {
    const key = await getOrCreateDeviceKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = ENC.encode(JSON.stringify(value));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    const packed = new Uint8Array(iv.length + ct.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ct), iv.length);
    return 'VEILRSTORE1:' + b64encLocal(packed.buffer);
  }

  /**
   * Decrypt a value previously produced by encryptForStorage().
   * Returns the original JS value, or `fallback` if decryption fails
   * (e.g. first run with no existing data, or corrupted/foreign data).
   */
  async function decryptFromStorage(stored, fallback) {
    if (typeof stored !== 'string' || !stored.startsWith('VEILRSTORE1:')) {
      return fallback;
    }
    try {
      const key = await getOrCreateDeviceKey();
      const packed = b64decLocal(stored.slice('VEILRSTORE1:'.length));
      const iv = packed.slice(0, 12);
      const ct = packed.slice(12);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      return JSON.parse(DEC.decode(plaintext));
    } catch (e) {
      return fallback;
    }
  }

  global.VeilrSecureStorage = { encryptForStorage, decryptFromStorage };
})(typeof window !== 'undefined' ? window : globalThis);
