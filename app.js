/* ===================================================================
   Card Vault — 100% local. No network calls anywhere in this file.
   Data model:
     meta store (key "config"): { salt, pinWrappedKey, pinWrappedIv,
       prfWrappedKey, prfWrappedIv, prfSalt, credentialId, authMode }
     cards store: { id, iv, cipher, photoIv, photoCipher, createdAt }
   The master AES-256 key encrypts every card record's JSON payload.
   It is itself wrapped by a PIN-derived key and, optionally, by a key
   derived from a WebAuthn PRF assertion (Face ID / Touch ID) — either
   one alone can unlock the vault.
=================================================================== */

// ---------- tiny helpers ----------
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

let toastTimer;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 1800);
}

// ---------- IndexedDB ----------
const DB_NAME = "cardvault-db";
let dbPromise = null;
function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta", { keyPath: "id" });
      if (!db.objectStoreNames.contains("cards")) db.createObjectStore("cards", { keyPath: "id", autoIncrement: true });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}
async function idbGet(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const r = tx.objectStore(store).get(key);
    r.onsuccess = () => resolve(r.result || null);
    r.onerror = () => reject(r.error);
  });
}
async function idbPut(store, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    const r = tx.objectStore(store).put(value);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function idbDelete(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    const r = tx.objectStore(store).delete(key);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}
async function idbAll(store) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const r = tx.objectStore(store).getAll();
    r.onsuccess = () => resolve(r.result || []);
    r.onerror = () => reject(r.error);
  });
}

// ---------- Crypto primitives ----------
async function deriveKeyFromPin(pin, saltBuf) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBuf, iterations: 250000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function deriveKeyFromBytes(rawBytes) {
  // Used for PRF output -> HKDF -> AES-GCM key
  const base = await crypto.subtle.importKey("raw", rawBytes, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(16), info: enc.encode("cardvault-prf") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function generateMasterKeyRaw() {
  return randomBytes(32); // 256-bit master key, held only in memory once unlocked
}
async function wrapMasterKey(masterKeyRaw, wrappingKey) {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, masterKeyRaw);
  return { iv: bufToB64(iv), cipher: bufToB64(cipher) };
}
async function unwrapMasterKey(ivB64, cipherB64, wrappingKey) {
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const cipher = b64ToBuf(cipherB64);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, wrappingKey, cipher); // returns ArrayBuffer
}
async function importMasterKey(rawBuf) {
  return crypto.subtle.importKey("raw", rawBuf, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptJSON(obj, key) {
  const iv = randomBytes(12);
  const bytes = enc.encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  return { iv: bufToB64(iv), cipher: bufToB64(cipher) };
}
async function decryptJSON(ivB64, cipherB64, key) {
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const cipher = b64ToBuf(cipherB64);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return JSON.parse(dec.decode(plain));
}
async function encryptString(str, key) {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(str));
  return { iv: bufToB64(iv), cipher: bufToB64(cipher) };
}
async function decryptString(ivB64, cipherB64, key) {
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64ToBuf(cipherB64));
  return dec.decode(plain);
}

// ---------- App state ----------
let sessionKey = null; // CryptoKey, only while unlocked, never persisted
let lockTimer = null;
const AUTO_LOCK_MS = 3 * 60 * 1000;

function scheduleAutoLock() {
  clearTimeout(lockTimer);
  lockTimer = setTimeout(lockVault, AUTO_LOCK_MS);
}
document.addEventListener("visibilitychange", async () => {
  if (document.hidden) {
    // Just drop the in-memory key. Do NOT touch WebAuthn here — a
    // biometric prompt can't run against a backgrounded page anyway, and
    // trying to fire one mid-transition is a likely reason it felt like
    // Face ID needed an extra manual tap.
    sessionKey = null;
    return;
  }
  if (sessionKey) return; // still unlocked, nothing to do
  const meta = await idbGet("meta", "config");
  if (!meta) return; // mid-setup flow, leave it alone
  if (!$("vault-screen").classList.contains("hidden")) showLockScreen();
  offerFaceID(meta);
});

function showScreen(id) {
  document.querySelectorAll(".screen").forEach((s) => s.classList.add("hidden"));
  $(id).classList.remove("hidden");
}

// ---------- PIN keypad component ----------
function buildKeypad(container, { onDigit, onDelete, showCancel, onCancel }) {
  container.innerHTML = "";
  const keys = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "⌫"];
  keys.forEach((k) => {
    const btn = document.createElement("button");
    if (k === "") {
      btn.className = "ghost";
      btn.disabled = true;
    } else if (k === "⌫") {
      btn.textContent = "⌫";
      btn.onclick = onDelete;
    } else {
      btn.textContent = k;
      btn.onclick = () => onDigit(k);
    }
    container.appendChild(btn);
  });
}
function renderDots(container, len, max = 6) {
  container.innerHTML = "";
  for (let i = 0; i < max; i++) {
    const d = document.createElement("div");
    d.className = "dot" + (i < len ? " filled" : "");
    container.appendChild(d);
  }
}

// ---------- Setup flow ----------
let pinBuffer = "";
let firstPin = "";

function startSetupFlow() {
  pinBuffer = "";
  renderDots($("setup-dots"), 0);
  $("setup-error").textContent = "";
  buildKeypad($("setup-keypad"), {
    onDigit: (d) => {
      if (pinBuffer.length >= 6) return;
      pinBuffer += d;
      renderDots($("setup-dots"), pinBuffer.length);
      if (pinBuffer.length >= 4 && pinBuffer.length === 6) finishFirstPin();
    },
    onDelete: () => {
      pinBuffer = pinBuffer.slice(0, -1);
      renderDots($("setup-dots"), pinBuffer.length);
    },
  });
  showScreen("setup-screen");
  // allow 4-digit PIN via a small "done" affordance: commit after short pause too
  $("setup-keypad").addEventListener("click", () => {
    if (pinBuffer.length >= 4) {
      clearTimeout(window.__setupCommitTimer);
      window.__setupCommitTimer = setTimeout(() => {
        if (pinBuffer.length >= 4 && $("setup-screen").classList.contains("hidden") === false) {
          finishFirstPin();
        }
      }, 550);
    }
  });
}
function finishFirstPin() {
  if (pinBuffer.length < 4) return;
  firstPin = pinBuffer;
  pinBuffer = "";
  startConfirmFlow();
}
function startConfirmFlow() {
  renderDots($("confirm-dots"), 0);
  $("confirm-error").textContent = "";
  buildKeypad($("confirm-keypad"), {
    onDigit: (d) => {
      if (pinBuffer.length >= firstPin.length) return;
      pinBuffer += d;
      renderDots($("confirm-dots"), pinBuffer.length);
      if (pinBuffer.length === firstPin.length) checkConfirm();
    },
    onDelete: () => {
      pinBuffer = pinBuffer.slice(0, -1);
      renderDots($("confirm-dots"), pinBuffer.length);
    },
  });
  showScreen("confirm-screen");
}
async function checkConfirm() {
  if (pinBuffer !== firstPin) {
    $("confirm-error").textContent = "兩次輸入不一致,請重新設定";
    $("confirm-dots").classList.add("shake");
    setTimeout(() => $("confirm-dots").classList.remove("shake"), 350);
    pinBuffer = "";
    setTimeout(() => { firstPin = ""; startSetupFlow(); }, 700);
    return;
  }
  await completeSetup(firstPin);
}

async function completeSetup(pin) {
  const salt = randomBytes(16);
  const pinKey = await deriveKeyFromPin(pin, salt);
  const masterKeyRaw = await generateMasterKeyRaw();
  const wrapped = await wrapMasterKey(masterKeyRaw, pinKey);

  await idbPut("meta", {
    id: "config",
    salt: bufToB64(salt),
    pinWrappedKey: wrapped.cipher,
    pinWrappedIv: wrapped.iv,
    prfWrappedKey: null,
    prfWrappedIv: null,
    prfSalt: null,
    credentialId: null,
    authMode: "pin-only",
  });

  sessionKey = await importMasterKey(masterKeyRaw);
  window.__pendingMasterKeyRaw = masterKeyRaw; // kept only until FaceID offer completes, then discarded

  if (window.PublicKeyCredential) {
    showScreen("faceid-offer-screen");
  } else {
    window.__pendingMasterKeyRaw = null;
    enterVault();
  }
}

// ---------- WebAuthn (Face ID / Touch ID) ----------
function randId() {
  return randomBytes(16);
}
async function registerFaceID() {
  const prfSalt = randomBytes(32);
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        rp: { name: "Card Vault" },
        user: { id: randId(), name: "cardvault-user", displayName: "Card Vault" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
        timeout: 60000,
        extensions: { prf: { eval: { first: prfSalt } } },
      },
    });

    const ext = cred.getClientExtensionResults();
    const prfSupported = !!(ext && ext.prf && ext.prf.enabled);

    const meta = await idbGet("meta", "config");
    meta.credentialId = bufToB64(cred.rawId);

    if (prfSupported && ext.prf.results && ext.prf.results.first) {
      // Full passwordless path: PRF output derives a real wrapping key.
      const prfKey = await deriveKeyFromBytes(ext.prf.results.first);
      const wrapped = await wrapMasterKey(window.__pendingMasterKeyRaw, prfKey);
      meta.prfWrappedKey = wrapped.cipher;
      meta.prfWrappedIv = wrapped.iv;
      meta.prfSalt = bufToB64(prfSalt);
      meta.authMode = "prf";
    } else {
      // Fallback: biometric acts as a gate, PIN still does the real key derivation.
      meta.authMode = "gate";
    }
    await idbPut("meta", meta);
    window.__pendingMasterKeyRaw = null;
    toast("Face ID 已啟用");
  } catch (e) {
    toast("Face ID 設定取消或失敗,仍可用 PIN 解鎖");
    window.__pendingMasterKeyRaw = null;
  }
  enterVault();
}

async function tryFaceIDUnlock() {
  const meta = await idbGet("meta", "config");
  if (!meta || !meta.credentialId) return false;
  try {
    const allowCredentials = [{ id: b64ToBuf(meta.credentialId), type: "public-key" }];
    if (meta.authMode === "prf") {
      const prfSalt = new Uint8Array(b64ToBuf(meta.prfSalt));
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: randomBytes(32),
          allowCredentials,
          userVerification: "required",
          timeout: 60000,
          extensions: { prf: { eval: { first: prfSalt } } },
        },
      });
      const ext = assertion.getClientExtensionResults();
      if (!ext.prf || !ext.prf.results || !ext.prf.results.first) throw new Error("prf-missing");
      const prfKey = await deriveKeyFromBytes(ext.prf.results.first);
      const rawMaster = await unwrapMasterKey(meta.prfWrappedIv, meta.prfWrappedKey, prfKey);
      sessionKey = await importMasterKey(rawMaster);
      return true;
    } else {
      // gate mode: biometric success required, then still ask for PIN
      await navigator.credentials.get({
        publicKey: { challenge: randomBytes(32), allowCredentials, userVerification: "required", timeout: 60000 },
      });
      return "gate-passed";
    }
  } catch (e) {
    return false;
  }
}

// ---------- Lock / unlock ----------
async function lockVault() {
  sessionKey = null;
  pinBuffer = "";
  showLockScreen();
  const meta = await idbGet("meta", "config");
  if (meta) offerFaceID(meta);
}
async function showLockScreen() {
  const meta = await idbGet("meta", "config");
  if (!meta) { startSetupFlow(); return; }
  pinBuffer = "";
  renderDots($("lock-dots"), 0);
  $("lock-error").textContent = "";
  $("lock-subtitle").textContent = "輸入 PIN 碼解鎖你的卡片";
  buildKeypad($("lock-keypad"), {
    onDigit: async (d) => {
      pinBuffer += d;
      renderDots($("lock-dots"), pinBuffer.length);
      if (pinBuffer.length >= 4) {
        clearTimeout(window.__lockCommitTimer);
        window.__lockCommitTimer = setTimeout(() => attemptPinUnlock(meta), 400);
      }
    },
    onDelete: () => {
      pinBuffer = pinBuffer.slice(0, -1);
      renderDots($("lock-dots"), pinBuffer.length);
    },
  });
  $("use-faceid-btn").classList.toggle("hidden", !meta.credentialId);
  showScreen("lock-screen");
}

// Runs the biometric prompt without waiting for a tap. Safe to call
// speculatively — it no-ops if there's no enrolled credential, and bails
// out cleanly if the vault got unlocked some other way while it was
// awaiting the prompt.
async function attemptAutoFaceID(meta) {
  if (!meta || !meta.credentialId || sessionKey) return;
  $("lock-subtitle").textContent = "正在使用 Face ID 解鎖…";
  const result = await tryFaceIDUnlock();
  if (sessionKey) return; // unlocked via PIN while this was pending
  if (result === true) { enterVault(); return; }
  if (result === "gate-passed") { $("lock-subtitle").textContent = "生物辨識通過,請輸入 PIN 完成解鎖"; return; }
  $("lock-subtitle").textContent = "輸入 PIN 碼解鎖你的卡片";
}

// iOS/Android both require a real tap before they'll show the biometric
// prompt — a page-load or visibility event alone isn't enough, no matter
// how the JS calls it. This overlay makes literally the first touch
// anywhere on the lock screen count as that tap, so there's no separate
// button to find. It removes itself after firing once so the keypad
// underneath works normally afterwards.
function armFaceIDCatcher(meta) {
  const screen = $("lock-screen");
  const existing = screen.querySelector(".faceid-catcher");
  if (existing) existing.remove();
  if (!meta || !meta.credentialId) return;
  const catcher = document.createElement("div");
  catcher.className = "faceid-catcher";
  catcher.addEventListener("pointerdown", () => {
    catcher.remove();
    attemptAutoFaceID(meta);
  }, { once: true });
  screen.appendChild(catcher);
}
async function offerFaceID(meta) {
  armFaceIDCatcher(meta);
  await attemptAutoFaceID(meta); // fires immediately too, in case the platform allows it without an extra tap
}
async function attemptPinUnlock(meta) {
  try {
    const salt = new Uint8Array(b64ToBuf(meta.salt));
    const pinKey = await deriveKeyFromPin(pinBuffer, salt);
    const rawMaster = await unwrapMasterKey(meta.pinWrappedIv, meta.pinWrappedKey, pinKey);
    sessionKey = await importMasterKey(rawMaster);
    enterVault();
  } catch (e) {
    $("lock-error").textContent = "PIN 碼錯誤";
    $("lock-dots").classList.add("shake");
    setTimeout(() => $("lock-dots").classList.remove("shake"), 350);
    pinBuffer = "";
    renderDots($("lock-dots"), 0);
  }
}

$("use-faceid-btn").addEventListener("click", async () => {
  const meta = await idbGet("meta", "config");
  await attemptAutoFaceID(meta);
});

// ---------- Vault (main list) ----------
function detectBrand(numberDigits) {
  if (/^4/.test(numberDigits)) return { name: "VISA", grad: "linear-gradient(135deg,#1c3a63,#2a5aa0)" };
  if (/^5[1-5]/.test(numberDigits) || /^2(2[2-9]|[3-6]\d|7[01]|720)/.test(numberDigits)) return { name: "Mastercard", grad: "linear-gradient(135deg,#5c1f1f,#a1421f)" };
  if (/^35/.test(numberDigits)) return { name: "JCB", grad: "linear-gradient(135deg,#173d2c,#1f6b45)" };
  if (/^3[47]/.test(numberDigits)) return { name: "AMEX", grad: "linear-gradient(135deg,#33255c,#5b3a99)" };
  if (/^6/.test(numberDigits)) return { name: "Discover/其他", grad: "linear-gradient(135deg,#173a3d,#1f6b6b)" };
  return { name: "卡片", grad: "linear-gradient(135deg,#232838,#171b24)" };
}
function formatNumberFull(digits) {
  return digits.replace(/(.{4})/g, "$1 ").trim();
}

async function enterVault() {
  showScreen("vault-screen");
  scheduleAutoLock();
  await refreshCardList();
}

async function refreshCardList() {
  const cards = await idbAll("cards");
  const list = $("card-list");
  const empty = $("empty-state");
  list.innerHTML = "";
  if (cards.length === 0) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  cards.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  for (const card of cards) {
    let data;
    try { data = await decryptJSON(card.iv, card.cipher, sessionKey); }
    catch (e) { continue; }
    const brand = detectBrand(data.number || "");
    const el = document.createElement("div");
    el.className = "card-thumb";

    if (card.photoCipher) {
      try {
        const photoUrl = await decryptString(card.photoIv, card.photoCipher, sessionKey);
        el.innerHTML = `<img src="${photoUrl}" alt="" />`;
      } catch (e) {
        el.style.background = brand.grad;
        el.innerHTML = `<div class="placeholder"><span class="brand-mark">${brand.name}</span></div>`;
      }
    } else {
      el.style.background = brand.grad;
      el.innerHTML = `<div class="placeholder"><span class="brand-mark">${brand.name}</span></div>`;
    }
    const caption = document.createElement("div");
    caption.className = "caption";
    caption.textContent = data.nickname || "未命名卡片";
    el.appendChild(caption);

    el.onclick = () => openDetail(card.id);
    list.appendChild(el);
  }
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- Detail sheet ----------
let currentDetailId = null;
let clipboardClearTimer = null;

async function openDetail(id) {
  const card = await idbGet("cards", id);
  if (!card) return;
  currentDetailId = id;
  let data;
  try { data = await decryptJSON(card.iv, card.cipher, sessionKey); }
  catch (e) { toast("解密失敗"); return; }
  const brand = detectBrand(data.number || "");

  $("detail-content").innerHTML = `
    <div class="detail-card" style="background:${brand.grad}">
      <div class="nickname">${escapeHtml(data.nickname || "未命名卡片")}</div>
      <div class="bank">${escapeHtml(data.bank || "")} · ${brand.name}</div>
      <div class="numberline mono">
        <span>${formatNumberFull(data.number || "")}</span>
        <button class="copy-btn" id="copy-btn">複製</button>
      </div>
      <div class="detail-row"><span>有效期限</span><span class="mono">${escapeHtml(data.expiry || "—")}</span></div>
      <div class="detail-row"><span>持卡人</span><span>${escapeHtml(data.holder || "—")}</span></div>
    </div>
    ${data.note ? `<div><div class="detail-row"><span>備註</span><span></span></div><div class="note-box">${escapeHtml(data.note)}</div></div>` : ""}
    <div class="copy-hint">複製的卡號會在 20 秒後自動從剪貼簿清除</div>
  `;

  $("copy-btn").onclick = async () => {
    try {
      await navigator.clipboard.writeText((data.number || "").replace(/\s/g, ""));
      toast("卡號已複製");
      clearTimeout(clipboardClearTimer);
      clipboardClearTimer = setTimeout(async () => {
        try {
          const cur = await navigator.clipboard.readText();
          if (cur === (data.number || "").replace(/\s/g, "")) await navigator.clipboard.writeText("");
        } catch (e) { /* clipboard read may be blocked; ignore */ }
      }, 20000);
    } catch (e) { toast("無法存取剪貼簿"); }
  };

  $("detail-edit-btn").onclick = () => { closeDetail(); openForm(card, data); };
  $("detail-delete-btn").onclick = async () => {
    await idbDelete("cards", id);
    closeDetail();
    toast("已刪除");
    refreshCardList();
  };
  $("detail-backdrop").classList.remove("hidden");
}
function closeDetail() {
  $("detail-backdrop").classList.add("hidden");
  currentDetailId = null;
}
$("detail-close-btn").onclick = closeDetail;
$("detail-backdrop").addEventListener("click", (e) => { if (e.target === $("detail-backdrop")) closeDetail(); });

// ---------- Add / edit form ----------
let editingCardId = null;
let pendingPhotoDataUrl = null;

function openForm(existingCard, existingData) {
  editingCardId = existingCard ? existingCard.id : null;
  pendingPhotoDataUrl = null;
  $("form-title").textContent = existingCard ? "編輯卡片" : "新增卡片";
  $("f-nickname").value = existingData?.nickname || "";
  $("f-bank").value = existingData?.bank || "";
  $("f-number").value = existingData?.number ? formatNumberFull(existingData.number) : "";
  $("f-expiry").value = existingData?.expiry || "";
  $("f-holder").value = existingData?.holder || "";
  $("f-note").value = existingData?.note || "";

  const preview = $("photo-preview");
  if (existingCard && existingCard.photoCipher) {
    decryptString(existingCard.photoIv, existingCard.photoCipher, sessionKey).then((url) => {
      pendingPhotoDataUrl = url;
      preview.innerHTML = `<img src="${url}" />`;
    });
  } else {
    preview.innerHTML = "點擊拍攝卡面縮圖(選填)";
  }
  $("form-backdrop").classList.remove("hidden");
}
$("add-card-btn").onclick = () => openForm(null, null);
$("form-cancel-btn").onclick = () => { $("form-backdrop").classList.add("hidden"); editingCardId = null; };
$("form-backdrop").addEventListener("click", (e) => { if (e.target === $("form-backdrop")) { $("form-backdrop").classList.add("hidden"); } });

$("photo-preview").onclick = () => $("photo-input").click();
$("photo-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const dataUrl = await compressImage(file, 420, 0.55);
  pendingPhotoDataUrl = dataUrl;
  $("photo-preview").innerHTML = `<img src="${dataUrl}" />`;
});
function compressImage(file, maxWidth, quality) {
  return new Promise((resolve) => {
    const img = new Image();
    const reader = new FileReader();
    reader.onload = () => { img.src = reader.result; };
    img.onload = () => {
      const scale = Math.min(1, maxWidth / img.width);
      const canvas = document.createElement("canvas");
      canvas.width = img.width * scale;
      canvas.height = img.height * scale;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      resolve(canvas.toDataURL("image/jpeg", quality));
    };
    reader.readAsDataURL(file);
  });
}

$("form-save-btn").onclick = async () => {
  const digits = $("f-number").value.replace(/\D/g, "");
  const payload = {
    nickname: $("f-nickname").value.trim(),
    bank: $("f-bank").value.trim(),
    number: digits,
    expiry: $("f-expiry").value.trim(),
    holder: $("f-holder").value.trim(),
    note: $("f-note").value.trim(),
  };
  if (!payload.nickname || !digits) { toast("至少填寫暱稱與卡號"); return; }

  const { iv, cipher } = await encryptJSON(payload, sessionKey);
  const record = { iv, cipher, createdAt: Date.now() };
  if (editingCardId) record.id = editingCardId;

  if (pendingPhotoDataUrl) {
    const photoEnc = await encryptString(pendingPhotoDataUrl, sessionKey);
    record.photoIv = photoEnc.iv;
    record.photoCipher = photoEnc.cipher;
  } else if (editingCardId) {
    // keep prior photo if editing and user didn't change it
    const prior = await idbGet("cards", editingCardId);
    if (prior) { record.photoIv = prior.photoIv; record.photoCipher = prior.photoCipher; }
  }

  await idbPut("cards", record);
  $("form-backdrop").classList.add("hidden");
  editingCardId = null;
  toast("已儲存");
  refreshCardList();
};

// ---------- wire static screen buttons ----------
$("enable-faceid-btn").onclick = registerFaceID;
$("skip-faceid-btn").onclick = () => { window.__pendingMasterKeyRaw = null; enterVault(); };
$("lock-now-btn").onclick = lockVault;

// re-arm auto-lock on interaction
["click", "touchstart", "keydown"].forEach((ev) => document.addEventListener(ev, () => {
  if (sessionKey) scheduleAutoLock();
}));

// ---------- boot ----------
async function boot() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("sw.js").catch(() => {});
    // A new SW version installs in the background (skipWaiting) and takes
    // over on its own; reload once so the update is actually visible
    // instead of sitting there until the next manual refresh.
    let reloading = false;
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (reloading) return;
      reloading = true;
      window.location.reload();
    });
  }
  const meta = await idbGet("meta", "config");
  if (!meta) {
    startSetupFlow();
    return;
  }
  await showLockScreen();
  if (document.visibilityState === "visible") offerFaceID(meta);
}
boot();
