/* ===================================================================
   Card Vault — 100% local. No network calls anywhere in this file.

   TEMPORARY: PIN entry and Face ID are stripped out for now while the
   vault UI is being polished — see ensureAutoKey() below. The card
   encryption itself is untouched (AES-256-GCM, per-card random IV);
   only the "how do we get the key" step is currently a stub.

   Data model:
     meta store (key "config"): { autoKey }
     cards store: { id, iv, cipher, photoIv, photoCipher, createdAt }
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
async function idbClear(store) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    const r = tx.objectStore(store).clear();
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}

// ---------- Crypto primitives ----------
async function generateMasterKeyRaw() {
  return randomBytes(32); // 256-bit master key, held only in memory once loaded
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
// TEMPORARY: PIN entry and Face ID are disabled while the vault UI is
// being iterated on. Cards are still encrypted at rest (AES-256-GCM) —
// the difference is the key is auto-provisioned on first run instead of
// being derived from a PIN/biometric, so there's currently no real access
// control in front of it. Re-introduce the PIN/Face ID flow before this
// goes anywhere someone other than you can get physical access to.
let sessionKey = null; // CryptoKey, held only in memory for this page session

function showScreen(id) {
  document.querySelectorAll(".screen").forEach((s) => s.classList.add("hidden"));
  $(id).classList.remove("hidden");
}

async function ensureAutoKey() {
  let meta = await idbGet("meta", "config");
  if (!meta || !meta.autoKey) {
    const masterKeyRaw = await generateMasterKeyRaw();
    meta = { id: "config", autoKey: bufToB64(masterKeyRaw) };
    await idbPut("meta", meta);
  }
  sessionKey = await importMasterKey(b64ToBuf(meta.autoKey));
}

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
    const el = document.createElement("div");
    el.className = "card-thumb";

    if (card.photoCipher) {
      try {
        const photoUrl = await decryptString(card.photoIv, card.photoCipher, sessionKey);
        el.innerHTML = `<img src="${photoUrl}" alt="" />`;
      } catch (e) {
        el.classList.add("no-photo");
        el.innerHTML = `<div class="placeholder"><span class="name-mark">${escapeHtml(data.nickname || "未命名卡片")}</span></div>`;
      }
    } else {
      el.classList.add("no-photo");
      el.innerHTML = `<div class="placeholder"><span class="name-mark">${escapeHtml(data.nickname || "未命名卡片")}</span></div>`;
    }

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
let deleteConfirmTimer = null;

async function openDetail(id) {
  const card = await idbGet("cards", id);
  if (!card) return;
  currentDetailId = id;
  let data;
  try { data = await decryptJSON(card.iv, card.cipher, sessionKey); }
  catch (e) { toast("解密失敗"); return; }
  const brand = detectBrand(data.number || "");

  $("detail-content").innerHTML = `
    <div class="detail-card">
      <div class="nickname">${escapeHtml(data.nickname || "未命名卡片")}</div>
      <div class="bank">${brand.name}</div>
      <div class="numberline mono">
        <span>${formatNumberFull(data.number || "")}</span>
        <button class="copy-btn" id="copy-btn" aria-label="複製卡號">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="8" y="8" width="12" height="12" rx="2"/>
            <path d="M5 15.5A2 2 0 0 1 4 14V6a2 2 0 0 1 2-2h8a2 2 0 0 1 1.7.9"/>
          </svg>
        </button>
      </div>
      <div class="detail-row"><span>有效期限</span><span class="mono">${escapeHtml(data.expiry || "—")}</span></div>
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
  const deleteBtn = $("detail-delete-btn");
  deleteBtn.textContent = "刪除";
  deleteBtn.classList.remove("confirming");
  clearTimeout(deleteConfirmTimer);
  deleteBtn.onclick = async () => {
    if (!deleteBtn.classList.contains("confirming")) {
      deleteBtn.classList.add("confirming");
      deleteBtn.textContent = "再按一次確認刪除";
      clearTimeout(deleteConfirmTimer);
      deleteConfirmTimer = setTimeout(() => {
        deleteBtn.classList.remove("confirming");
        deleteBtn.textContent = "刪除";
      }, 3000);
      return;
    }
    clearTimeout(deleteConfirmTimer);
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
  clearTimeout(deleteConfirmTimer);
  $("detail-delete-btn").classList.remove("confirming");
  $("detail-delete-btn").textContent = "刪除";
}
$("detail-backdrop").addEventListener("click", (e) => { if (e.target === $("detail-backdrop")) closeDetail(); });

// ---------- Add / edit form ----------
let editingCardId = null;
let pendingPhotoDataUrl = null;

function openForm(existingCard, existingData) {
  editingCardId = existingCard ? existingCard.id : null;
  pendingPhotoDataUrl = null;
  $("form-title").textContent = existingCard ? "編輯卡片" : "新增卡片";
  $("f-nickname").value = existingData?.nickname || "";
  $("f-number").value = existingData?.number ? formatNumberFull(existingData.number) : "";
  $("f-expiry").value = existingData?.expiry || "";
  $("f-note").value = existingData?.note || "";
  $("f-number-error").textContent = "";
  $("f-number").classList.remove("invalid");
  $("f-expiry-error").textContent = "";
  $("f-expiry").classList.remove("invalid");

  const preview = $("photo-preview");
  if (existingCard && existingCard.photoCipher) {
    decryptString(existingCard.photoIv, existingCard.photoCipher, sessionKey).then((url) => {
      pendingPhotoDataUrl = url;
      preview.innerHTML = `<img src="${url}" />`;
    });
  } else {
    preview.innerHTML = "尚未選擇卡面縮圖(選填)";
  }
  $("form-backdrop").classList.remove("hidden");
}
$("add-card-btn").onclick = () => openForm(null, null);
$("form-cancel-btn").onclick = () => { $("form-backdrop").classList.add("hidden"); editingCardId = null; };
$("form-backdrop").addEventListener("click", (e) => { if (e.target === $("form-backdrop")) { $("form-backdrop").classList.add("hidden"); } });

$("photo-preview").onclick = () => $("photo-input").click();
async function handlePhotoFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  const dataUrl = await compressImage(file, 420, 0.55);
  pendingPhotoDataUrl = dataUrl;
  $("photo-preview").innerHTML = `<img src="${dataUrl}" />`;
}
$("photo-input").addEventListener("change", handlePhotoFile);

function cardNumberError(digits) {
  if (digits.length === 0) return "";
  if (digits.length < 16) return `還差 ${16 - digits.length} 碼,卡號需要完整 16 碼`;
  return "";
}
$("f-number").addEventListener("input", (e) => {
  const digits = e.target.value.replace(/\D/g, "").slice(0, 16);
  e.target.value = digits.replace(/(.{4})/g, "$1 ").trim();
  $("f-number").classList.remove("invalid");
  $("f-number-error").textContent = "";
});
$("f-number").addEventListener("blur", (e) => {
  const digits = e.target.value.replace(/\D/g, "");
  const msg = cardNumberError(digits);
  $("f-number-error").textContent = msg;
  $("f-number").classList.toggle("invalid", !!msg);
});

// Full expiry plausibility, not just "is this a real month": a card
// that already expired years ago or one dated decades out isn't a typo
// worth silently accepting.
function expiryError(value) {
  if (!value) return "";
  const m = value.match(/^(\d{2})\/(\d{2})$/);
  if (!m) return "請輸入完整的 MM/YY";
  const mm = parseInt(m[1], 10);
  if (mm < 1 || mm > 12) return "月份不正確";
  const fullYear = 2000 + parseInt(m[2], 10);
  const now = new Date();
  const currentYear = now.getFullYear();
  const currentMonth = now.getMonth() + 1;
  if (fullYear < currentYear || (fullYear === currentYear && mm < currentMonth)) return "這組日期已經過期";
  if (fullYear > currentYear + 15) return "年份看起來不太合理";
  return "";
}
$("f-expiry").addEventListener("input", (e) => {
  let digits = e.target.value.replace(/\D/g, "").slice(0, 4);
  if (digits.length >= 1) {
    // Clamp the month as it's typed: 00->01, anything above 12 caps at 12.
    let mm = digits.slice(0, 2);
    if (mm.length === 2) {
      let n = parseInt(mm, 10);
      if (n === 0) n = 1;
      if (n > 12) n = 12;
      mm = String(n).padStart(2, "0");
      digits = mm + digits.slice(2);
    }
  }
  if (digits.length >= 3) digits = digits.slice(0, 2) + "/" + digits.slice(2);
  e.target.value = digits;
  if (digits.length < 5) {
    $("f-expiry").classList.remove("invalid");
    $("f-expiry-error").textContent = "";
  }
});
$("f-expiry").addEventListener("blur", (e) => {
  const msg = expiryError(e.target.value.trim());
  $("f-expiry-error").textContent = msg;
  $("f-expiry").classList.toggle("invalid", !!msg);
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
  const expiry = $("f-expiry").value.trim();

  const numMsg = digits.length === 0 ? "請輸入卡號" : cardNumberError(digits);
  $("f-number-error").textContent = numMsg;
  $("f-number").classList.toggle("invalid", !!numMsg);

  const expMsg = expiryError(expiry);
  $("f-expiry-error").textContent = expMsg;
  $("f-expiry").classList.toggle("invalid", !!expMsg);

  if (!$("f-nickname").value.trim()) { toast("請輸入卡片暱稱"); return; }
  if (numMsg || expMsg) { toast("請確認標紅的欄位"); return; }

  const payload = {
    nickname: $("f-nickname").value.trim(),
    number: digits,
    expiry,
    note: $("f-note").value.trim(),
  };

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

// ---------- Backup / restore ----------
// The whole backup payload (meta + cards) is encrypted with a key derived
// from a password the user sets at export time (PBKDF2-SHA256 -> AES-256-GCM).
// Nothing in the exported file can be decrypted without that password —
// unlike the app's own in-memory key, this is a real secret the user holds,
// so losing the password means losing the backup, on purpose.
const BACKUP_FORMAT_VERSION = 2;
const PBKDF2_ITERATIONS = 600000; // OWASP-recommended floor for PBKDF2-SHA256 as of 2023+

async function deriveKeyFromPassword(password, saltBytes, iterations) {
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function exportDataEncrypted(password) {
  try {
    const meta = await idbGet("meta", "config");
    const cards = await idbAll("cards");
    const inner = JSON.stringify({ meta, cards });

    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveKeyFromPassword(password, salt, PBKDF2_ITERATIONS);
    const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(inner));

    const payload = {
      format: "jaxcards-backup",
      version: BACKUP_FORMAT_VERSION,
      exportedAt: new Date().toISOString(),
      kdf: { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS, salt: bufToB64(salt) },
      iv: bufToB64(iv),
      cipher: bufToB64(cipherBuf),
      cardCount: cards.length, // shown before decrypting, so the confirm dialog can mention it
    };
    const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `jaxcards-backup-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast("已匯出");
    return true;
  } catch (e) {
    toast("匯出失敗");
    return false;
  }
}

let pendingImportFile = null;

async function importDataEncrypted(file, password) {
  let payload;
  try {
    const text = await file.text();
    payload = JSON.parse(text);
  } catch (e) {
    toast("檔案格式無法讀取");
    return false;
  }
  if (!payload || payload.format !== "jaxcards-backup" || payload.version !== BACKUP_FORMAT_VERSION || !payload.kdf || !payload.cipher) {
    toast("這不是有效的 JaxCards 備份檔");
    return false;
  }

  let inner;
  try {
    const salt = new Uint8Array(b64ToBuf(payload.kdf.salt));
    const iv = new Uint8Array(b64ToBuf(payload.iv));
    const key = await deriveKeyFromPassword(password, salt, payload.kdf.iterations || PBKDF2_ITERATIONS);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64ToBuf(payload.cipher));
    inner = JSON.parse(dec.decode(plainBuf));
  } catch (e) {
    // AES-GCM auth failure (wrong password) and JSON parse errors both land here
    $("import-pw-error").textContent = "密碼錯誤,或檔案已損壞";
    return false;
  }

  const ok = window.confirm(`確定要匯入這份備份嗎?\n\n這會覆蓋目前手機上所有的卡片資料(共 ${inner.cards.length} 張),此動作無法復原。`);
  if (!ok) return false;

  try {
    await idbClear("cards");
    await idbPut("meta", inner.meta);
    for (const card of inner.cards) {
      await idbPut("cards", card);
    }
    await ensureAutoKey();
    await refreshCardList();
    toast(`已匯入 ${inner.cards.length} 張卡片`);
    return true;
  } catch (e) {
    toast("匯入失敗");
    return false;
  }
}

function showBackupStep(step) {
  $("backup-main").classList.toggle("hidden", step !== "main");
  $("backup-export-step").classList.toggle("hidden", step !== "export");
  $("backup-import-step").classList.toggle("hidden", step !== "import");
}
function closeBackupSheet() {
  $("backup-backdrop").classList.add("hidden");
  showBackupStep("main");
  $("export-pw").value = ""; $("export-pw-confirm").value = ""; $("export-pw-error").textContent = "";
  $("import-pw").value = ""; $("import-pw-error").textContent = "";
  pendingImportFile = null;
}

$("backup-btn").onclick = () => { $("backup-backdrop").classList.remove("hidden"); showBackupStep("main"); };
$("backup-close-btn").onclick = closeBackupSheet;
$("backup-backdrop").addEventListener("click", (e) => { if (e.target === $("backup-backdrop")) closeBackupSheet(); });

$("export-btn").onclick = () => showBackupStep("export");
$("export-pw-cancel").onclick = () => showBackupStep("main");
$("export-pw-confirm-btn").onclick = async () => {
  const pw = $("export-pw").value;
  const pw2 = $("export-pw-confirm").value;
  if (pw.length < 6) { $("export-pw-error").textContent = "密碼至少要 6 碼"; return; }
  if (pw !== pw2) { $("export-pw-error").textContent = "兩次輸入的密碼不一致"; return; }
  $("export-pw-error").textContent = "";
  const success = await exportDataEncrypted(pw);
  if (success) closeBackupSheet();
};

$("import-btn").onclick = () => $("import-input").click();
$("import-input").addEventListener("change", (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  pendingImportFile = file;
  $("import-pw-error").textContent = "";
  showBackupStep("import");
});
$("import-pw-cancel").onclick = () => { pendingImportFile = null; showBackupStep("main"); };
$("import-pw-confirm-btn").onclick = async () => {
  if (!pendingImportFile) return;
  const pw = $("import-pw").value;
  if (!pw) { $("import-pw-error").textContent = "請輸入密碼"; return; }
  const success = await importDataEncrypted(pendingImportFile, pw);
  if (success) closeBackupSheet();
};

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
  await ensureAutoKey();
  await enterVault();
}
boot();
