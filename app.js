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
