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
function formatNumberFull(digits) {
  return digits.replace(/(.{4})/g, "$1 ").trim();
}
// Shifts every digit by `offset` (mod 10, wraps both directions:
// 0-1 -> 9, 9+1 -> 0) — used to display a decoy CVV that isn't the real
// one, with the real offset hidden in the hint line below it.
function shiftDigits(digits, offset) {
  return digits.split("").map((d) => String(((parseInt(d, 10) + offset) % 10 + 10) % 10)).join("");
}

async function enterVault() {
  showScreen("vault-screen");
  await refreshCardList();
  if (typeof refreshLayout === "function") requestAnimationFrame(refreshLayout);
}

async function refreshCardList() {
  const cards = await idbAll("cards");
  const stack = $("card-stack");
  const empty = $("empty-state");
  stack.innerHTML = "";
  if (cards.length === 0) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  cards.sort((a, b) => {
    if (a.order != null && b.order != null) return a.order - b.order;
    if (a.order != null) return -1;
    if (b.order != null) return 1;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });
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
    stack.appendChild(el);
  }
}

// ---------- JaxMoney's shell mechanism, ported verbatim ----------
// screen.height/width (paired with orientation.type) are static device
// metrics that don't suffer from window.innerHeight/visualViewport.height
// sometimes getting durably stuck on a wrong value during iOS cold-start/
// rotation/resume — this is the same fix already proven on-device in
// JaxMoney, applied the same way: size #app (the canvas-wrap) off this
// trusted number instead of CSS dvh, then scale #app-canvas to fit.
function trustedViewportHeight() {
  const s = window.screen;
  const o = s && s.orientation;
  if (s && o && typeof o.type === "string") {
    const isPortrait = o.type.indexOf("portrait") === 0;
    const h = isPortrait ? s.height : s.width;
    if (h) return h;
  }
  return window.innerHeight;
}

function setViewportHeight() {
  const app = $("app");
  const header = $("boardHeader");
  if (!header) return;
  const headerHeight = header.offsetHeight;
  document.documentElement.style.setProperty("--header-height", headerHeight + "px");
  if (app) {
    app.style.top = headerHeight + "px";
    app.style.bottom = "auto";
    app.style.height = Math.max(0, trustedViewportHeight() - headerHeight) + "px";
  }
}

function resetScrollPosition() { window.scrollTo(0, 0); }

// #app-canvas no longer scales — JaxMoney's uniform transform:scale()
// shrinks width along with height (that's what was making the whole
// column look too narrow, letterboxed on the sides). Since #app itself
// is already correctly sized via trustedViewportHeight (real fix for the
// underlying dvh bug), #card-list can just be sized directly to fill
// exactly the remaining space below the icon row — full width always,
// no side-effect on horizontal size.
function sizeCardList() {
  const app = $("app");
  const iconRow = $("icon-row");
  const list = $("card-list");
  if (!app || !iconRow || !list) return;
  const appRect = app.getBoundingClientRect();
  const rowRect = iconRow.getBoundingClientRect();
  const h = appRect.bottom - rowRect.bottom - 22; // 22 = .screen's own bottom padding
  list.style.height = Math.max(0, h) + "px";
}

function refreshLayout() {
  setViewportHeight();
  resetScrollPosition();
  requestAnimationFrame(sizeCardList);
}

// The quiet-period stabilization below only guards against iOS's transient
// window-height glitch on launch/resume/rotation. It can't know when
// slow-loading content (e.g. cards still being decrypted one by one)
// finishes changing the icon row's/list's layout. A ResizeObserver catches
// that case directly, whenever it actually happens, regardless of how long
// the load took.
function setupCanvasResizeObserver() {
  if (typeof ResizeObserver === "undefined") return;
  const canvas = $("app-canvas");
  const app = $("app");
  if (!canvas || !app) return;
  const observer = new ResizeObserver(() => {
    requestAnimationFrame(sizeCardList);
  });
  observer.observe(canvas);
  observer.observe(app);
}

let stabilizeTimer = null;
let stabilizeAttempts = 0;
const QUIET_MS = 180, STABLE_CHECK_MS = 120, MAX_STABILIZE_ATTEMPTS = 8;

function viewportKey() {
  const app = $("app");
  const header = $("boardHeader");
  const headerHeight = header ? header.offsetHeight : 0;
  if (!app) return window.innerWidth + "x" + window.innerHeight + "x" + headerHeight;
  return app.clientWidth + "x" + app.clientHeight + "x" + headerHeight;
}
function scheduleStableRefresh() {
  if (stabilizeTimer) clearTimeout(stabilizeTimer);
  stabilizeAttempts = 0;
  stabilizeTimer = setTimeout(checkStable, QUIET_MS);
}
function checkStable() {
  const before = viewportKey();
  stabilizeTimer = setTimeout(() => {
    const after = viewportKey();
    stabilizeAttempts++;
    if (after === before || stabilizeAttempts >= MAX_STABILIZE_ATTEMPTS) {
      refreshLayout();
    } else {
      stabilizeTimer = setTimeout(checkStable, STABLE_CHECK_MS);
    }
  }, STABLE_CHECK_MS);
}
function delayedRefreshLayout() {
  refreshLayout();
  scheduleStableRefresh();
}

window.addEventListener("load", delayedRefreshLayout);
window.addEventListener("resize", scheduleStableRefresh);
if (window.visualViewport) {
  window.visualViewport.addEventListener("resize", scheduleStableRefresh);
  window.visualViewport.addEventListener("scroll", scheduleStableRefresh);
}
window.addEventListener("orientationchange", delayedRefreshLayout);
window.addEventListener("pageshow", delayedRefreshLayout);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") delayedRefreshLayout();
});
delayedRefreshLayout();
setupCanvasResizeObserver();
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- Reorder screen ----------
// A simple vertical drag-to-reorder list. Only the handle icon on each row
// is a drag target (touch-action:none there only), so the list still
// scrolls normally when there are more cards than fit on screen. The DOM
// order IS the source of truth while dragging — "完成" just reads back
// each row's data-id in its final DOM position and writes an explicit
// numeric `order` to every card.
let reorderDragEl = null, reorderStartY = 0, reorderRowH = 0;

async function openReorderScreen() {
  const cards = await idbAll("cards");
  cards.sort((a, b) => {
    if (a.order != null && b.order != null) return a.order - b.order;
    if (a.order != null) return -1;
    if (b.order != null) return 1;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });
  const list = $("reorder-list");
  list.innerHTML = "";
  for (const card of cards) {
    let data;
    try { data = await decryptJSON(card.iv, card.cipher, sessionKey); }
    catch (e) { continue; }
    const row = document.createElement("div");
    row.className = "reorder-row";
    row.dataset.id = card.id;
    let thumbInner = `<span style="font-size:10px;text-align:center;padding:2px;">${escapeHtml((data.nickname || "").slice(0, 6))}</span>`;
    if (card.photoCipher) {
      try {
        const photoUrl = await decryptString(card.photoIv, card.photoCipher, sessionKey);
        thumbInner = `<img src="${photoUrl}" alt="" />`;
      } catch (e) { /* fall back to the nickname chip above */ }
    }
    row.innerHTML = `
      <div class="reorder-thumb">${thumbInner}</div>
      <div class="reorder-name">${escapeHtml(data.nickname || "未命名卡片")}</div>
      <div class="drag-handle" aria-label="拖曳排序">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="4" y1="8" x2="20" y2="8"/><line x1="4" y1="16" x2="20" y2="16"/>
        </svg>
      </div>`;
    list.appendChild(row);
  }
  $("reorder-backdrop").classList.remove("hidden");
}

function reorderPointerDown(e) {
  const row = e.target.closest(".reorder-row");
  if (!row) return;
  e.target.setPointerCapture(e.pointerId);
  reorderDragEl = row;
  reorderStartY = e.clientY;
  reorderRowH = row.offsetHeight + 8; // + row's margin-bottom
  row.classList.add("dragging");
}
function reorderPointerMove(e) {
  if (!reorderDragEl) return;
  const list = $("reorder-list");
  let dy = e.clientY - reorderStartY;
  let rows = [...list.children];
  let idx = rows.indexOf(reorderDragEl);
  while (dy < -reorderRowH / 2 && idx > 0) {
    list.insertBefore(reorderDragEl, rows[idx - 1]);
    reorderStartY -= reorderRowH;
    dy = e.clientY - reorderStartY;
    rows = [...list.children];
    idx = rows.indexOf(reorderDragEl);
  }
  while (dy > reorderRowH / 2 && idx < rows.length - 1) {
    list.insertBefore(rows[idx + 1], reorderDragEl);
    reorderStartY += reorderRowH;
    dy = e.clientY - reorderStartY;
    rows = [...list.children];
    idx = rows.indexOf(reorderDragEl);
  }
  reorderDragEl.style.transform = `translateY(${dy}px)`;
}
function reorderPointerEnd() {
  if (!reorderDragEl) return;
  reorderDragEl.style.transform = "";
  reorderDragEl.classList.remove("dragging");
  reorderDragEl = null;
}
$("reorder-list").addEventListener("pointerdown", (e) => {
  if (e.target.closest(".drag-handle")) reorderPointerDown(e);
});
$("reorder-list").addEventListener("pointermove", reorderPointerMove);
$("reorder-list").addEventListener("pointerup", reorderPointerEnd);
$("reorder-list").addEventListener("pointercancel", reorderPointerEnd);

$("reorder-btn").onclick = openReorderScreen;
$("reorder-cancel-btn").onclick = () => $("reorder-backdrop").classList.add("hidden");
$("reorder-done-btn").onclick = async () => {
  const rows = [...$("reorder-list").children];
  for (let i = 0; i < rows.length; i++) {
    const id = Number(rows[i].dataset.id);
    const card = await idbGet("cards", id);
    if (card) { card.order = i; await idbPut("cards", card); }
  }
  $("reorder-backdrop").classList.add("hidden");
  await refreshCardList();
};

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

  // Dot placement signals the DECODE operation, not the raw offset sign:
  // offset > 0 means displayed = real + offset, so getting back to the
  // real CVV means subtracting — that's what the leading dot means.
  // offset < 0 means displayed = real - |offset|, so decoding means
  // adding — trailing dot. Dot count = magnitude (1 or 2).
  const baseHint = "複製的卡號會在 20 秒後自動從剪貼簿清除";
  let cvvRowHtml = "";
  let hintHtml = escapeHtml(baseHint);
  if (data.cvv) {
    const offset = [-1, 1][Math.floor(Math.random() * 2)];
    const decoyCvv = shiftDigits(data.cvv, offset);
    const dots = ".".repeat(Math.abs(offset));
    hintHtml = offset > 0 ? `${dots}${escapeHtml(baseHint)}` : `${escapeHtml(baseHint)}${dots}`;
    cvvRowHtml = `<div class="detail-row"><span>CVV</span><span class="mono">${escapeHtml(decoyCvv)}</span></div>`;
  }

  $("detail-content").innerHTML = `
    <div class="detail-card">
      <div class="nickname">${escapeHtml(data.nickname || "未命名卡片")}</div>
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
      ${cvvRowHtml}
    </div>
    ${data.note ? `<div><div class="detail-row"><span>備註</span><span></span></div><div class="note-box">${escapeHtml(data.note)}</div></div>` : ""}
    <div class="copy-hint">${hintHtml}</div>
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
  $("f-cvv").value = existingData?.cvv || "";
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
  e.target.value = ""; // allow re-picking the same file later
  if (!file) return;
  openCropScreen(file);
}
$("photo-input").addEventListener("change", handlePhotoFile);

// ---------- Photo crop screen ----------
// A minimal drag-to-pan / pinch-to-zoom cropper: the crop window itself is
// fixed size (matches the card thumbnail's 1.586:1 aspect ratio) — the user
// moves and scales the photo underneath it rather than resizing a box. This
// mirrors how most phone photo pickers already work and is much simpler to
// get right on touch than a resizable crop rectangle.
//
// IMPORTANT: a raw phone camera photo can be 4000x3000px+ (several MB
// decoded). Continuously CSS-transforming (pan/zoom) a DOM <img> at that
// full resolution on every touch-move is what was freezing/crashing the
// page. So before anything touches the DOM, the photo is decoded once and
// redrawn onto an offscreen "working" canvas capped at 1400px on its long
// side — plenty for a 640px final output — and everything below (display,
// pan/zoom, final crop) operates on that much lighter canvas instead.
let cropSourceCanvas = null;
let cropImgW = 0, cropImgH = 0;
let cropScale = 1, cropMinScale = 1, cropTX = 0, cropTY = 0;
let cropVW = 0, cropVH = 0;
const cropPointers = new Map();
let cropPinchStartDist = 0, cropPinchStartScale = 1;
let cropPanStart = null;

async function loadDownscaledCanvas(file, maxDim) {
  let source, w, h;
  if (window.createImageBitmap) {
    try {
      const bitmap = await createImageBitmap(file);
      source = bitmap; w = bitmap.width; h = bitmap.height;
    } catch (e) { /* fall through to the <img>-based path below */ }
  }
  if (!source) {
    source = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = reject;
        img.src = reader.result;
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
    w = source.naturalWidth; h = source.naturalHeight;
  }
  const scale = Math.min(1, maxDim / Math.max(w, h));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(w * scale));
  canvas.height = Math.max(1, Math.round(h * scale));
  canvas.getContext("2d").drawImage(source, 0, 0, canvas.width, canvas.height);
  if (source.close) source.close(); // release the ImageBitmap's decoded memory
  return canvas;
}

function cropClamp() {
  const dispW = cropImgW * cropScale;
  const dispH = cropImgH * cropScale;
  cropTX = Math.min(0, Math.max(cropVW - dispW, cropTX));
  cropTY = Math.min(0, Math.max(cropVH - dispH, cropTY));
}
function cropApply() {
  cropClamp();
  $("crop-img").style.transform = `translate(${cropTX}px, ${cropTY}px) scale(${cropScale})`;
}

async function openCropScreen(file) {
  const workCanvas = await loadDownscaledCanvas(file, 1400);
  cropSourceCanvas = workCanvas;
  cropImgW = workCanvas.width;
  cropImgH = workCanvas.height;

  $("crop-backdrop").classList.remove("hidden");
  // Size the crop window to fit the screen, keeping the card's 1.586:1 ratio.
  cropVW = Math.min(340, window.innerWidth - 48);
  cropVH = Math.round(cropVW / 1.586);
  $("crop-viewport").style.width = cropVW + "px";
  $("crop-viewport").style.height = cropVH + "px";
  // Start at "cover" scale (image fills the crop window with no gaps),
  // centered — this is also the minimum zoom allowed.
  cropMinScale = Math.max(cropVW / cropImgW, cropVH / cropImgH);
  cropScale = cropMinScale;
  cropTX = (cropVW - cropImgW * cropScale) / 2;
  cropTY = (cropVH - cropImgH * cropScale) / 2;
  $("crop-img").src = workCanvas.toDataURL("image/jpeg", 0.85);
  cropApply();
}

function rotateCropPhoto() {
  if (!cropSourceCanvas) return;
  const src = cropSourceCanvas;
  const rotated = document.createElement("canvas");
  rotated.width = src.height;
  rotated.height = src.width;
  const ctx = rotated.getContext("2d");
  ctx.translate(rotated.width / 2, rotated.height / 2);
  ctx.rotate(Math.PI / 2); // 90deg clockwise
  ctx.drawImage(src, -src.width / 2, -src.height / 2);
  cropSourceCanvas = rotated;
  cropImgW = rotated.width;
  cropImgH = rotated.height;
  // Re-center at cover scale, same as the initial load — panning/zoom from
  // before the rotation doesn't map to anything sensible afterwards.
  cropMinScale = Math.max(cropVW / cropImgW, cropVH / cropImgH);
  cropScale = cropMinScale;
  cropTX = (cropVW - cropImgW * cropScale) / 2;
  cropTY = (cropVH - cropImgH * cropScale) / 2;
  $("crop-img").src = rotated.toDataURL("image/jpeg", 0.85);
  cropApply();
}
$("crop-rotate-btn").onclick = rotateCropPhoto;

function cropPointerDist(pts) {
  const [a, b] = pts;
  return Math.hypot(a.x - b.x, a.y - b.y);
}
$("crop-viewport").addEventListener("pointerdown", (e) => {
  e.target.setPointerCapture(e.pointerId);
  cropPointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
  if (cropPointers.size === 1) {
    cropPanStart = { x: e.clientX, y: e.clientY, tx: cropTX, ty: cropTY };
  } else if (cropPointers.size === 2) {
    cropPinchStartDist = cropPointerDist([...cropPointers.values()]);
    cropPinchStartScale = cropScale;
  }
});
$("crop-viewport").addEventListener("pointermove", (e) => {
  if (!cropPointers.has(e.pointerId)) return;
  cropPointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
  if (cropPointers.size === 1 && cropPanStart) {
    cropTX = cropPanStart.tx + (e.clientX - cropPanStart.x);
    cropTY = cropPanStart.ty + (e.clientY - cropPanStart.y);
    cropApply();
  } else if (cropPointers.size === 2) {
    const dist = cropPointerDist([...cropPointers.values()]);
    cropScale = Math.min(cropMinScale * 4, Math.max(cropMinScale, cropPinchStartScale * (dist / cropPinchStartDist)));
    cropApply();
  }
});
function cropPointerEnd(e) {
  cropPointers.delete(e.pointerId);
  if (cropPointers.size === 1) {
    const [p] = [...cropPointers.values()];
    cropPanStart = { x: p.x, y: p.y, tx: cropTX, ty: cropTY };
  } else {
    cropPanStart = null;
  }
}
$("crop-viewport").addEventListener("pointerup", cropPointerEnd);
$("crop-viewport").addEventListener("pointercancel", cropPointerEnd);
// Desktop convenience: mouse wheel to zoom (no pinch gesture on a mouse/trackpad).
$("crop-viewport").addEventListener("wheel", (e) => {
  e.preventDefault();
  cropScale = Math.min(cropMinScale * 4, Math.max(cropMinScale, cropScale * (1 - e.deltaY * 0.001)));
  cropApply();
}, { passive: false });

$("crop-cancel-btn").onclick = () => { $("crop-backdrop").classList.add("hidden"); cropSourceCanvas = null; };
$("crop-done-btn").onclick = () => {
  const outW = 900, outH = Math.round(outW / 1.586);
  const sx = -cropTX / cropScale;
  const sy = -cropTY / cropScale;
  const sW = cropVW / cropScale;
  const sH = cropVH / cropScale;
  const canvas = document.createElement("canvas");
  canvas.width = outW; canvas.height = outH;
  canvas.getContext("2d").drawImage(cropSourceCanvas, sx, sy, sW, sH, 0, 0, outW, outH);
  const dataUrl = canvas.toDataURL("image/jpeg", 0.7);
  pendingPhotoDataUrl = dataUrl;
  $("photo-preview").innerHTML = `<img src="${dataUrl}" />`;
  $("crop-backdrop").classList.add("hidden");
  cropSourceCanvas = null;
};


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
$("f-cvv").addEventListener("input", (e) => {
  e.target.value = e.target.value.replace(/\D/g, "").slice(0, 4);
});
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
    cvv: $("f-cvv").value.trim(),
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
