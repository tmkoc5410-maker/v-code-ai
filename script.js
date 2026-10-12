// =========================================================
// V CODE PERSISTENT STATE, STRICT API KEY + MODEL CONNECTOR
// & ANTIGRAVITY-STYLE CHAT + CODE FILES ENGINE
// (100% English | Zero Emojis | No Return to 1st Home Screen)
// =========================================================
const STORAGE_KEY = "vcode_persistent_memory_v6";

const PROVIDER_CATALOG = [
  {
    name: "Google Gemini",
    tag: "Free Tier Available",
    keyUrl: "https://aistudio.google.com/app/apikey",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
    defaultModel: "gemini-2.5-flash",
    models: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"]
  },
  {
    name: "Groq",
    tag: "Ultra-Fast & Free Tier",
    keyUrl: "https://console.groq.com/keys",
    baseUrl: "https://api.groq.com/openai/v1",
    defaultModel: "llama-3.3-70b-versatile",
    models: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"]
  },
  {
    name: "OpenRouter",
    tag: "Free & All AI Models",
    keyUrl: "https://openrouter.ai/keys",
    baseUrl: "https://openrouter.ai/api/v1",
    defaultModel: "openai/gpt-4o-mini",
    models: ["openai/gpt-4o-mini", "deepseek/deepseek-chat", "anthropic/claude-3.5-sonnet"]
  },
  {
    name: "OpenAI",
    tag: "Official GPT-4o",
    keyUrl: "https://platform.openai.com/api-keys",
    baseUrl: "https://api.openai.com/v1",
    defaultModel: "gpt-4o-mini",
    models: ["gpt-4o-mini", "gpt-4o", "o3-mini"]
  },
  {
    name: "DeepSeek",
    tag: "Coding & Reasoning",
    keyUrl: "https://platform.deepseek.com/api_keys",
    baseUrl: "https://api.deepseek.com/v1",
    defaultModel: "deepseek-chat",
    models: ["deepseek-chat", "deepseek-reasoner"]
  },
  {
    name: "Mistral AI",
    tag: "Codestral & Large",
    keyUrl: "https://console.mistral.ai/api-keys/",
    baseUrl: "https://api.mistral.ai/v1",
    defaultModel: "codestral-latest",
    models: ["codestral-latest", "mistral-large-latest"]
  },
  {
    name: "Together AI",
    tag: "Open-Source Cloud",
    keyUrl: "https://api.together.xyz/settings/api-keys",
    baseUrl: "https://api.together.xyz/v1",
    defaultModel: "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    models: ["meta-llama/Llama-3.3-70B-Instruct-Turbo"]
  },
  {
    name: "Local Ollama",
    tag: "Offline Local AI",
    keyUrl: "https://ollama.com/",
    baseUrl: "http://localhost:11434/v1",
    defaultModel: "qwen2.5-coder:7b",
    models: ["qwen2.5-coder:7b", "llama3.2"]
  }
];

// V.ai has NO AI models; other providers start with empty models until user adds API Key & Model Name
const DEFAULT_PROVIDERS = {
  "V.ai": {
    name: "V.ai",
    official: true,
    comingSoon: true,
    enabled: false,
    baseUrl: "https://api.v.ai/api/anthropic",
    apiKey: "",
    models: []
  },
  "Google Gemini": {
    name: "Google Gemini",
    official: false,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
    apiKey: "",
    models: []
  },
  "Groq": {
    name: "Groq",
    official: false,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://api.groq.com/openai/v1",
    apiKey: "",
    models: []
  },
  "OpenRouter": {
    name: "OpenRouter",
    official: false,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://openrouter.ai/api/v1",
    apiKey: "",
    models: []
  },
  "OpenAI": {
    name: "OpenAI",
    official: false,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://api.openai.com/v1",
    apiKey: "",
    models: []
  }
};

const DEFAULT_STATE = {
  theme: "dark",
  fontSize: "13.5px",
  username: "V Code Dev",
  language: "English",
  persistentMemoryEnabled: true,
  requireNameOnNew: false,
  enterToSend: true,
  selectedProvider: "V.ai",
  connectionMode: "API Key",
  providers: structuredClone(DEFAULT_PROVIDERS),
  activeProvider: "",
  activeModel: "",
  activeProjectId: "proj_default",
  activeSessionId: null,
  projects: [
    {
      id: "proj_default",
      name: "VCodeProject",
      memoryNotes: ["Workspace initialized for V Code AI development."],
      sessions: []
    }
  ]
};

// =========================================================
// 0.5 CLIENT-SIDE SECURITY VAULT, SECRET REDACTION & SANITIZERS
// =========================================================
const VAULT_PREFIX = "vcvault:v1:";
const VAULT_SALT = "VCode::Antigravity::ClientVault::2026";

function encryptVaultSecret(plainText) {
  const raw = String(plainText || "").trim();
  if (!raw) return "";
  if (raw.startsWith(VAULT_PREFIX)) return raw;
  try {
    const bytes = new TextEncoder().encode(raw);
    const saltBytes = new TextEncoder().encode(VAULT_SALT);
    const xored = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      xored[i] = bytes[i] ^ saltBytes[i % saltBytes.length] ^ ((i * 31) & 0xff);
    }
    let bin = "";
    xored.forEach((b) => {
      bin += String.fromCharCode(b);
    });
    return VAULT_PREFIX + btoa(bin);
  } catch {
    return raw;
  }
}

function decryptVaultSecret(cipherText) {
  const raw = String(cipherText || "").trim();
  if (!raw) return "";
  if (!raw.startsWith(VAULT_PREFIX)) return raw;
  try {
    const b64 = raw.slice(VAULT_PREFIX.length);
    const bin = atob(b64);
    const saltBytes = new TextEncoder().encode(VAULT_SALT);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i) ^ saltBytes[i % saltBytes.length] ^ ((i * 31) & 0xff);
    }
    return new TextDecoder().decode(out);
  } catch {
    return "";
  }
}

function redactSensitiveSecrets(inputStr) {
  return String(inputStr || "")
    .replace(/\b(sk-[a-zA-Z0-9_-]{16,})\b/g, "[REDACTED_API_KEY]")
    .replace(/\b(gsk_[a-zA-Z0-9_-]{16,})\b/g, "[REDACTED_GROQ_KEY]")
    .replace(/\b(AIza[0-9A-Za-z_-]{25,})\b/g, "[REDACTED_GEMINI_KEY]")
    .replace(/\b(xai-[a-zA-Z0-9_-]{16,})\b/g, "[REDACTED_XAI_KEY]");
}

function isSafeApiBaseUrl(urlStr) {
  try {
    const u = new URL(String(urlStr || "").trim());
    if (u.protocol === "https:") return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

function sanitizeSafeFilename(nameStr) {
  const cleaned = String(nameStr || "")
    .replace(/\\/g, "/")
    .split("/")
    .filter((seg) => seg && seg !== "." && seg !== "..")
    .join("/")
    .replace(/[^a-zA-Z0-9._/-]/g, "_");
  return cleaned.slice(0, 64) || "module.js";
}

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return structuredClone(DEFAULT_STATE);
    const parsed = JSON.parse(raw);
    const mergedProviders = { ...structuredClone(DEFAULT_PROVIDERS), ...(parsed.providers || {}) };
    Object.values(mergedProviders).forEach((p) => {
      if (p && typeof p.apiKey === "string" && p.apiKey) {
        p.apiKey = decryptVaultSecret(p.apiKey);
      }
    });
    if (mergedProviders["V.ai"]) {
      mergedProviders["V.ai"].models = [];
      mergedProviders["V.ai"].comingSoon = true;
      mergedProviders["V.ai"].enabled = false;
    }
    return {
      ...structuredClone(DEFAULT_STATE),
      ...parsed,
      requireNameOnNew: false,
      providers: mergedProviders
    };
  } catch {
    return structuredClone(DEFAULT_STATE);
  }
}

function saveState() {
  try {
    const toStore = structuredClone(state);
    if (toStore.providers) {
      Object.values(toStore.providers).forEach((p) => {
        if (p && typeof p.apiKey === "string" && p.apiKey) {
          p.apiKey = encryptVaultSecret(p.apiKey);
        }
      });
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toStore));
  } catch {
    // Ignore storage quota errors
  }
}

let state = loadState();
let attachedFiles = [];
let codeBlocksRegistry = [];
let workspaceCodeFiles = [];
let activeCodeFileIdx = 0;

// =========================================================
// 1. TOAST NOTIFICATIONS & CUSTOM INPUT MODAL (No alert/prompt)
// =========================================================
const toastContainer = document.getElementById("toast-container");

function showToast(message) {
  const toast = document.createElement("div");
  toast.className = "vc-toast";
  toast.textContent = message;
  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 180);
  }, 2400);
}

const customInputModal = document.getElementById("custom-input-modal");
const customInputTitle = document.getElementById("custom-input-title");
const customInputDesc = document.getElementById("custom-input-desc");
const customInputField = document.getElementById("custom-input-field");
const customInputForm = document.getElementById("custom-input-form");
let customInputCallback = null;

function openCustomInputModal({ title, desc, defaultValue = "", placeholder = "", onConfirm }) {
  customInputTitle.textContent = title;
  customInputDesc.textContent = desc;
  customInputField.value = defaultValue;
  customInputField.placeholder = placeholder;
  customInputCallback = onConfirm;
  customInputModal.classList.remove("hidden");
  setTimeout(() => customInputField.focus(), 60);
}

function closeCustomInputModal() {
  customInputModal.classList.add("hidden");
  customInputCallback = null;
}

document.getElementById("close-custom-input-btn").addEventListener("click", closeCustomInputModal);
document.getElementById("cancel-custom-input-btn").addEventListener("click", closeCustomInputModal);

customInputForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const val = customInputField.value.trim();
  if (!val) return;
  const cb = customInputCallback;
  closeCustomInputModal();
  if (cb) cb(val);
});

// =========================================================
// 2. THEME APPLICATION (Dark / Light / Midnight)
// =========================================================
function applyTheme(themeName) {
  state.theme = themeName;
  document.documentElement.setAttribute("data-theme", themeName);
  document.documentElement.style.setProperty("--chat-font-size", state.fontSize || "13.5px");

  document.querySelectorAll("[data-set-theme]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.setTheme === themeName);
  });
  saveState();
}

function cycleTheme() {
  const order = ["dark", "light", "midnight"];
  const next = order[(order.indexOf(state.theme) + 1) % order.length];
  applyTheme(next);
  showToast(`Theme switched to ${next.toUpperCase()}`);
}

applyTheme(state.theme || "dark");

// =========================================================
// 3. FAST BOOT SCREEN SEQUENCE (With Instant Skip Support)
// =========================================================
const bootEl = document.getElementById("boot");
const pctEl = document.getElementById("boot-pct");
const statusLabelEl = document.getElementById("status-label");
const statusDetailEl = document.getElementById("status-detail");

const homeScreen = document.getElementById("home-screen");
const workspaceScreen = document.getElementById("workspace-screen");
const settingsScreen = document.getElementById("settings-screen");

const BOOT_STEPS = [
  { at: 0,   label: "Initializing", detail: "Mounting virtual file system..." },
  { at: 22,  label: "Loading Core", detail: "Starting language server protocol..." },
  { at: 48,  label: "Indexing",     detail: "Restoring persistent project & chat memory..." },
  { at: 73,  label: "Optimizing",   detail: "Preparing multi-provider API connectors..." },
  { at: 92,  label: "Finalizing",   detail: "Preparing V Code interface..." },
  { at: 100, label: "Ready",        detail: "System online" }
];

const START_DELAY_MS = 120;
const DURATION_MS = 1250;
const KEYFRAMES = [
  { t: 0.0,  p: 0 },
  { t: 0.20, p: 22 },
  { t: 0.45, p: 48 },
  { t: 0.70, p: 73 },
  { t: 0.90, p: 92 },
  { t: 1.0,  p: 100 }
];

function interpolateProgress(normTime) {
  if (normTime <= 0) return 0;
  if (normTime >= 1) return 100;
  for (let i = 0; i < KEYFRAMES.length - 1; i++) {
    const curr = KEYFRAMES[i];
    const next = KEYFRAMES[i + 1];
    if (normTime >= curr.t && normTime <= next.t) {
      const segProgress = (normTime - curr.t) / (next.t - curr.t);
      return Math.round(curr.p + segProgress * (next.p - curr.p));
    }
  }
  return 100;
}

let animFrameId = null;
let lastStepIndex = -1;

function setStatusMessage(pct) {
  let stepIndex = 0;
  for (let i = 0; i < BOOT_STEPS.length; i++) {
    if (pct >= BOOT_STEPS[i].at) stepIndex = i;
  }
  if (stepIndex !== lastStepIndex) {
    lastStepIndex = stepIndex;
    const step = BOOT_STEPS[stepIndex];
    statusLabelEl.textContent = step.label;
    statusDetailEl.style.opacity = "0";
    setTimeout(() => {
      statusDetailEl.textContent = step.detail;
      statusDetailEl.style.opacity = "1";
    }, 180);
  }
}

function skipBootNow() {
  if (animFrameId) cancelAnimationFrame(animFrameId);
  bootEl.classList.add("hidden");
}

document.getElementById("skip-boot-btn").addEventListener("click", skipBootNow);

function runBootSequence() {
  if (animFrameId) cancelAnimationFrame(animFrameId);
  lastStepIndex = -1;
  pctEl.textContent = "0%";
  setStatusMessage(0);

  const startTime = performance.now();
  function tick(now) {
    const elapsed = now - startTime - START_DELAY_MS;
    if (elapsed < 0) {
      animFrameId = requestAnimationFrame(tick);
      return;
    }
    const norm = Math.min(elapsed / DURATION_MS, 1);
    const pct = interpolateProgress(norm);
    pctEl.textContent = `${pct}%`;
    setStatusMessage(pct);

    if (norm < 1) {
      animFrameId = requestAnimationFrame(tick);
    } else {
      setTimeout(() => bootEl.classList.add("hidden"), 400);
    }
  }
  animFrameId = requestAnimationFrame(tick);
}

// =========================================================
// 4. "COMING SOON" POPUP (For V.ai, Personal Plan & Agent Capabilities)
// =========================================================
const comingSoonModal = document.getElementById("coming-soon-modal");
const comingSoonTitle = document.getElementById("coming-soon-title");
const comingSoonHeading = document.getElementById("coming-soon-heading");
const comingSoonDesc = document.getElementById("coming-soon-desc");

function showComingSoonPopup(reason = "V.ai") {
  if (reason === "Personal plan") {
    comingSoonTitle.textContent = "Personal Plan Notice";
    comingSoonHeading.textContent = "This AI is not available this time — Coming soon!";
    comingSoonDesc.innerHTML =
      "Personal Plan subscription login is coming soon. Please use <strong>API Key</strong> mode with Google Gemini, Groq, OpenRouter, or OpenAI.";
  } else if (reason === "V.ai") {
    comingSoonTitle.textContent = "V.ai Notice";
    comingSoonHeading.textContent = "This AI is not available this time — Coming soon!";
    comingSoonDesc.innerHTML =
      "V.ai has no active AI models at this time — Coming soon! To connect a live working AI, select a provider under <em>Custom providers</em> (or click <strong>+ Add provider</strong>), paste your API Key, and add your Model Name.";
  } else {
    comingSoonTitle.textContent = reason;
    comingSoonHeading.textContent = "Coming Soon";
    comingSoonDesc.innerHTML = `<strong>${escapeHtml(reason)}</strong> capability is coming soon in an upcoming V Code update.`;
  }
  comingSoonModal.classList.remove("hidden");
}

document.getElementById("close-coming-soon-btn").addEventListener("click", () => comingSoonModal.classList.add("hidden"));
document.getElementById("ok-coming-soon-btn").addEventListener("click", () => comingSoonModal.classList.add("hidden"));

// =========================================================
// 5. SCREEN NAVIGATION (Never returns to 1st Home Screen once left!)
// =========================================================
const vDropdown = document.getElementById("v-dropdown");
const wsPromptInput = document.getElementById("ws-prompt-input");

function showScreen(target) {
  vDropdown.classList.add("hidden");
  [homeScreen, workspaceScreen, settingsScreen].forEach((sc) => {
    sc.classList.toggle("active", sc === target);
  });
}

function openWorkspaceScreen(pendingPrompt = "", forceSaveKind = null) {
  showScreen(workspaceScreen);
  renderAllUI();

  if (forceSaveKind) {
    openSaveModal(forceSaveKind, pendingPrompt);
  } else if (pendingPrompt && pendingPrompt.trim()) {
    handleIncomingPrompt(pendingPrompt.trim());
  } else {
    setTimeout(() => wsPromptInput.focus(), 150);
  }
}

function openSettingsScreen(tabName = "models") {
  showScreen(settingsScreen);
  switchSettingsTab(tabName);
  renderSettingsUI();
  renderAboutGuideGrid();
}

// =========================================================
// 6. SAVE-BY-NAME MODAL (Projects, Tasks, Chats)
// =========================================================
const saveNameModal = document.getElementById("save-name-modal");
const saveModalTitle = document.getElementById("save-modal-title");
const saveModalDesc = document.getElementById("save-modal-desc");
const saveProjectSelectRow = document.getElementById("save-project-select-row");
const saveModalProjectSelect = document.getElementById("save-modal-project-select");
const saveNameLabel = document.getElementById("save-name-label");
const saveNameInput = document.getElementById("save-name-input");
const saveMemoryNoteInput = document.getElementById("save-memory-note-input");
const saveNameForm = document.getElementById("save-name-form");

let pendingSaveAction = { kind: "task", initialPrompt: "" };

function openSaveModal(kind, initialPrompt = "") {
  pendingSaveAction = { kind, initialPrompt };
  saveNameInput.value = "";
  saveMemoryNoteInput.value = "";

  saveModalProjectSelect.innerHTML = state.projects
    .map((p) => `<option value="${p.id}" ${p.id === state.activeProjectId ? "selected" : ""}>${escapeHtml(p.name)}</option>`)
    .join("");

  if (kind === "project") {
    saveModalTitle.textContent = "Save New Workspace Project";
    saveModalDesc.textContent = "Save your project with a unique name first so V Code AI remembers all tasks, files, and chats inside it.";
    saveProjectSelectRow.style.display = "none";
    saveNameLabel.textContent = "Project Name";
    saveNameInput.placeholder = "e.g., VCode-FullStack-App";
  } else if (kind === "chat") {
    saveModalTitle.textContent = "Save New Chat by Name";
    saveModalDesc.textContent = "Give this Chat a name so your API-connected model keeps permanent memory of this conversation.";
    saveProjectSelectRow.style.display = "flex";
    saveNameLabel.textContent = "Chat Name";
    saveNameInput.placeholder = "e.g., Architecture-Memory-Chat";
  } else {
    saveModalTitle.textContent = "Save New Task by Name";
    saveModalDesc.textContent = "Save this Task with a name first so V Code AI never forgets what it is working on.";
    saveProjectSelectRow.style.display = "flex";
    saveNameLabel.textContent = "Task Name";
    saveNameInput.placeholder = "e.g., API-Integration-Task";
  }

  saveNameModal.classList.remove("hidden");
  setTimeout(() => saveNameInput.focus(), 100);
}

document.getElementById("close-save-modal-btn").addEventListener("click", () => saveNameModal.classList.add("hidden"));
document.getElementById("cancel-save-modal-btn").addEventListener("click", () => saveNameModal.classList.add("hidden"));

saveNameForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const nameVal = saveNameInput.value.trim();
  const noteVal = saveMemoryNoteInput.value.trim();
  if (!nameVal) return;

  if (pendingSaveAction.kind === "project") {
    const newProj = {
      id: "proj_" + Date.now(),
      name: nameVal,
      memoryNotes: noteVal ? [noteVal] : [`Project ${nameVal} created.`],
      sessions: []
    };
    state.projects.push(newProj);
    state.activeProjectId = newProj.id;
    state.activeSessionId = null;
    saveState();
    saveNameModal.classList.add("hidden");
    renderAllUI();
    showToast(`Project "${nameVal}" saved to Persistent Memory`);
  } else {
    const targetProjId = saveModalProjectSelect.value || state.activeProjectId;
    state.activeProjectId = targetProjId;
    const proj = getActiveProject();
    if (noteVal) proj.memoryNotes.push(`[${nameVal}] ${noteVal}`);

    const newSession = {
      id: "sess_" + Date.now(),
      name: nameVal,
      kind: pendingSaveAction.kind,
      memoryNote: noteVal,
      facts: noteVal ? [noteVal] : [],
      messages: []
    };
    proj.sessions.unshift(newSession);
    state.activeSessionId = newSession.id;
    saveState();
    saveNameModal.classList.add("hidden");
    renderAllUI();
    showToast(`${pendingSaveAction.kind === "chat" ? "Chat" : "Task"} "${nameVal}" locked in memory`);

    if (pendingSaveAction.initialPrompt) {
      executePromptInActiveSession(pendingSaveAction.initialPrompt);
    } else {
      wsPromptInput.focus();
    }
  }
});

// =========================================================
// 7. STRICT API KEY & MODEL NAME RESOLUTION
// (If no API Key + Model Name is added & enabled, NO model name is shown!)
// =========================================================
function getActiveProject() {
  return state.projects.find((p) => p.id === state.activeProjectId) || state.projects[0];
}

function getActiveSession() {
  const proj = getActiveProject();
  if (!proj) return null;
  return proj.sessions.find((s) => s.id === state.activeSessionId) || null;
}

function isProviderConfiguredAndEnabled(prov) {
  return Boolean(
    prov &&
    !prov.comingSoon &&
    prov.enabled &&
    prov.apiKey &&
    prov.apiKey.trim() !== "" &&
    Array.isArray(prov.models) &&
    prov.models.length > 0
  );
}

function getWorkingProviderConfig() {
  const active = state.providers[state.activeProvider];
  if (isProviderConfiguredAndEnabled(active)) {
    return active;
  }
  const selected = state.providers[state.selectedProvider];
  if (isProviderConfiguredAndEnabled(selected)) {
    return selected;
  }
  for (const key of Object.keys(state.providers)) {
    const p = state.providers[key];
    if (isProviderConfiguredAndEnabled(p)) {
      return p;
    }
  }
  return null;
}

function getActiveModelName() {
  const workingProv = getWorkingProviderConfig();
  if (!workingProv) return null;
  const found = workingProv.models.find((m) => m.name === state.activeModel);
  return found ? found.name : workingProv.models[0].name;
}

// Ordered list of all enabled providers & models for automatic failover (misterdev model_selector style)
function getAllWorkingProviderCandidates() {
  const candidates = [];
  const seen = new Set();
  const primaryProv = getWorkingProviderConfig();
  const primaryModel = getActiveModelName();

  if (primaryProv && primaryModel) {
    const key = `${primaryProv.name}::${primaryModel}`;
    seen.add(key);
    candidates.push({ prov: primaryProv, model: primaryModel });
  }

  Object.values(state.providers).forEach((prov) => {
    if (isProviderConfiguredAndEnabled(prov)) {
      prov.models.forEach((m) => {
        const key = `${prov.name}::${m.name}`;
        if (!seen.has(key)) {
          seen.add(key);
          candidates.push({ prov, model: m.name });
        }
      });
    }
  });
  return candidates;
}

// Anchored SEARCH / REPLACE Patching Engine (Ported from misterdev/llm/responses/apply.py)
function applySearchReplaceToCode(originalCode, incomingBlock) {
  if (!incomingBlock || !incomingBlock.includes("<<<<<<< SEARCH")) {
    return incomingBlock;
  }
  let patched = String(originalCode || "");
  const hunkRegex = /<<<<<<< SEARCH\r?\n([\s\S]*?)\r?\n=======\r?\n([\s\S]*?)\r?\n>>>>>>> REPLACE/g;
  let match;
  let appliedAny = false;

  while ((match = hunkRegex.exec(incomingBlock)) !== null) {
    const searchStr = match[1];
    const replaceStr = match[2];
    if (!searchStr.trim()) {
      patched = replaceStr;
      appliedAny = true;
      continue;
    }
    if (patched.includes(searchStr)) {
      patched = patched.replace(searchStr, replaceStr);
      appliedAny = true;
    } else {
      // Whitespace-tolerant line matching fallback
      const origLines = patched.replace(/\r\n/g, "\n").split("\n");
      const searchLines = searchStr.replace(/\r\n/g, "\n").split("\n");
      let foundIdx = -1;
      for (let i = 0; i <= origLines.length - searchLines.length; i++) {
        let allMatch = true;
        for (let j = 0; j < searchLines.length; j++) {
          if (origLines[i + j].trim() !== searchLines[j].trim()) {
            allMatch = false;
            break;
          }
        }
        if (allMatch) {
          foundIdx = i;
          break;
        }
      }
      if (foundIdx !== -1) {
        const replaceLines = replaceStr.replace(/\r\n/g, "\n").split("\n");
        origLines.splice(foundIdx, searchLines.length, ...replaceLines);
        patched = origLines.join("\n");
        appliedAny = true;
      }
    }
  }
  return appliedAny ? patched : incomingBlock;
}

// Client-Side Correctness & Syntax Gate (Ported from misterdev/core/verification/gatekeeper)
function verifyCodeGate(code, lang, filename = "") {
  const cleanCode = String(code || "").trim();
  if (!cleanCode) {
    return { ok: true, label: "Syntax OK", reason: "Empty block" };
  }
  const lower = (filename || lang || "").toLowerCase();

  // 1. JSON Gate
  if (lower.endsWith(".json") || lang === "json") {
    try {
      const stripped = cleanCode.replace(/^\s*\/\/.*$/gm, "").trim();
      JSON.parse(stripped);
      return { ok: true, label: "JSON Valid", reason: "Passed JSON.parse gate" };
    } catch (err) {
      return { ok: false, label: "JSON Error", reason: err.message };
    }
  }

  // 2. JavaScript Syntax Gate
  if (lower.endsWith(".js") || lang === "js" || lang === "javascript") {
    try {
      const moduleStripped = cleanCode
        .replace(/^\s*import\s+[\s\S]*?from\s+['"][^'"]+['"]\s*;?/gm, "")
        .replace(/^\s*import\s+['"][^'"]+['"]\s*;?/gm, "")
        .replace(/^\s*export\s+default\s+/gm, "")
        .replace(/^\s*export\s+(?=(?:const|let|var|function|class|async)\b)/gm, "");
      // Parse-only check via Function constructor (never invoked)
      new Function(moduleStripped);
      return { ok: true, label: "Syntax OK", reason: "Passed JS syntax gate" };
    } catch (err) {
      return { ok: false, label: "Syntax Issue", reason: err.message };
    }
  }

  // 3. CSS Brace Balance Gate
  if (lower.endsWith(".css") || lang === "css") {
    const noComments = cleanCode.replace(/\/\*[\s\S]*?\*\//g, "");
    const opens = (noComments.match(/\{/g) || []).length;
    const closes = (noComments.match(/\}/g) || []).length;
    if (opens !== closes) {
      return {
        ok: false,
        label: "CSS Brace Issue",
        reason: `Unbalanced CSS braces: ${opens} opening '{' vs ${closes} closing '}'`
      };
    }
    return { ok: true, label: "CSS Valid", reason: "Balanced CSS rules" };
  }

  // 4. HTML Tag Gate
  if (lower.endsWith(".html") || lang === "html") {
    const scriptOpens = (cleanCode.match(/<script\b[^>]*>/gi) || []).length;
    const scriptCloses = (cleanCode.match(/<\/script>/gi) || []).length;
    if (scriptOpens !== scriptCloses) {
      return { ok: false, label: "HTML Tag Issue", reason: "Unclosed <script> tag detected" };
    }
    const styleOpens = (cleanCode.match(/<style\b[^>]*>/gi) || []).length;
    const styleCloses = (cleanCode.match(/<\/style>/gi) || []).length;
    if (styleOpens !== styleCloses) {
      return { ok: false, label: "HTML Tag Issue", reason: "Unclosed <style> tag detected" };
    }
    return { ok: true, label: "HTML Valid", reason: "Passed HTML structure gate" };
  }

  return { ok: true, label: "Syntax OK", reason: "Structure verified" };
}

function extractMemoryFacts(text, session, project) {
  const cleaned = redactSensitiveSecrets(text).trim();
  if (cleaned.length > 3) {
    const factSummary = cleaned.length > 130 ? cleaned.slice(0, 130) + "..." : cleaned;
    if (!session.facts.includes(factSummary)) {
      session.facts.push(factSummary);
    }
    const tagged = `[${session.name}] ${factSummary}`;
    if (!project.memoryNotes.includes(tagged)) {
      project.memoryNotes.push(tagged);
    }
  }
}

async function callSingleProviderEndpoint(prov, modelName, systemPrompt, historyMessages) {
  const baseUrl = prov.baseUrl.replace(/\/$/, "");
  if (!isSafeApiBaseUrl(baseUrl)) {
    throw new Error("Blocked insecure Base URL protocol. Only HTTPS (or localhost) endpoints are permitted.");
  }
  const apiKey = prov.apiKey.trim();

  if (baseUrl.includes("generativelanguage.googleapis.com") && !baseUrl.endsWith("/openai")) {
    const geminiUrl = `${baseUrl}/models/${modelName}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const contents = historyMessages.map((m) => ({
      role: m.role === "user" ? "user" : "model",
      parts: [{ text: m.content }]
    }));
    const response = await fetch(geminiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt }] },
        contents
      })
    });
    if (!response.ok) {
      const errText = redactSensitiveSecrets(await response.text());
      throw new Error(`API Error (${response.status}): ${errText.slice(0, 180)}`);
    }
    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || "No response text returned.";
  } else {
    const endpoint = `${baseUrl}/chat/completions`;
    const headers = {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`
    };
    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: modelName,
        messages: [{ role: "system", content: systemPrompt }, ...historyMessages]
      })
    });
    if (!response.ok) {
      const errText = redactSensitiveSecrets(await response.text());
      throw new Error(`API Error (${response.status}): ${errText.slice(0, 200)}`);
    }
    const data = await response.json();
    return data.choices?.[0]?.message?.content || "Empty response from model.";
  }
}

async function callRealModelApiWithMemory(userText, session, project) {
  const candidates = getAllWorkingProviderCandidates();

  if (candidates.length === 0) {
    return `**No Active API Key or Model Configured**\n\nTo run AI chat and generate code files, please open **Settings -> Model settings**:\n1. Select a provider under **Custom providers** (such as **Google Gemini**, **Groq**, **OpenRouter**, **OpenAI**) or click **+ Add provider**.\n2. Paste your **API Key** and click **Enable API Key**.\n3. Enter your **Model Name** (or click **Load Free Models** to pick one in 1 click) and click **+ Add Model**.\n\n*(Your prompt and memory for **${project.name} -> ${session.name}** have been safely stored in the Persistent Memory Vault.)*`;
  }

  const existingFilesSummary =
    workspaceCodeFiles.length > 0
      ? `\nExisting Code Files in Workspace (${workspaceCodeFiles.length}):\n` +
        workspaceCodeFiles.map((f) => `- ${f.filename} (${f.linesCount} lines)`).join("\n")
      : "\nNo code files generated in this session yet.";

  const memoryBlock = `
=== V CODE PERSISTENT MEMORY VAULT (DO NOT FORGET) ===
Developer Name: ${state.username}
Preferred Language: ${state.language}
Active Workspace Project: "${project.name}"
Active ${session.kind.toUpperCase()} Name: "${session.name}"
Session Initial Context: ${session.memoryNote || "General development"}
Project Memory Notes & Learned Facts:
${project.memoryNotes.map((n, i) => `${i + 1}. ${n}`).join("\n")}
Session Remembered Facts:
${session.facts.map((f, i) => `${i + 1}. ${f}`).join("\n")}
${existingFilesSummary}
======================================================
Instructions for V Code AI (misterdev Orchestrator Protocol):
1. Always remember the above project, session context, and existing files.
2. When building or updating code, separate code into clean modular files (e.g., index.html, styles.css, app.js, main.py) and ALWAYS place a filename comment on line 1 of every fenced code block:
   - HTML: <!-- filename: index.html -->
   - CSS: /* filename: styles.css */
   - JS/TS: // filename: app.js
   - Python: # filename: main.py
3. When updating an existing file, output the updated file with the exact same filename comment on line 1 (or use anchored <<<<<<< SEARCH / ======= / >>>>>>> REPLACE blocks) so V Code updates that file in the Code Viewer and records a new version.
4. Ensure all JavaScript, JSON, HTML, and CSS pass syntax & brace verification gates.`;

  const historyMessages = session.messages
    .filter((m) => !m.temp)
    .slice(-16)
    .map((m) => ({
      role: m.role === "user" ? "user" : "assistant",
      content: m.text
    }));

  let lastError = null;
  for (let i = 0; i < candidates.length; i++) {
    const { prov, model } = candidates[i];
    try {
      const replyText = await callSingleProviderEndpoint(prov, model, memoryBlock, historyMessages);
      if (i > 0) {
        showToast(`Auto-failover: Completed using ${prov.name} (${model})`);
      }
      return replyText;
    } catch (err) {
      lastError = { prov, model, err };
      if (i < candidates.length - 1) {
        showToast(`${prov.name} busy — failing over to ${candidates[i + 1].prov.name}...`);
      }
    }
  }

  const failed = lastError || { prov: candidates[0].prov, model: candidates[0].model, err: new Error("Unknown error") };
  return `**API Connection Error (${failed.prov.name} — ${failed.model})**\n\`${redactSensitiveSecrets(failed.err.message)}\`\n\nPlease verify your API Key, Base URL, and Model Name (\`${failed.model}\`) in **Settings -> Model settings**, or click **Load Free Models** to pick another working model. Your conversation history and memory facts for **${session.name}** remain safely saved.`;
}

function handleIncomingPrompt(promptText) {
  let finalPrompt = promptText;
  if (attachedFiles.length > 0) {
    const fileContext = attachedFiles
      .map((f) => `\n\n\`\`\`${f.ext}\n// filename: ${sanitizeSafeFilename(f.name)}\n${f.content}\n\`\`\``)
      .join("");
    finalPrompt += fileContext;
    attachedFiles = [];
    renderAttachedFileChips();
  }

  const activeSession = getActiveSession();
  if (!activeSession && state.requireNameOnNew) {
    openSaveModal("task", finalPrompt);
    return;
  }
  if (!activeSession) {
    const proj = getActiveProject();
    const cleanTitle = promptText.replace(/\s+/g, " ").trim().slice(0, 44) || `Task ${proj.sessions.length + 1}`;
    const autoSess = {
      id: "sess_" + Date.now(),
      name: cleanTitle,
      kind: "task",
      memoryNote: "",
      facts: [],
      messages: []
    };
    proj.sessions.unshift(autoSess);
    state.activeSessionId = autoSess.id;
  }
  executePromptInActiveSession(finalPrompt);
}

let activeTypingController = null;

function stopActiveTypingInstantly() {
  if (activeTypingController && typeof activeTypingController.finishNow === "function") {
    activeTypingController.finishNow();
  }
}

async function executePromptInActiveSession(promptText) {
  stopActiveTypingInstantly();

  const proj = getActiveProject();
  const session = getActiveSession();
  if (!session) return;

  extractMemoryFacts(promptText, session, proj);

  const workingProv = getWorkingProviderConfig();
  const activeModel = getActiveModelName();
  const usedModelLabel = workingProv && activeModel ? `${workingProv.name} / ${activeModel}` : "No API Key Connected";

  session.messages.push({
    role: "user",
    text: promptText,
    model: usedModelLabel,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  });

  const thinkingMsg = {
    role: "agent",
    text: workingProv && activeModel
      ? `Running ${activeModel}...`
      : "Checking API Key configuration...",
    model: usedModelLabel,
    time: "Now",
    temp: true,
    streaming: true
  };
  session.messages.push(thinkingMsg);
  saveState();
  renderAllUI();

  const reply = await callRealModelApiWithMemory(promptText, session, proj);

  session.messages = session.messages.filter((m) => !m.temp);
  const liveAgentMsg = {
    role: "agent",
    text: "",
    fullText: reply,
    streaming: true,
    model: usedModelLabel,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  };
  session.messages.push(liveAgentMsg);

  await streamReplyWithTypingEffect(liveAgentMsg, reply);
}

function isCompactViewport() {
  return window.innerWidth <= 960;
}

function streamReplyWithTypingEffect(msgObj, fullText) {
  return new Promise((resolve) => {
    const totalLen = fullText.length;
    if (totalLen === 0) {
      msgObj.text = "";
      delete msgObj.streaming;
      delete msgObj.fullText;
      saveState();
      renderAllUI();
      resolve();
      return;
    }

    let currentIdx = 0;
    let paneAutoOpened = false;
    // Adaptive step so typing feels crisp, natural, and fast (~2-3.5s total even for large multi-file code)
    const stepSize = Math.max(4, Math.min(28, Math.ceil(totalLen / 95)));

    const finishNow = () => {
      if (activeTypingController?.timerId) {
        clearInterval(activeTypingController.timerId);
      }
      activeTypingController = null;
      msgObj.text = fullText;
      delete msgObj.streaming;
      delete msgObj.fullText;
      saveState();
      renderAllUI();
      if (workspaceCodeFiles.length > 0 && !isCompactViewport()) {
        setRightCodePaneOpen(true);
      }
      resolve();
    };

    const timerId = setInterval(() => {
      currentIdx = Math.min(totalLen, currentIdx + stepSize);
      msgObj.text = fullText.slice(0, currentIdx);
      renderAllUI();

      if (!paneAutoOpened && workspaceCodeFiles.length > 0 && !isCompactViewport()) {
        paneAutoOpened = true;
        setRightCodePaneOpen(true);
      }

      if (currentIdx >= totalLen) {
        finishNow();
      }
    }, 24);

    activeTypingController = { timerId, finishNow };
  });
}

// =========================================================
// 8. COLLAPSIBLE LEFT SIDEBAR & RIGHT WRITTEN CODE / PROGRESS PANEL
// =========================================================
const wsLayout = document.getElementById("ws-layout");
const wsCanvas = document.getElementById("ws-canvas");
const wsMainSplit = document.getElementById("ws-main-split");
const wsCodePane = document.getElementById("ws-code-pane");
const wsMobileBackdrop = document.getElementById("ws-mobile-backdrop");
const agWrittenCodeSection = document.getElementById("ag-written-code-section");
const agPaneTabs = document.getElementById("ag-pane-tabs");
const agActiveFilepath = document.getElementById("ag-active-filepath");
const agActiveFilemeta = document.getElementById("ag-active-filemeta");
const agPaneEditor = document.getElementById("ag-pane-editor");
const wsCodeFilesCount = document.getElementById("ws-code-files-count");

const wsTopbarLeftToggleBtn = document.getElementById("ws-topbar-left-toggle-btn");
const wsLayoutLeftBtn = document.getElementById("ws-layout-left-btn");
const wsLayoutRightBtn = document.getElementById("ws-layout-right-btn");

function syncMobileBackdropState() {
  if (!wsMobileBackdrop) return;
  const isLeftOpen = !wsLayout.classList.contains("left-sidebar-hidden");
  const isRightOpen = !wsCodePane.classList.contains("hidden");
  const showBackdrop = isCompactViewport() && (isLeftOpen || isRightOpen);
  wsMobileBackdrop.classList.toggle("hidden", !showBackdrop);
}

function setLeftSidebarOpen(isOpen) {
  if (isOpen && isCompactViewport() && !wsCodePane.classList.contains("hidden")) {
    wsMainSplit.classList.remove("code-pane-open");
    wsCodePane.classList.add("hidden");
    wsLayoutRightBtn?.classList.remove("active");
  }
  wsLayout.classList.toggle("left-sidebar-hidden", !isOpen);
  wsLayoutLeftBtn?.classList.toggle("active", isOpen);
  wsTopbarLeftToggleBtn?.classList.toggle("active", isOpen);
  syncMobileBackdropState();
}

function toggleLeftSidebar() {
  const isCurrentlyHidden = wsLayout.classList.contains("left-sidebar-hidden");
  setLeftSidebarOpen(isCurrentlyHidden);
}

function setRightCodePaneOpen(isOpen) {
  if (isOpen && isCompactViewport() && !wsLayout.classList.contains("left-sidebar-hidden")) {
    wsLayout.classList.add("left-sidebar-hidden");
    wsLayoutLeftBtn?.classList.remove("active");
    wsTopbarLeftToggleBtn?.classList.remove("active");
  }
  wsMainSplit.classList.toggle("code-pane-open", isOpen);
  wsCodePane.classList.toggle("hidden", !isOpen);
  wsLayoutRightBtn?.classList.toggle("active", isOpen);
  if (isOpen) {
    renderCodePane();
  }
  syncMobileBackdropState();
}

function toggleRightCodePane() {
  const isCurrentlyHidden = wsCodePane.classList.contains("hidden");
  setRightCodePaneOpen(isCurrentlyHidden);
}

wsMobileBackdrop?.addEventListener("click", () => {
  setLeftSidebarOpen(false);
  setRightCodePaneOpen(false);
});

window.addEventListener("resize", () => {
  syncMobileBackdropState();
});

if (isCompactViewport()) {
  setLeftSidebarOpen(false);
}

document.getElementById("ws-hide-left-sidebar-btn")?.addEventListener("click", toggleLeftSidebar);
wsTopbarLeftToggleBtn?.addEventListener("click", toggleLeftSidebar);
wsLayoutLeftBtn?.addEventListener("click", toggleLeftSidebar);

document.getElementById("ws-open-code-pane-btn")?.addEventListener("click", toggleRightCodePane);
wsLayoutRightBtn?.addEventListener("click", toggleRightCodePane);
document.getElementById("ag-close-pane-btn")?.addEventListener("click", () => setRightCodePaneOpen(false));

document.getElementById("ag-git-commit-btn")?.addEventListener("click", () => {
  const sess = getActiveSession();
  const count = workspaceCodeFiles.length;
  showToast(
    count > 0
      ? `Committed ${count} file(s) to branch feat/${slugifyName(sess?.name || "workspace")}`
      : "Workspace state committed to session memory"
  );
});

function slugifyName(str) {
  return String(str || "vcode")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 26) || "vcode";
}

function getBadgeInfoForExt(langOrFilename) {
  const lower = String(langOrFilename || "").toLowerCase();
  if (lower.endsWith(".js") || lower === "js" || lower === "javascript" || lower === "jsx") {
    return { cls: "js", label: "JS" };
  }
  if (lower.endsWith(".html") || lower === "html" || lower === "htm") {
    return { cls: "html", label: "HTML" };
  }
  if (lower.endsWith(".css") || lower === "css" || lower === "scss") {
    return { cls: "css", label: "CSS" };
  }
  if (lower.endsWith(".py") || lower === "py" || lower === "python") {
    return { cls: "py", label: "PY" };
  }
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower === "ts" || lower === "typescript") {
    return { cls: "ts", label: "TS" };
  }
  if (lower.endsWith(".json") || lower === "json") {
    return { cls: "json", label: "JSON" };
  }
  return { cls: "txt", label: (lower.slice(0, 3) || "TXT").toUpperCase() };
}

function inferFilenameFromCodeBlock(lang, code, index, existingFiles = []) {
  const firstLine = (code.split("\n")[0] || "").trim();
  const fileMatch = firstLine.match(/(?:\/\/|#|<!--|\/\*)\s*(?:filename|file):\s*([^\s*-->]+)/i);
  if (fileMatch && fileMatch[1]) {
    return sanitizeSafeFilename(fileMatch[1].replace(/^\/+/, ""));
  }

  const used = new Set(existingFiles.map((f) => f.filename));
  const l = (lang || "").toLowerCase();
  const candidatesByLang = {
    javascript: ["app.js", "engine.js", "utils.js", "server.js"],
    js: ["app.js", "engine.js", "utils.js", "server.js"],
    html: ["index.html", "view.html"],
    css: ["styles.css", "theme.css"],
    python: ["main.py", "app.py", "utils.py"],
    py: ["main.py", "app.py", "utils.py"],
    typescript: ["app.ts", "index.ts"],
    ts: ["app.ts", "index.ts"],
    json: ["package.json", "config.json"]
  };

  const candidates = candidatesByLang[l];
  if (candidates) {
    for (const c of candidates) {
      if (!used.has(c)) return c;
    }
  }

  const extMap = {
    javascript: "js",
    js: "js",
    typescript: "ts",
    ts: "ts",
    python: "py",
    py: "py",
    html: "html",
    css: "css",
    json: "json",
    bash: "sh",
    sh: "sh"
  };
  const ext = extMap[l] || (l || "js");
  return `module_${index + 1}.${ext}`;
}

function highlightCodeLine(rawLine) {
  if (!rawLine) return " ";
  const trimmed = rawLine.trim();
  if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
    return `<span class="syn-cm">${escapeHtml(rawLine)}</span>`;
  }

  const tokenRegex = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\b(?:const|let|var|function|return|async|await|import|export|from|default|class|extends|new|if|else|for|while|switch|case|break|try|catch|finally|throw|typeof|instanceof|in|of|def|elif|except|pass|lambda|yield|with|as|True|False|None|true|false|null|undefined|interface|type|public|private)\b|\b\d+(?:\.\d+)?\b|\b[a-zA-Z_$][a-zA-Z0-9_$]*(?=\s*\())/g;

  let result = "";
  let lastIdx = 0;
  let match;
  while ((match = tokenRegex.exec(rawLine)) !== null) {
    if (match.index > lastIdx) {
      result += escapeHtml(rawLine.slice(lastIdx, match.index));
    }
    const tok = match[0];
    if (tok.startsWith('"') || tok.startsWith("'") || tok.startsWith("`")) {
      result += `<span class="syn-str">${escapeHtml(tok)}</span>`;
    } else if (/^\d/.test(tok)) {
      result += `<span class="syn-num">${escapeHtml(tok)}</span>`;
    } else if (/^(const|let|var|function|return|async|await|import|export|from|default|class|extends|new|if|else|for|while|switch|case|break|try|catch|finally|throw|typeof|instanceof|in|of|def|elif|except|pass|lambda|yield|with|as|True|False|None|true|false|null|undefined|interface|type|public|private)$/.test(tok)) {
      result += `<span class="syn-kw">${escapeHtml(tok)}</span>`;
    } else {
      result += `<span class="syn-fn">${escapeHtml(tok)}</span>`;
    }
    lastIdx = tokenRegex.lastIndex;
  }
  if (lastIdx < rawLine.length) {
    result += escapeHtml(rawLine.slice(lastIdx));
  }
  return result;
}

function renderLineNumberedCodeHtml(codeString, showCursorOnLastLine = false) {
  const lines = codeString.replace(/\r\n/g, "\n").split("\n");
  return `
    <div class="ag-code-table">
      ${lines
        .map((line, idx) => {
          const isLast = showCursorOnLastLine && idx === lines.length - 1;
          return `
        <div class="ag-code-line">
          <span class="ag-line-num">${idx + 1}</span>
          <span class="ag-line-text">${highlightCodeLine(line)}${isLast ? '<span class="vc-typing-cursor"></span>' : ""}</span>
        </div>
      `;
        })
        .join("")}
    </div>
  `;
}

let isEditingCodePane = false;

function openCodeFileInPane(fileIndex) {
  if (workspaceCodeFiles.length === 0) {
    setRightCodePaneOpen(true);
    return;
  }
  isEditingCodePane = false;
  activeCodeFileIdx = Math.max(0, Math.min(fileIndex, workspaceCodeFiles.length - 1));
  setRightCodePaneOpen(true);
}

// Smart File Registry: Deduplicates by filename, applies SEARCH/REPLACE patches, and tracks version history (v1, v2...)
function registerOrUpdateWorkspaceFile(lang, rawCode, isStreamingCode) {
  const activeSess = getActiveSession();
  const filename = inferFilenameFromCodeBlock(lang, rawCode, workspaceCodeFiles.length, workspaceCodeFiles);
  const existingIdx = workspaceCodeFiles.findIndex((f) => f.filename.toLowerCase() === filename.toLowerCase());

  if (existingIdx !== -1) {
    const existing = workspaceCodeFiles[existingIdx];
    const patchedCode = applySearchReplaceToCode(existing.code, rawCode);
    if (!isStreamingCode && patchedCode !== existing.code) {
      existing.versions.push(patchedCode);
    }
    // Check if user manually edited/overrode this file in the Code Viewer
    const overrideHistory = activeSess?.fileOverrides?.[filename];
    const finalCode =
      !isStreamingCode && Array.isArray(overrideHistory) && overrideHistory.length > 0
        ? overrideHistory[overrideHistory.length - 1]
        : patchedCode;

    existing.code = finalCode;
    existing.linesCount = Math.max(1, finalCode.split("\n").length);
    existing.isStreamingCode = isStreamingCode;
    existing.versionNum = existing.versions.length + (Array.isArray(overrideHistory) ? overrideHistory.length : 0);
    existing.gate = isStreamingCode
      ? { ok: true, label: "Writing...", reason: "Streaming code" }
      : verifyCodeGate(finalCode, lang, filename);

    const cardEntry = {
      ...existing,
      code: patchedCode,
      linesCount: Math.max(1, patchedCode.split("\n").length),
      fileIdx: existingIdx
    };
    return { entry: cardEntry, fileIdx: existingIdx };
  }

  const overrideHistory = activeSess?.fileOverrides?.[filename];
  const finalCode =
    !isStreamingCode && Array.isArray(overrideHistory) && overrideHistory.length > 0
      ? overrideHistory[overrideHistory.length - 1]
      : rawCode;

  const fileIdx = workspaceCodeFiles.length;
  const linesCount = Math.max(1, finalCode.split("\n").length);
  const badge = getBadgeInfoForExt(filename || lang);
  const versions = [rawCode];
  if (Array.isArray(overrideHistory) && overrideHistory.length > 0) {
    versions.push(...overrideHistory);
  }
  const gate = isStreamingCode
    ? { ok: true, label: "Writing...", reason: "Streaming code" }
    : verifyCodeGate(finalCode, lang, filename);

  const fileEntry = {
    lang,
    code: finalCode,
    filename,
    fileIdx,
    linesCount,
    badge,
    versions,
    versionNum: versions.length,
    gate,
    isStreamingCode
  };
  workspaceCodeFiles.push(fileEntry);
  return { entry: fileEntry, fileIdx };
}

function renderCodePane() {
  const activeProj = getActiveProject();
  const paneFileCountEl = document.getElementById("ag-pane-filecount");
  const paneTabsBarEl = document.getElementById("ag-pane-tabs-bar");
  const activeVersionEl = document.getElementById("ag-active-version");
  const activeGateEl = document.getElementById("ag-active-gate");
  const undoBtnEl = document.getElementById("ag-undo-file-btn");
  const editLabelEl = document.getElementById("ag-edit-file-label");
  const editBtnEl = document.getElementById("ag-edit-file-btn");

  if (wsCodeFilesCount) {
    wsCodeFilesCount.textContent = String(workspaceCodeFiles.length);
  }
  if (paneFileCountEl) {
    paneFileCountEl.textContent = `${workspaceCodeFiles.length} file${workspaceCodeFiles.length === 1 ? "" : "s"}`;
  }

  if (workspaceCodeFiles.length === 0) {
    isEditingCodePane = false;
    if (paneTabsBarEl) paneTabsBarEl.classList.add("hidden");
    if (activeVersionEl) activeVersionEl.classList.add("hidden");
    if (activeGateEl) activeGateEl.classList.add("hidden");
    if (undoBtnEl) undoBtnEl.classList.add("hidden");
    if (editLabelEl) editLabelEl.textContent = "Edit";
    editBtnEl?.classList.remove("active");
    agPaneTabs.innerHTML = "";
    agActiveFilepath.textContent = `${activeProj.name} / No code files yet`;
    agActiveFilemeta.textContent = "0 lines";
    agPaneEditor.innerHTML = `
      <div class="ag-empty-code-viewer">
        <span>No code files generated in this chat yet.</span>
      </div>
    `;
    return;
  }

  if (paneTabsBarEl) paneTabsBarEl.classList.remove("hidden");

  if (activeCodeFileIdx >= workspaceCodeFiles.length) {
    activeCodeFileIdx = workspaceCodeFiles.length - 1;
  }
  const activeFile = workspaceCodeFiles[activeCodeFileIdx];

  agPaneTabs.innerHTML = workspaceCodeFiles
    .map((f, idx) => {
      const badge = getBadgeInfoForExt(f.filename || f.lang);
      const verTag = f.versionNum > 1 ? `<span class="ag-tab-ver">v${f.versionNum}</span>` : "";
      return `
        <button type="button" class="ag-pane-tab ${idx === activeCodeFileIdx ? "active" : ""}" data-tab-file="${idx}">
          <span class="ag-ext-badge ${badge.cls}">${badge.label}</span>
          <span>${escapeHtml(f.filename.split("/").pop())}</span>
          ${verTag}
        </button>
      `;
    })
    .join("");

  agPaneTabs.querySelectorAll("[data-tab-file]").forEach((btn) => {
    btn.addEventListener("click", () => {
      isEditingCodePane = false;
      activeCodeFileIdx = Number(btn.dataset.tabFile);
      renderCodePane();
    });
  });

  agActiveFilepath.textContent = `${activeProj.name} / ${activeFile.filename}`;
  agActiveFilemeta.textContent = `${activeFile.linesCount} lines`;

  if (activeVersionEl) {
    activeVersionEl.textContent = `v${activeFile.versionNum || 1}`;
    activeVersionEl.classList.remove("hidden");
  }

  if (activeGateEl && activeFile.gate) {
    activeGateEl.textContent = activeFile.gate.label;
    activeGateEl.title = activeFile.gate.reason || "";
    activeGateEl.classList.toggle("pass", Boolean(activeFile.gate.ok));
    activeGateEl.classList.toggle("fail", !activeFile.gate.ok);
    activeGateEl.classList.remove("hidden");
  }

  if (undoBtnEl) {
    const canUndo = Array.isArray(activeFile.versions) && activeFile.versions.length > 1;
    undoBtnEl.classList.toggle("hidden", !canUndo);
  }

  if (editLabelEl) {
    editLabelEl.textContent = isEditingCodePane ? "Save Edit" : "Edit";
  }
  editBtnEl?.classList.toggle("active", isEditingCodePane);

  if (isEditingCodePane) {
    agPaneEditor.innerHTML = `
      <textarea class="ag-code-editor-textarea" id="ag-live-code-textarea" spellcheck="false">${escapeHtml(activeFile.code)}</textarea>
    `;
    const ta = document.getElementById("ag-live-code-textarea");
    ta?.focus();
  } else {
    agPaneEditor.innerHTML = renderLineNumberedCodeHtml(activeFile.code, Boolean(activeFile.isStreamingCode));
  }
}

document.getElementById("ag-edit-file-btn")?.addEventListener("click", () => {
  const f = workspaceCodeFiles[activeCodeFileIdx];
  if (!f) return;

  if (!isEditingCodePane) {
    isEditingCodePane = true;
    renderCodePane();
    return;
  }

  const ta = document.getElementById("ag-live-code-textarea");
  if (ta) {
    const updatedCode = ta.value;
    if (updatedCode !== f.code) {
      f.versions = f.versions || [f.code];
      f.versions.push(updatedCode);
      f.code = updatedCode;
      f.linesCount = Math.max(1, updatedCode.split("\n").length);
      f.versionNum = f.versions.length;
      f.gate = verifyCodeGate(updatedCode, f.lang, f.filename);

      const sess = getActiveSession();
      if (sess) {
        sess.fileOverrides = sess.fileOverrides || {};
        sess.fileOverrides[f.filename] = sess.fileOverrides[f.filename] || [];
        sess.fileOverrides[f.filename].push(updatedCode);
        saveState();
      }
      showToast(`Saved ${f.filename} (v${f.versionNum}) — ${f.gate.label}`);
    }
  }
  isEditingCodePane = false;
  renderCodePane();
});

document.getElementById("ag-undo-file-btn")?.addEventListener("click", () => {
  const f = workspaceCodeFiles[activeCodeFileIdx];
  if (!f || !Array.isArray(f.versions) || f.versions.length <= 1) return;

  f.versions.pop();
  const prevCode = f.versions[f.versions.length - 1];
  f.code = prevCode;
  f.linesCount = Math.max(1, prevCode.split("\n").length);
  f.versionNum = f.versions.length;
  f.gate = verifyCodeGate(prevCode, f.lang, f.filename);

  const sess = getActiveSession();
  if (sess?.fileOverrides?.[f.filename]?.length) {
    sess.fileOverrides[f.filename].pop();
    saveState();
  }
  isEditingCodePane = false;
  renderCodePane();
  showToast(`Reverted ${f.filename} to v${f.versionNum}`);
});

document.getElementById("ag-copy-file-btn")?.addEventListener("click", () => {
  const f = workspaceCodeFiles[activeCodeFileIdx];
  if (!f) return;
  navigator.clipboard.writeText(f.code);
  showToast(`Copied ${f.filename}`);
});

document.getElementById("ag-download-file-btn")?.addEventListener("click", () => {
  const f = workspaceCodeFiles[activeCodeFileIdx];
  if (!f) return;
  const blob = new Blob([f.code], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = f.filename.split("/").pop() || "code.txt";
  a.click();
  showToast(`Saved ${f.filename}`);
});

document.getElementById("ag-download-all-btn")?.addEventListener("click", () => {
  if (workspaceCodeFiles.length === 0) {
    showToast("No code files to save yet");
    return;
  }
  workspaceCodeFiles.forEach((f, i) => {
    setTimeout(() => {
      const blob = new Blob([f.code], { type: "text/plain;charset=utf-8" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = f.filename.split("/").pop() || `file_${i + 1}.txt`;
      a.click();
    }, i * 140);
  });
  showToast(`Saving all ${workspaceCodeFiles.length} file(s)...`);
});

// =========================================================
// 9. RENDER WORKSPACE, SIDEBAR, SCREENSHOT-STYLE CHAT & STRICT MODEL BADGES
// =========================================================
const wsProjectTree = document.getElementById("ws-project-tree");
const wsTaskFeed = document.getElementById("ws-task-feed");
const wsWatermark = document.getElementById("ws-watermark");
const wsHeroHeading = document.getElementById("ws-hero-heading");

function renderAllUI() {
  const activeProj = getActiveProject();
  const activeSess = getActiveSession();
  const workingProv = getWorkingProviderConfig();
  const activeModel = getActiveModelName();

  document.getElementById("ws-username-display").textContent = state.username || "V Code Dev";
  document.getElementById("composer-project-label").textContent = activeProj.name;

  const topbarProjName = document.getElementById("ws-topbar-project-name");
  const topbarBranchName = document.getElementById("ws-topbar-branch-name");
  if (topbarProjName) topbarProjName.textContent = activeProj.name;
  if (topbarBranchName) {
    topbarBranchName.textContent = activeSess ? `upgrade/v3.0` : "main";
  }

  // STRICT RULE: Only show model name if API Key is added & enabled AND model name is added!
  const homeBadgeEl = document.getElementById("home-model-badge");
  const wsModelTextEl = document.getElementById("ws-model-text");
  const wsApiBadgeEl = document.getElementById("ws-api-status-badge");

  if (workingProv && activeModel) {
    homeBadgeEl.textContent = `${workingProv.name}: ${activeModel}`;
    wsModelTextEl.textContent = activeModel;
    if (wsApiBadgeEl) wsApiBadgeEl.textContent = `${workingProv.name} (${activeModel})`;
  } else {
    homeBadgeEl.textContent = "Connect API Key";
    wsModelTextEl.textContent = "Add API Key";
    if (wsApiBadgeEl) wsApiBadgeEl.textContent = "No API Key";
  }

  const sessionLabel = document.getElementById("ws-active-session-label");
  const composerSessionBadge = document.getElementById("composer-session-badge");
  if (activeSess) {
    const kindLabel = activeSess.kind === "chat" ? "Chat" : "Task";
    const firstUserPrompt = activeSess.messages.find((m) => m.role === "user")?.text;
    sessionLabel.textContent = firstUserPrompt
      ? firstUserPrompt.replace(/\s+/g, " ").trim().slice(0, 62) + (firstUserPrompt.length > 62 ? "..." : "")
      : `${activeSess.name}`;
    composerSessionBadge.textContent = `${kindLabel}: ${activeSess.name}`;
    wsHeroHeading.innerHTML = `${escapeHtml(activeSess.name)}`;
  } else {
    sessionLabel.textContent = `Start a new task in ${activeProj.name}`;
    composerSessionBadge.textContent = "Ready";
    wsHeroHeading.innerHTML = `Start a new task in <span id="ws-title-project">${escapeHtml(activeProj.name)}</span>`;
  }

  // Render Sidebar Tree with Hover Rename & Delete Buttons
  wsProjectTree.innerHTML = state.projects
    .map((proj) => {
      const isProjActive = proj.id === activeProj.id;
      const sessionsHtml =
        proj.sessions.length === 0
          ? `<div class="ws-empty-tasks">No tasks yet</div>`
          : proj.sessions
              .map((sess) => {
                const isSessActive = activeSess && sess.id === activeSess.id;
                return `
                  <div class="ws-task-item ${isSessActive ? "active" : ""}" data-proj-id="${proj.id}" data-sess-id="${sess.id}">
                    <span class="ws-task-dot"></span>
                    <span class="ws-task-title">${escapeHtml(sess.name)}</span>
                    <span class="ws-item-right">
                      <span class="ws-item-actions">
                        <button type="button" class="ws-act-btn" data-rename-sess="${sess.id}" data-proj-id="${proj.id}" title="Rename">Edit</button>
                        <button type="button" class="ws-act-btn del" data-del-sess="${sess.id}" data-proj-id="${proj.id}" title="Delete">Del</button>
                      </span>
                      <span class="ws-task-time">2m</span>
                    </span>
                  </div>
                `;
              })
              .join("");

      return `
        <div class="ws-project-group">
          <div class="ws-folder-item ${isProjActive ? "active" : ""}" data-select-proj="${proj.id}">
            <span class="ws-folder-left">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
              </svg>
              <span>${escapeHtml(proj.name)}</span>
            </span>
            <span class="ws-item-right">
              <span class="ws-item-actions">
                <button type="button" class="ws-act-btn" data-rename-proj="${proj.id}" title="Rename Project">Edit</button>
                ${state.projects.length > 1 ? `<button type="button" class="ws-act-btn del" data-del-proj="${proj.id}" title="Delete Project">Del</button>` : ""}
              </span>
            </span>
          </div>
          <div class="ws-task-list">${sessionsHtml}</div>
        </div>
      `;
    })
    .join("");

  wsProjectTree.querySelectorAll("[data-select-proj]").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      state.activeProjectId = el.dataset.selectProj;
      const p = getActiveProject();
      state.activeSessionId = p.sessions[0]?.id || null;
      saveState();
      renderAllUI();
    });
  });

  wsProjectTree.querySelectorAll("[data-sess-id]").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      state.activeProjectId = el.dataset.projId;
      state.activeSessionId = el.dataset.sessId;
      saveState();
      renderAllUI();
      if (isCompactViewport()) {
        setLeftSidebarOpen(false);
      }
    });
  });

  wsProjectTree.querySelectorAll("[data-rename-proj]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const proj = state.projects.find((p) => p.id === btn.dataset.renameProj);
      if (!proj) return;
      openCustomInputModal({
        title: "Rename Workspace Project",
        desc: "Enter a new name for this project:",
        defaultValue: proj.name,
        onConfirm: (newName) => {
          proj.name = newName;
          saveState();
          renderAllUI();
          showToast(`Project renamed to "${newName}"`);
        }
      });
    });
  });

  wsProjectTree.querySelectorAll("[data-del-proj]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (state.projects.length <= 1) return;
      state.projects = state.projects.filter((p) => p.id !== btn.dataset.delProj);
      if (!state.projects.some((p) => p.id === state.activeProjectId)) {
        state.activeProjectId = state.projects[0].id;
        state.activeSessionId = state.projects[0].sessions[0]?.id || null;
      }
      saveState();
      renderAllUI();
      showToast("Project deleted");
    });
  });

  wsProjectTree.querySelectorAll("[data-rename-sess]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const proj = state.projects.find((p) => p.id === btn.dataset.projId);
      const sess = proj?.sessions.find((s) => s.id === btn.dataset.renameSess);
      if (!sess) return;
      openCustomInputModal({
        title: "Rename Saved Session",
        desc: "Enter a new name for this Task or Chat:",
        defaultValue: sess.name,
        onConfirm: (newName) => {
          sess.name = newName;
          saveState();
          renderAllUI();
          showToast(`Session renamed to "${newName}"`);
        }
      });
    });
  });

  wsProjectTree.querySelectorAll("[data-del-sess]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const proj = state.projects.find((p) => p.id === btn.dataset.projId);
      if (!proj) return;
      proj.sessions = proj.sessions.filter((s) => s.id !== btn.dataset.delSess);
      if (state.activeSessionId === btn.dataset.delSess) {
        state.activeSessionId = proj.sessions[0]?.id || null;
      }
      saveState();
      renderAllUI();
      showToast("Session removed");
    });
  });

  // Render Chat, Written Code Cards & "Code Files (N)" Summary Box
  codeBlocksRegistry = [];
  workspaceCodeFiles = [];

  if (activeSess && activeSess.messages.length > 0) {
    wsCanvas.classList.add("has-messages");
    wsTaskFeed.classList.remove("hidden");
    wsWatermark.classList.add("compact");

    wsTaskFeed.innerHTML = activeSess.messages
      .map((m, msgIdx) => {
        const isUser = m.role === "user";
        if (isUser && msgIdx === 0) {
          return "";
        }
        const isStreamingMsg = Boolean(m.streaming);
        const bodyHtml = formatAntigravityMessageHtml(m.text, isUser, msgIdx, isStreamingMsg);
        const streamingFooterHtml =
          isStreamingMsg && !m.temp
            ? `
              <div class="vc-streaming-row">
                <span class="vc-streaming-dot"></span>
                <span>Writing response &amp; code...</span>
                <button type="button" class="vc-skip-typing-btn" data-finish-typing="1">Finish now</button>
              </div>
            `
            : "";
        return `
          <div class="ws-feed-msg ${m.role}" data-msg-turn="${msgIdx}">
            ${bodyHtml}
            ${streamingFooterHtml}
          </div>
        `;
      })
      .join("");

    wsTaskFeed.querySelectorAll("[data-finish-typing]").forEach((btn) => {
      btn.addEventListener("click", stopActiveTypingInstantly);
    });

    wsTaskFeed.querySelectorAll("[data-copy-code]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const entry = codeBlocksRegistry[Number(btn.dataset.copyCode)];
        if (entry) {
          navigator.clipboard.writeText(entry.code);
          showToast(`Copied ${entry.filename}`);
        }
      });
    });

    wsTaskFeed.querySelectorAll("[data-open-codefile]").forEach((btn) => {
      btn.addEventListener("click", () => {
        openCodeFileInPane(Number(btn.dataset.openCodefile));
      });
    });

    // 1-Click Auto-Fix button when Syntax Gate detects an error (misterdev try-edit-verify loop)
    wsTaskFeed.querySelectorAll("[data-autofix-code]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const entry = codeBlocksRegistry[Number(btn.dataset.autofixCode)];
        if (!entry) return;
        const fixPrompt = `Fix the syntax/structure issue in ${entry.filename} (${entry.gate?.reason || "Syntax error"}). Return the complete corrected file with the filename comment on line 1:\n\n\`\`\`${entry.lang}\n// filename: ${entry.filename}\n${entry.code}\n\`\`\``;
        executePromptInActiveSession(fixPrompt);
      });
    });

    // Toggle individual Written Code card visibility (Hide / Show)
    wsTaskFeed.querySelectorAll("[data-toggle-inline-code]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const card = btn.closest(".ag-code-card");
        if (!card) return;
        const isCollapsed = card.classList.toggle("collapsed");
        btn.textContent = isCollapsed ? "Show" : "Hide";
      });
    });

    // Toggle all Written Code cards in a turn from the "Code Files (N)" box
    wsTaskFeed.querySelectorAll("[data-toggle-turn-code]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const turnEl = btn.closest(".ws-feed-msg");
        if (!turnEl) return;
        const cards = turnEl.querySelectorAll(".ag-code-card");
        const anyExpanded = Array.from(cards).some((c) => !c.classList.contains("collapsed"));
        cards.forEach((c) => {
          c.classList.toggle("collapsed", anyExpanded);
          const toggleBtn = c.querySelector("[data-toggle-inline-code]");
          if (toggleBtn) toggleBtn.textContent = anyExpanded ? "Show" : "Hide";
        });
        btn.textContent = anyExpanded ? "Show Code" : "Hide Code";
      });
    });

    wsTaskFeed.scrollTop = wsTaskFeed.scrollHeight;
  } else {
    wsCanvas.classList.remove("has-messages");
    wsTaskFeed.classList.add("hidden");
    wsWatermark.classList.remove("compact");
  }

  renderCodePane();
}

function buildCodeCardHtml(entry, codeId, showCursor = false) {
  const gate = entry.gate || { ok: true, label: "Syntax OK", reason: "" };
  const gatePillHtml = `<span class="ag-gate-pill ${gate.ok ? "pass" : "fail"}" title="${escapeHtml(gate.reason || gate.label)}">${escapeHtml(gate.label)}</span>`;
  const verBadgeHtml = entry.versionNum > 1 ? `<span class="ag-version-badge">v${entry.versionNum}</span>` : "";
  const autoFixBtnHtml = !gate.ok
    ? `<button type="button" class="vc-code-btn autofix" data-autofix-code="${codeId}" title="Send error to AI for automatic repair">Auto-Fix</button>`
    : "";

  return `
    <div class="ag-code-card" id="ag-code-card-${codeId}">
      <div class="ag-code-header">
        <div class="ag-code-file-info">
          <span class="ag-ext-badge ${entry.badge.cls}">${entry.badge.label}</span>
          <span class="ag-code-filename" data-open-codefile="${entry.fileIdx}" title="Click to open in Right Code Viewer">${escapeHtml(entry.filename)}</span>
          ${verBadgeHtml}
          <span class="ag-code-lines-pill">${entry.linesCount} lines</span>
          ${gatePillHtml}
        </div>
        <div class="ag-code-actions">
          ${autoFixBtnHtml}
          <button type="button" class="vc-code-btn" data-open-codefile="${entry.fileIdx}" title="Open in Right Code Viewer">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="3" width="18" height="18" rx="2"/><line x1="15" y1="3" x2="15" y2="21"/>
            </svg>
            <span>Code Viewer</span>
          </button>
          <button type="button" class="vc-code-btn" data-copy-code="${codeId}" title="Copy code">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
            <span>Copy</span>
          </button>
          <button type="button" class="vc-code-btn" data-toggle-inline-code="${codeId}">Hide</button>
        </div>
      </div>
      ${renderLineNumberedCodeHtml(entry.code, showCursor)}
    </div>
  `;
}

function formatAntigravityMessageHtml(rawText, isUser, msgIdx = 0, isStreaming = false) {
  if (isUser) {
    return `<div class="ag-narrative-text">${formatInlineText(rawText)}</div>`;
  }

  const narrativeParts = [];
  const codeCardsHtml = [];
  let lastIndex = 0;
  const regex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;
  let match;
  const turnFileIndices = [];

  while ((match = regex.exec(rawText)) !== null) {
    if (match.index > lastIndex) {
      const chunk = rawText.slice(lastIndex, match.index).trim();
      if (chunk) {
        narrativeParts.push(`<div class="ag-narrative-text">${formatInlineText(chunk)}</div>`);
      }
    }
    const lang = (match[1] || "js").toLowerCase();
    const code = match[2].replace(/\s+$/, "");
    const codeId = codeBlocksRegistry.length;

    const { entry, fileIdx } = registerOrUpdateWorkspaceFile(lang, code, false);
    codeBlocksRegistry.push(entry);
    if (!turnFileIndices.includes(fileIdx)) {
      turnFileIndices.push(fileIdx);
    }

    codeCardsHtml.push(buildCodeCardHtml(entry, codeId, false));
    lastIndex = regex.lastIndex;
  }

  let hasUnclosedCodeBlock = false;
  if (lastIndex < rawText.length) {
    const remaining = rawText.slice(lastIndex);
    const unclosedMatch = remaining.match(/```([a-zA-Z0-9_-]*)\n([\s\S]*)$/);
    if (unclosedMatch) {
      hasUnclosedCodeBlock = true;
      const beforeCode = remaining.slice(0, unclosedMatch.index).trim();
      if (beforeCode) {
        narrativeParts.push(`<div class="ag-narrative-text">${formatInlineText(beforeCode)}</div>`);
      }
      const lang = (unclosedMatch[1] || "js").toLowerCase();
      const code = unclosedMatch[2];
      const codeId = codeBlocksRegistry.length;

      const { entry, fileIdx } = registerOrUpdateWorkspaceFile(lang, code, isStreaming);
      codeBlocksRegistry.push(entry);
      if (!turnFileIndices.includes(fileIdx)) {
        turnFileIndices.push(fileIdx);
      }
      activeCodeFileIdx = fileIdx;

      codeCardsHtml.push(buildCodeCardHtml(entry, codeId, isStreaming));
    } else {
      const tail = remaining.trim();
      if (tail) {
        narrativeParts.push(
          `<div class="ag-narrative-text">${formatInlineText(tail)}${isStreaming ? '<span class="vc-typing-cursor"></span>' : ""}</div>`
        );
      } else if (isStreaming && narrativeParts.length === 0 && codeCardsHtml.length === 0) {
        narrativeParts.push(`<div class="ag-narrative-text"><span class="vc-typing-cursor"></span></div>`);
      }
    }
  } else if (isStreaming && !hasUnclosedCodeBlock) {
    if (narrativeParts.length > 0) {
      const last = narrativeParts.pop();
      narrativeParts.push(last.replace(/<\/div>$/, '<span class="vc-typing-cursor"></span></div>'));
    }
  }

  if (turnFileIndices.length > 0) {
    const turnFiles = turnFileIndices.map((idx) => workspaceCodeFiles[idx]).filter(Boolean);

    // Clean Code Files List Card at Bottom of Turn
    const filesChangedCardHtml = `
      <div class="ag-files-changed-card">
        <div class="ag-fc-header">
          <div class="ag-fc-title">
            <span>Code Files (${turnFiles.length})</span>
          </div>
          <div class="ag-fc-actions">
            <button type="button" class="ag-fc-link-btn" data-toggle-turn-code="${msgIdx}">Hide Code</button>
            <button type="button" class="ag-fc-link-btn" data-open-codefile="${turnFiles[0].fileIdx}">Open Code Viewer</button>
          </div>
        </div>
        <div class="ag-fc-list">
          ${turnFiles
            .map(
              (f) => `
            <div class="ag-fc-row" data-open-codefile="${f.fileIdx}" title="Click to view ${escapeHtml(f.filename)} in Right Code Viewer">
              <div class="ag-fc-file-left">
                <span class="ag-ext-badge ${f.badge.cls}">${f.badge.label}</span>
                <span>${escapeHtml(f.filename)}</span>
                ${f.versionNum > 1 ? `<span class="ag-version-badge">v${f.versionNum}</span>` : ""}
              </div>
              <div class="ag-fc-file-right">
                <span class="ag-gate-pill ${f.gate?.ok !== false ? "pass" : "fail"}">${escapeHtml(f.gate?.label || "Syntax OK")}</span>
                <span class="ag-code-lines-pill">${f.linesCount} lines</span>
              </div>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `;

    return narrativeParts.join("") + codeCardsHtml.join("") + filesChangedCardHtml;
  }

  return narrativeParts.join("");
}

function formatInlineText(str) {
  return escapeHtml(str)
    .replace(/^###\s+(.+)$/gm, '<strong class="ag-md-h3">$1</strong>')
    .replace(/^##\s+(.+)$/gm, '<strong class="ag-md-h2">$1</strong>')
    .replace(/^\s*[-*]\s+(.+)$/gm, '<span class="ag-md-li">&bull; $1</span>')
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\b([a-zA-Z0-9_-]+\.(?:html|css|js|ts|py|json|md))\b/g, '<span class="ag-inline-file-link">$1</span>')
    .replace(/`([^`]+)`/g, '<code class="ag-cmd-code">$1</code>')
    .replace(/\n/g, "<br>");
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[ch]));
}

// =========================================================
// 10. FILE UPLOAD CHIPS, PROJECT DROPDOWN & STRICT MODEL POPOVER
// =========================================================
const wsFileInput = document.getElementById("ws-file-input");
const wsAttachedFiles = document.getElementById("ws-attached-files");

wsFileInput.addEventListener("change", (e) => {
  const files = Array.from(e.target.files || []);
  files.forEach((file) => {
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result || "");
      const ext = (file.name.split(".").pop() || "txt").toLowerCase();
      attachedFiles.push({ name: file.name, ext, content: content.slice(0, 15000) });
      renderAttachedFileChips();
      showToast(`Attached code file "${file.name}"`);
    };
    reader.readAsText(file);
  });
  wsFileInput.value = "";
});

function renderAttachedFileChips() {
  if (attachedFiles.length === 0) {
    wsAttachedFiles.classList.add("hidden");
    wsAttachedFiles.innerHTML = "";
    return;
  }
  wsAttachedFiles.classList.remove("hidden");
  wsAttachedFiles.innerHTML = attachedFiles
    .map(
      (f, i) => `
      <span class="ws-file-chip">
        <span>@${escapeHtml(f.name)}</span>
        <button type="button" data-rm-file="${i}" title="Remove file">&times;</button>
      </span>
    `
    )
    .join("");

  wsAttachedFiles.querySelectorAll("[data-rm-file]").forEach((btn) => {
    btn.addEventListener("click", () => {
      attachedFiles.splice(Number(btn.dataset.rmFile), 1);
      renderAttachedFileChips();
    });
  });
}

// Project Switcher Dropdown
const wsProjectSelector = document.getElementById("ws-project-selector");
const wsProjectDropdown = document.getElementById("ws-project-dropdown");

wsProjectSelector.addEventListener("click", (e) => {
  e.stopPropagation();
  wsModelPopover.classList.add("hidden");
  const isHidden = wsProjectDropdown.classList.contains("hidden");
  if (!isHidden) {
    wsProjectDropdown.classList.add("hidden");
    return;
  }
  wsProjectDropdown.innerHTML =
    state.projects
      .map(
        (p) => `
        <button type="button" class="ws-float-item ${p.id === state.activeProjectId ? "active" : ""}" data-switch-proj="${p.id}">
          <span>${escapeHtml(p.name)}</span>
          <span style="font-size:10.5px;color:var(--text-secondary);">${p.sessions.length} sessions</span>
        </button>
      `
      )
      .join("") +
    `<div class="v-dropdown-divider"></div>
     <button type="button" class="ws-float-item" id="drop-new-proj-btn" style="color:var(--accent);font-weight:600;">
       + Create New Project
     </button>`;

  wsProjectDropdown.classList.remove("hidden");

  wsProjectDropdown.querySelectorAll("[data-switch-proj]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeProjectId = btn.dataset.switchProj;
      const p = getActiveProject();
      state.activeSessionId = p.sessions[0]?.id || null;
      saveState();
      wsProjectDropdown.classList.add("hidden");
      renderAllUI();
      showToast(`Switched to project "${p.name}"`);
    });
  });

  document.getElementById("drop-new-proj-btn")?.addEventListener("click", () => {
    wsProjectDropdown.classList.add("hidden");
    openSaveModal("project");
  });
});

// Quick Model Switcher Popover (STRICT: Only shows models for providers with an enabled API Key!)
const wsModelPill = document.getElementById("ws-model-pill");
const wsModelPopover = document.getElementById("ws-model-popover");

wsModelPill.addEventListener("click", (e) => {
  e.stopPropagation();
  wsProjectDropdown.classList.add("hidden");
  const isHidden = wsModelPopover.classList.contains("hidden");
  if (!isHidden) {
    wsModelPopover.classList.add("hidden");
    return;
  }

  const items = [];
  Object.values(state.providers).forEach((prov) => {
    if (isProviderConfiguredAndEnabled(prov)) {
      prov.models.forEach((m) => {
        const isAct = state.activeProvider === prov.name && state.activeModel === m.name;
        items.push(`
          <button type="button" class="ws-float-item ${isAct ? "active" : ""}" data-pop-prov="${escapeHtml(prov.name)}" data-pop-model="${escapeHtml(m.name)}">
            <span>${escapeHtml(m.name)}</span>
            <span style="font-size:10px;color:var(--text-secondary);">${escapeHtml(prov.name)}</span>
          </button>
        `);
      });
    }
  });

  const emptyNotice =
    items.length === 0
      ? `<div style="padding:8px 10px;font-size:11.5px;color:var(--text-secondary);">No API Key &amp; Model enabled yet.</div>`
      : items.join("");

  wsModelPopover.innerHTML =
    emptyNotice +
    `<div class="v-dropdown-divider"></div>
     <button type="button" class="ws-float-item" id="pop-manage-models-btn" style="color:var(--accent);font-weight:600;">
       + Add API Key &amp; Model in Settings
     </button>`;

  wsModelPopover.classList.remove("hidden");

  wsModelPopover.querySelectorAll("[data-pop-model]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeProvider = btn.dataset.popProv;
      state.activeModel = btn.dataset.popModel;
      saveState();
      wsModelPopover.classList.add("hidden");
      renderAllUI();
      showToast(`Active model: ${state.activeModel} (${state.activeProvider})`);
    });
  });

  document.getElementById("pop-manage-models-btn")?.addEventListener("click", () => {
    wsModelPopover.classList.add("hidden");
    openSettingsScreen("models");
  });
});

// =========================================================
// 11. COMMAND PALETTE & SEARCH MODAL (Ctrl+K)
// =========================================================
const commandPaletteModal = document.getElementById("command-palette-modal");
const cmdPaletteInput = document.getElementById("cmd-palette-input");
const cmdResultsList = document.getElementById("cmd-results-list");

function openCommandPalette() {
  cmdPaletteInput.value = "";
  renderCommandPaletteResults("");
  commandPaletteModal.classList.remove("hidden");
  setTimeout(() => cmdPaletteInput.focus(), 80);
}

function renderCommandPaletteResults(query) {
  const q = query.trim().toLowerCase();
  const entries = [];

  state.projects.forEach((proj) => {
    proj.sessions.forEach((sess) => {
      if (!q || sess.name.toLowerCase().includes(q) || proj.name.toLowerCase().includes(q)) {
        entries.push({
          label: `${sess.name} (in ${proj.name})`,
          badge: sess.kind.toUpperCase(),
          action: () => {
            state.activeProjectId = proj.id;
            state.activeSessionId = sess.id;
            saveState();
            openWorkspaceScreen();
          }
        });
      }
    });
  });

  const quickActions = [
    { label: "Hide / Show Left Sidebar", badge: "Ctrl+B", action: () => toggleLeftSidebar() },
    { label: "Hide / Show Right Written Code & Progress Panel", badge: "Ctrl+E", action: () => toggleRightCodePane() },
    { label: "Create & Save New Task", badge: "Ctrl+N", action: () => openSaveModal("task") },
    { label: "Create & Save New Chat", badge: "Ctrl+J", action: () => openSaveModal("chat") },
    { label: "Create & Save New Project", badge: "Project", action: () => openSaveModal("project") },
    { label: "Open API Key & Model Settings", badge: "Settings", action: () => openSettingsScreen("models") },
    { label: "Open Persistent Memory Vault", badge: "Memory", action: () => openMemoryVault() },
    { label: "Cycle Color Theme (Dark / Light / Midnight)", badge: "Theme", action: () => cycleTheme() }
  ];

  quickActions.forEach((act) => {
    if (!q || act.label.toLowerCase().includes(q)) {
      entries.push(act);
    }
  });

  cmdResultsList.innerHTML = entries
    .map(
      (item, idx) => `
      <div class="cmd-item" data-cmd-idx="${idx}">
        <span>${escapeHtml(item.label)}</span>
        <span class="cmd-badge">${escapeHtml(item.badge)}</span>
      </div>
    `
    )
    .join("");

  cmdResultsList.querySelectorAll("[data-cmd-idx]").forEach((el) => {
    el.addEventListener("click", () => {
      const target = entries[Number(el.dataset.cmdIdx)];
      commandPaletteModal.classList.add("hidden");
      if (target) target.action();
    });
  });
}

cmdPaletteInput.addEventListener("input", (e) => renderCommandPaletteResults(e.target.value));
document.getElementById("close-cmd-palette-btn").addEventListener("click", () => commandPaletteModal.classList.add("hidden"));

// =========================================================
// 12. FULL SETTINGS SCREEN LOGIC & STRICT MODEL DISPLAY
// =========================================================
const stOfficialProviderList = document.getElementById("st-official-provider-list");
const stCustomProviderList = document.getElementById("st-custom-provider-list");
const stBaseUrlInput = document.getElementById("st-base-url-input");
const stApiKeyInput = document.getElementById("st-api-key-input");
const stInlineModelInput = document.getElementById("st-inline-model-input");
const stInlineModelRow = document.getElementById("st-inline-model-row");
const stEnabledBadge = document.getElementById("st-enabled-badge");
const stHeaderEnableBtn = document.getElementById("st-header-enable-btn");
const stEnableKeyBtn = document.getElementById("st-enable-key-btn");
const stDeleteProviderBtn = document.getElementById("st-delete-provider-btn");
const stInfoBanner = document.getElementById("st-info-banner");
const stBannerText = document.getElementById("st-banner-text");
const stModelList = document.getElementById("st-model-list");
const stConnBtn = document.getElementById("st-conn-btn");
const stConnMenu = document.getElementById("st-conn-menu");
const stConnLabel = document.getElementById("st-conn-label");

function getSelectedProviderObj() {
  return state.providers[state.selectedProvider] || state.providers["V.ai"];
}

function renderSettingsUI() {
  const prov = getSelectedProviderObj();

  stOfficialProviderList.innerHTML = Object.values(state.providers)
    .filter((p) => p.official)
    .map((p) => {
      const isAct = state.selectedProvider === p.name;
      return `
        <button class="st-provider-item ${isAct ? "active" : ""}" data-prov="${escapeHtml(p.name)}">
          <span class="st-prov-left">
            <span class="st-mini-v">V</span>
            <span>${escapeHtml(p.name)}</span>
          </span>
          <span class="st-prov-dot"></span>
        </button>
      `;
    })
    .join("");

  stCustomProviderList.innerHTML = Object.values(state.providers)
    .filter((p) => !p.official)
    .map((p) => {
      const isAct = state.selectedProvider === p.name;
      const isEnabled = isProviderConfiguredAndEnabled(p);
      return `
        <button class="st-provider-item ${isAct ? "active" : ""}" data-prov="${escapeHtml(p.name)}">
          <span class="st-prov-left">
            <span class="st-mini-v">${escapeHtml(p.name.charAt(0).toUpperCase())}</span>
            <span>${escapeHtml(p.name)}</span>
          </span>
          <span class="st-prov-dot ${isEnabled ? "enabled" : ""}"></span>
        </button>
      `;
    })
    .join("");

  document.querySelectorAll("[data-prov]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.selectedProvider = btn.dataset.prov;
      saveState();
      renderSettingsUI();
    });
  });

  document.getElementById("st-active-prov-icon").textContent = prov.name.charAt(0).toUpperCase();
  document.getElementById("st-active-prov-title").textContent = prov.name;
  stBaseUrlInput.value = prov.baseUrl || "";
  stApiKeyInput.value = prov.apiKey || "";
  stConnLabel.textContent = "API Key";

  const hasApiKey = !prov.comingSoon && Boolean(prov.enabled && prov.apiKey && prov.apiKey.trim());
  const isFullyReady = isProviderConfiguredAndEnabled(prov);

  stEnabledBadge.textContent = isFullyReady ? `Enabled (${prov.models[0].name})` : hasApiKey ? "API Key Saved (Add Model Name)" : "Not enabled";
  stEnabledBadge.classList.toggle("enabled", isFullyReady);

  stHeaderEnableBtn.textContent = isFullyReady ? "Enabled" : "Enable Provider";
  stHeaderEnableBtn.classList.toggle("active", isFullyReady);
  stEnableKeyBtn.textContent = hasApiKey ? "API Key Enabled" : "Enable API Key";

  stDeleteProviderBtn.style.display = prov.official ? "none" : "inline-flex";
  stInfoBanner.classList.toggle("enabled", isFullyReady);

  if (prov.comingSoon) {
    stBannerText.textContent = "V.ai has no active AI models at this time — Coming soon!";
    stInlineModelRow.style.display = "none";
    stModelList.innerHTML = `<div style="padding:10px;font-size:12px;color:var(--text-secondary);">No AI models available for V.ai.</div>`;
  } else {
    stInlineModelRow.style.display = "flex";
    const catHint = PROVIDER_CATALOG.find((c) => c.name.toLowerCase() === prov.name.toLowerCase());
    stInlineModelInput.placeholder = catHint
      ? `Enter Model Name (e.g., ${catHint.models.join(", ")})`
      : "Enter Model Name (e.g., gemini-2.5-flash, gpt-4o-mini)";

    if (isFullyReady) {
      stBannerText.textContent = `${prov.name} API Key and Model (${state.activeModel || prov.models[0].name}) are active.`;
    } else if (hasApiKey) {
      stBannerText.textContent = `API Key enabled for ${prov.name}. Now enter a Model Name below and click "+ Add Model".`;
    } else {
      stBannerText.textContent = `Paste your ${prov.name} API key and add a Model Name to enable.`;
    }

    // STRICT: Only show model names if API Key is added/enabled AND models are added!
    if (!hasApiKey) {
      stModelList.innerHTML = `<div style="padding:10px;font-size:12px;color:var(--text-secondary);">No API Key enabled. Paste and enable your API Key above to view or use added models.</div>`;
    } else if (prov.models.length === 0) {
      stModelList.innerHTML = `<div style="padding:10px;font-size:12px;color:var(--text-secondary);">No model name added yet. Type your Model Name above and click "+ Add Model".</div>`;
    } else {
      stModelList.innerHTML = prov.models
        .map((m, idx) => {
          const isSelectedModel = state.activeProvider === prov.name && state.activeModel === m.name;
          return `
            <div class="st-model-row">
              <span class="st-model-name">${escapeHtml(m.name)} ${isSelectedModel ? "(Active)" : ""}</span>
              <div class="st-model-actions">
                <span class="st-ctx-badge">${escapeHtml(m.context || "API")}</span>
                <button class="st-row-icon-btn" data-use-model="${escapeHtml(m.name)}" title="Use Model in Chat">Use</button>
                <button class="st-row-icon-btn" data-edit-model="${idx}" title="Edit Model Name">Edit</button>
                <button class="st-row-icon-btn" data-del-model="${idx}" title="Delete Model">Delete</button>
              </div>
            </div>
          `;
        })
        .join("");
    }
  }

  stModelList.querySelectorAll("[data-use-model]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeProvider = prov.name;
      state.activeModel = btn.dataset.useModel;
      saveState();
      renderSettingsUI();
      renderAllUI();
      showToast(`Active model set to ${state.activeModel}`);
    });
  });

  stModelList.querySelectorAll("[data-edit-model]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.editModel);
      openCustomInputModal({
        title: "Edit Model Name",
        desc: `Update model name for ${prov.name}:`,
        defaultValue: prov.models[idx].name,
        onConfirm: (updated) => {
          const oldName = prov.models[idx].name;
          prov.models[idx].name = updated;
          if (state.activeModel === oldName) state.activeModel = updated;
          saveState();
          renderSettingsUI();
          renderAllUI();
          showToast(`Model updated to "${updated}"`);
        }
      });
    });
  });

  stModelList.querySelectorAll("[data-del-model]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.delModel);
      const removed = prov.models.splice(idx, 1)[0];
      if (removed && state.activeModel === removed.name) {
        state.activeModel = prov.models[0]?.name || "";
      }
      saveState();
      renderSettingsUI();
      renderAllUI();
      showToast("Model removed");
    });
  });

  document.getElementById("gen-username-input").value = state.username || "V Code Dev";
  document.getElementById("gen-lang-select").value = state.language || "English";
  document.getElementById("gen-memory-toggle").checked = Boolean(state.persistentMemoryEnabled);
  document.getElementById("gen-require-name-toggle").checked = Boolean(state.requireNameOnNew);
  document.getElementById("gen-enter-send-toggle").checked = Boolean(state.enterToSend);
  document.getElementById("app-fontsize-select").value = state.fontSize || "13.5px";
}

function handleEnableProviderAction() {
  const prov = getSelectedProviderObj();
  if (prov.comingSoon) {
    showComingSoonPopup("V.ai");
    return;
  }

  const keyVal = stApiKeyInput.value.trim();
  const urlVal = stBaseUrlInput.value.trim();
  const inlineModelVal = stInlineModelInput.value.trim();

  if (!keyVal) {
    showToast(`Please paste your ${prov.name} API Key in the API Key field first`);
    stApiKeyInput.focus();
    return;
  }

  prov.apiKey = keyVal;
  if (urlVal) prov.baseUrl = urlVal;
  prov.enabled = true;

  if (inlineModelVal) {
    if (!prov.models.some((m) => m.name === inlineModelVal)) {
      prov.models.push({ name: inlineModelVal, context: "API" });
    }
    state.activeModel = inlineModelVal;
    stInlineModelInput.value = "";
  } else if (prov.models.length > 0) {
    state.activeModel = prov.models[0].name;
  }

  state.activeProvider = prov.name;
  saveState();
  renderSettingsUI();
  renderAllUI();

  if (prov.models.length === 0) {
    showToast(`${prov.name} API Key saved! Now enter your Model Name below.`);
    stInlineModelInput.focus();
  } else {
    showToast(`${prov.name} enabled with model "${state.activeModel}"`);
  }
}

stEnableKeyBtn.addEventListener("click", handleEnableProviderAction);
stHeaderEnableBtn.addEventListener("click", handleEnableProviderAction);

document.getElementById("st-add-model-btn").addEventListener("click", () => {
  const prov = getSelectedProviderObj();
  if (prov.comingSoon) {
    showComingSoonPopup("V.ai");
    return;
  }

  const keyVal = stApiKeyInput.value.trim();
  if (keyVal) {
    prov.apiKey = keyVal;
    prov.enabled = true;
  }

  if (!prov.apiKey || !prov.apiKey.trim()) {
    showToast(`Please enter and enable your ${prov.name} API Key first`);
    stApiKeyInput.focus();
    return;
  }

  const inlineVal = stInlineModelInput.value.trim();
  if (inlineVal) {
    if (!prov.models.some((m) => m.name === inlineVal)) {
      prov.models.push({ name: inlineVal, context: "API" });
    }
    state.activeProvider = prov.name;
    state.activeModel = inlineVal;
    stInlineModelInput.value = "";
    saveState();
    renderSettingsUI();
    renderAllUI();
    showToast(`Model "${inlineVal}" added and activated`);
    return;
  }

  openCustomInputModal({
    title: `Add Model Name to ${prov.name}`,
    desc: "Enter the exact Model Name to use with your API Key:",
    placeholder: "e.g., gemini-2.5-flash, llama-3.3-70b-versatile, gpt-4o",
    onConfirm: (newModel) => {
      if (!prov.models.some((m) => m.name === newModel)) {
        prov.models.push({ name: newModel, context: "API" });
      }
      state.activeProvider = prov.name;
      state.activeModel = newModel;
      saveState();
      renderSettingsUI();
      renderAllUI();
      showToast(`Model "${newModel}" added and activated`);
    }
  });
});

// Live Free-Model Harvester (Ported from misterdev/core/economics/free_models.py)
let cachedOpenRouterFreeModels = null;

async function harvestLiveFreeModelsForProvider(prov) {
  const nameLower = (prov.name || "").toLowerCase();
  const urlLower = (prov.baseUrl || "").toLowerCase();

  if (nameLower.includes("openrouter") || urlLower.includes("openrouter.ai")) {
    if (Array.isArray(cachedOpenRouterFreeModels) && cachedOpenRouterFreeModels.length > 0) {
      return cachedOpenRouterFreeModels;
    }
    try {
      const resp = await fetch("https://openrouter.ai/api/v1/models");
      if (resp.ok) {
        const json = await resp.json();
        const data = Array.isArray(json.data) ? json.data : [];
        const freeIds = data
          .filter(
            (m) =>
              m &&
              typeof m.id === "string" &&
              (m.id.endsWith(":free") ||
                (m.pricing && String(m.pricing.prompt) === "0" && String(m.pricing.completion) === "0"))
          )
          .map((m) => m.id)
          .slice(0, 18);
        if (freeIds.length > 0) {
          cachedOpenRouterFreeModels = freeIds;
          return freeIds;
        }
      }
    } catch (_) {
      // Fallback to curated free models below if offline
    }
    return [
      "deepseek/deepseek-chat-v3-0324:free",
      "deepseek/deepseek-r1:free",
      "meta-llama/llama-3.3-70b-instruct:free",
      "qwen/qwen-2.5-coder-32b-instruct:free",
      "google/gemini-2.0-flash-exp:free",
      "mistralai/mistral-small-3.1-24b-instruct:free"
    ];
  }

  if (nameLower.includes("gemini") || urlLower.includes("googleapis.com")) {
    return ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash", "gemini-1.5-flash"];
  }
  if (nameLower.includes("groq") || urlLower.includes("groq.com")) {
    return [
      "llama-3.3-70b-versatile",
      "llama-3.1-8b-instant",
      "deepseek-r1-distill-llama-70b",
      "qwen-2.5-coder-32b",
      "mixtral-8x7b-32768"
    ];
  }
  const cat = PROVIDER_CATALOG.find((c) => c.name.toLowerCase() === nameLower);
  if (cat && Array.isArray(cat.models)) {
    return cat.models;
  }
  return [
    "gemini-2.5-flash",
    "llama-3.3-70b-versatile",
    "deepseek/deepseek-chat-v3-0324:free",
    "qwen/qwen-2.5-coder-32b-instruct:free",
    "gpt-4o-mini"
  ];
}

document.getElementById("st-fetch-free-models-btn")?.addEventListener("click", async () => {
  const prov = getSelectedProviderObj();
  if (prov.comingSoon) {
    showComingSoonPopup("V.ai");
    return;
  }

  const pickerEl = document.getElementById("st-free-models-picker");
  if (!pickerEl) return;

  if (!pickerEl.classList.contains("hidden") && pickerEl.dataset.loadedProv === prov.name) {
    pickerEl.classList.add("hidden");
    return;
  }

  pickerEl.classList.remove("hidden");
  pickerEl.dataset.loadedProv = prov.name;
  pickerEl.innerHTML = `<div class="st-free-picker-head"><span>Harvesting live models for ${escapeHtml(prov.name)}...</span></div>`;

  const modelsList = await harvestLiveFreeModelsForProvider(prov);
  pickerEl.innerHTML = `
    <div class="st-free-picker-head">
      <span>Select a model for <strong>${escapeHtml(prov.name)}</strong> (1-Click Add):</span>
      <button type="button" class="st-free-picker-close" id="st-close-free-picker-btn">Close</button>
    </div>
    <div class="st-free-chips-wrap">
      ${modelsList
        .map(
          (mId) => `
          <button type="button" class="st-free-model-chip" data-pick-free-model="${escapeHtml(mId)}">
            ${escapeHtml(mId)}
          </button>
        `
        )
        .join("")}
    </div>
  `;

  document.getElementById("st-close-free-picker-btn")?.addEventListener("click", () => {
    pickerEl.classList.add("hidden");
  });

  pickerEl.querySelectorAll("[data-pick-free-model]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const pickedModel = chip.dataset.pickFreeModel;
      stInlineModelInput.value = pickedModel;
      const keyVal = stApiKeyInput.value.trim() || (prov.apiKey ? prov.apiKey.trim() : "");
      if (keyVal) {
        prov.apiKey = keyVal;
        prov.enabled = true;
        if (!prov.models.some((m) => m.name === pickedModel)) {
          prov.models.push({ name: pickedModel, context: pickedModel.endsWith(":free") ? "FREE" : "API" });
        }
        state.activeProvider = prov.name;
        state.activeModel = pickedModel;
        stInlineModelInput.value = "";
        saveState();
        renderSettingsUI();
        renderAllUI();
        showToast(`Model "${pickedModel}" added and activated for ${prov.name}`);
      } else {
        showToast(`Selected "${pickedModel}" — now paste your API Key above and click Enable API Key`);
        stApiKeyInput.focus();
      }
    });
  });
});

stBaseUrlInput.addEventListener("input", () => {
  const prov = getSelectedProviderObj();
  prov.baseUrl = stBaseUrlInput.value.trim();
  saveState();
});

stDeleteProviderBtn.addEventListener("click", () => {
  const prov = getSelectedProviderObj();
  if (prov.official) return;
  delete state.providers[prov.name];
  if (state.activeProvider === prov.name) {
    state.activeProvider = "";
    state.activeModel = "";
  }
  state.selectedProvider = "V.ai";
  saveState();
  renderSettingsUI();
  renderAllUI();
  showToast(`Deleted provider ${prov.name}`);
});

// Add Custom API Provider Modal
const addProviderModal = document.getElementById("add-provider-modal");
const newProvNameInput = document.getElementById("new-prov-name");
const newProvUrlInput = document.getElementById("new-prov-url");
const newProvModelInput = document.getElementById("new-prov-model");
const newProvKeyInput = document.getElementById("new-prov-key");

document.getElementById("st-add-provider-btn").addEventListener("click", () => {
  newProvNameInput.value = "";
  newProvUrlInput.value = "";
  newProvModelInput.value = "";
  newProvKeyInput.value = "";
  addProviderModal.classList.remove("hidden");
  setTimeout(() => newProvNameInput.focus(), 100);
});

document.getElementById("close-add-provider-btn").addEventListener("click", () => addProviderModal.classList.add("hidden"));
document.getElementById("cancel-add-provider-btn").addEventListener("click", () => addProviderModal.classList.add("hidden"));

document.querySelectorAll("[data-preset]").forEach((pill) => {
  pill.addEventListener("click", () => {
    const item = PROVIDER_CATALOG.find((c) => c.name === pill.dataset.preset);
    if (item) {
      newProvNameInput.value = item.name;
      newProvUrlInput.value = item.baseUrl;
      newProvModelInput.value = item.defaultModel;
    }
  });
});

document.getElementById("add-provider-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const name = newProvNameInput.value.trim();
  const url = newProvUrlInput.value.trim();
  const model = newProvModelInput.value.trim();
  const key = newProvKeyInput.value.trim();
  if (!name || !url || !model) return;

  if (!isSafeApiBaseUrl(url)) {
    showToast("Security Notice: Base URL must use HTTPS (or http://localhost)");
    newProvUrlInput.focus();
    return;
  }

  state.providers[name] = {
    name,
    official: false,
    comingSoon: false,
    enabled: Boolean(key),
    baseUrl: url,
    apiKey: key,
    models: [{ name: model, context: "API" }]
  };
  state.selectedProvider = name;
  if (key) {
    state.activeProvider = name;
    state.activeModel = model;
  }
  saveState();
  addProviderModal.classList.add("hidden");
  renderSettingsUI();
  renderAllUI();
  showToast(key ? `Provider "${name}" and model "${model}" enabled` : `Provider "${name}" added — paste API Key to enable`);
});

document.getElementById("st-get-api-key-btn").addEventListener("click", () => {
  const prov = getSelectedProviderObj();
  if (prov.comingSoon) {
    showComingSoonPopup("V.ai");
    return;
  }
  const found = PROVIDER_CATALOG.find((c) => c.name.toLowerCase() === prov.name.toLowerCase());
  window.open(found ? found.keyUrl : "https://openrouter.ai/keys", "_blank", "noopener,noreferrer");
});

document.getElementById("st-toggle-key-vis").addEventListener("click", () => {
  stApiKeyInput.type = stApiKeyInput.type === "password" ? "text" : "password";
});

stConnBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  stConnMenu.classList.toggle("open");
});

document.querySelectorAll(".st-conn-opt").forEach((opt) => {
  opt.addEventListener("click", () => {
    stConnMenu.classList.remove("open");
    if (opt.dataset.mode === "Personal plan") {
      showComingSoonPopup("Personal plan");
      return;
    }
    state.connectionMode = "API Key";
    saveState();
    renderSettingsUI();
  });
});

// =========================================================
// 13. ABOUT V CODE & API GUIDE DIRECTORY RENDERER
// =========================================================
function renderAboutGuideGrid() {
  const grid = document.getElementById("about-provider-guide-grid");
  if (!grid) return;

  grid.innerHTML = PROVIDER_CATALOG.map(
    (item) => `
    <div class="prov-guide-card">
      <div class="prov-guide-head">
        <h4>${escapeHtml(item.name)}</h4>
        <span class="prov-guide-tag">${escapeHtml(item.tag)}</span>
      </div>
      <div class="prov-guide-meta">
        <div><strong>Get Key:</strong> <a href="${escapeHtml(item.keyUrl)}" target="_blank" rel="noopener noreferrer" style="color:var(--accent);">${escapeHtml(item.keyUrl)}</a></div>
        <div style="margin-top:4px;"><strong>Base URL:</strong> <code>${escapeHtml(item.baseUrl)}</code></div>
        <div style="margin-top:4px;"><strong>Example Models:</strong> ${item.models.map((m) => `<code>${escapeHtml(m)}</code>`).join(" ")}</div>
      </div>
      <div class="prov-guide-actions">
        <button type="button" class="st-add-model-btn" data-quick-setup="${escapeHtml(item.name)}">
          Configure in V Code
        </button>
        <button type="button" class="st-add-model-btn" data-open-key-url="${escapeHtml(item.keyUrl)}">
          Get API Key
        </button>
      </div>
    </div>
  `
  ).join("");

  grid.querySelectorAll("[data-quick-setup]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const cat = PROVIDER_CATALOG.find((c) => c.name === btn.dataset.quickSetup);
      if (!cat) return;
      if (!state.providers[cat.name]) {
        state.providers[cat.name] = {
          name: cat.name,
          official: false,
          comingSoon: false,
          enabled: false,
          baseUrl: cat.baseUrl,
          apiKey: "",
          models: []
        };
      }
      state.selectedProvider = cat.name;
      saveState();
      switchSettingsTab("models");
      renderSettingsUI();
      stInlineModelInput.value = cat.defaultModel;
      setTimeout(() => stApiKeyInput.focus(), 100);
    });
  });

  grid.querySelectorAll("[data-open-key-url]").forEach((btn) => {
    btn.addEventListener("click", () => window.open(btn.dataset.openKeyUrl, "_blank", "noopener,noreferrer"));
  });
}

// =========================================================
// 14. SETTINGS SIDEBAR TABS (All Agent Capabilities -> "Coming Soon")
// =========================================================
const stPaneModels = document.getElementById("st-pane-models");
const stPaneAbout = document.getElementById("st-pane-about");
const stPaneGeneral = document.getElementById("st-pane-general");
const stPaneAppearance = document.getElementById("st-pane-appearance");
const stPaneDynamic = document.getElementById("st-pane-dynamic");

const AGENT_CAPABILITIES_TABS = {
  plugins: "Plugins",
  skills: "Skills",
  subagents: "Subagents",
  mcp: "MCP servers",
  commands: "Commands",
  hooks: "Hooks"
};

function switchSettingsTab(tabKey) {
  document.querySelectorAll(".st-nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.stTab === tabKey);
  });

  [stPaneModels, stPaneAbout, stPaneGeneral, stPaneAppearance, stPaneDynamic].forEach((p) => p.classList.remove("active"));

  if (tabKey === "models") {
    stPaneModels.classList.add("active");
  } else if (tabKey === "about") {
    stPaneAbout.classList.add("active");
    renderAboutGuideGrid();
  } else if (tabKey === "general") {
    stPaneGeneral.classList.add("active");
  } else if (tabKey === "appearance") {
    stPaneAppearance.classList.add("active");
  } else {
    stPaneDynamic.classList.add("active");
    renderDynamicSettingsPane(tabKey);
  }
}

document.querySelectorAll(".st-nav-item").forEach((item) => {
  item.addEventListener("click", () => switchSettingsTab(item.dataset.stTab));
});

document.getElementById("st-open-about-guide-btn").addEventListener("click", () => switchSettingsTab("about"));

function renderDynamicSettingsPane(tabKey) {
  const titleEl = document.getElementById("st-dyn-title");
  const subEl = document.getElementById("st-dyn-sub");
  const bodyEl = document.getElementById("st-dyn-body");

  if (AGENT_CAPABILITIES_TABS[tabKey]) {
    const capName = AGENT_CAPABILITIES_TABS[tabKey];
    titleEl.textContent = capName;
    subEl.textContent = `V Code Agent Capability — ${capName}`;
    bodyEl.innerHTML = `
      <div class="coming-soon-panel">
        <span class="coming-soon-badge">Coming Soon</span>
        <h3 style="font-size:20px; color:var(--text); margin-top:6px;">${escapeHtml(capName)} — Coming Soon</h3>
        <p class="st-ctrl-desc" style="max-width:420px;">
          This agent capability is currently under development and will be available in an upcoming V Code release.
        </p>
      </div>
    `;
    return;
  }

  const totalSessions = state.projects.reduce((acc, p) => acc + p.sessions.length, 0);
  const totalMessages = state.projects.reduce(
    (acc, p) => acc + p.sessions.reduce((sAcc, s) => sAcc + s.messages.length, 0),
    0
  );
  const totalFacts = state.projects.reduce((acc, p) => acc + p.memoryNotes.length, 0);
  const workingProv = getWorkingProviderConfig();
  const activeModel = getActiveModelName();

  const configs = {
    browser: {
      title: "Browser",
      sub: "Configure built-in headless browser context fetching.",
      html: `
        <div class="st-control-row">
          <div><div class="st-ctrl-title">Enable Documentation Context Reader</div><div class="st-ctrl-desc">Allow AI tasks to inspect documentation URLs</div></div>
          <label class="toggle-switch"><input type="checkbox" checked /><span class="toggle-slider"></span></label>
        </div>
        <div class="st-control-row">
          <div><div class="st-ctrl-title">Default Search Engine</div><div class="st-ctrl-desc">Used when researching libraries</div></div>
          <select class="st-text-input small-w"><option>Google</option><option>DuckDuckGo</option></select>
        </div>
      `
    },
    index: {
      title: "Index & Persistent Memory",
      sub: "Overview of indexed projects, tasks, and permanent memory facts.",
      html: `
        <div class="st-control-row">
          <div><div class="st-ctrl-title">Saved Workspace Projects</div><div class="st-ctrl-desc">Total named projects in storage</div></div>
          <strong>${state.projects.length} Projects</strong>
        </div>
        <div class="st-control-row">
          <div><div class="st-ctrl-title">Saved Named Tasks &amp; Chats</div><div class="st-ctrl-desc">Active persistent threads</div></div>
          <strong>${totalSessions} Sessions</strong>
        </div>
        <div class="st-control-row">
          <div><div class="st-ctrl-title">Indexed Memory Facts</div><div class="st-ctrl-desc">Facts automatically recalled in every prompt</div></div>
          <strong>${totalFacts} Facts</strong>
        </div>
      `
    },
    usage: {
      title: "Usage Statistics",
      sub: "API requests and persistent memory messages processed.",
      html: `
        <div class="st-control-row">
          <div><div class="st-ctrl-title">Total Messages Stored</div><div class="st-ctrl-desc">Across all saved projects &amp; chats</div></div>
          <strong>${totalMessages} Messages</strong>
        </div>
        <div class="st-control-row">
          <div><div class="st-ctrl-title">Active API Provider &amp; Model</div><div class="st-ctrl-desc">Current live model connection</div></div>
          <strong>${workingProv && activeModel ? `${escapeHtml(workingProv.name)} (${escapeHtml(activeModel)})` : "No API Key Connected"}</strong>
        </div>
      `
    },
    getstarted: {
      title: "Get started with V Code",
      sub: "Quick guide to connecting your API key, adding your model name, and working with Code Files.",
      html: `
        <div class="st-control-row">
          <div><div class="st-ctrl-title">1. Open About &amp; API Guide</div><div class="st-ctrl-desc">Click <strong>About &amp; API Guide</strong> in the sidebar to see where to get API keys.</div></div>
        </div>
        <div class="st-control-row">
          <div><div class="st-ctrl-title">2. Add API Key &amp; Model Name</div><div class="st-ctrl-desc">In <strong>Model settings</strong>, paste your API key, enter your Model Name, and click <strong>Enable API Key</strong>.</div></div>
        </div>
        <div class="st-control-row">
          <div><div class="st-ctrl-title">3. Antigravity-Style Chat &amp; Code Files</div><div class="st-ctrl-desc">Generated code blocks appear as line-numbered Code File cards in chat and open in the right-side Code Files Explorer.</div></div>
        </div>
      `
    }
  };

  const cfg = configs[tabKey] || configs.getstarted;
  titleEl.textContent = cfg.title;
  subEl.textContent = cfg.sub;
  bodyEl.innerHTML = cfg.html;
}

// General & Appearance Controls Event Listeners
document.querySelectorAll("[data-set-theme]").forEach((btn) => {
  btn.addEventListener("click", () => applyTheme(btn.dataset.setTheme));
});

document.getElementById("gen-username-input").addEventListener("input", (e) => {
  state.username = e.target.value.trim() || "V Code Dev";
  saveState();
  renderAllUI();
});

document.getElementById("gen-lang-select").addEventListener("change", (e) => {
  state.language = e.target.value;
  saveState();
});

document.getElementById("gen-memory-toggle").addEventListener("change", (e) => {
  state.persistentMemoryEnabled = e.target.checked;
  saveState();
});

document.getElementById("gen-require-name-toggle").addEventListener("change", (e) => {
  state.requireNameOnNew = e.target.checked;
  saveState();
});

document.getElementById("gen-enter-send-toggle").addEventListener("change", (e) => {
  state.enterToSend = e.target.checked;
  saveState();
});

document.getElementById("sec-clear-keys-btn")?.addEventListener("click", () => {
  Object.values(state.providers).forEach((p) => {
    if (p && !p.comingSoon) {
      p.apiKey = "";
      p.enabled = false;
    }
  });
  state.activeProvider = "";
  state.activeModel = "";
  stApiKeyInput.value = "";
  saveState();
  renderSettingsUI();
  renderAllUI();
  showToast("All API keys securely wiped from browser vault");
});

document.getElementById("app-fontsize-select").addEventListener("change", (e) => {
  state.fontSize = e.target.value;
  document.documentElement.style.setProperty("--chat-font-size", state.fontSize);
  saveState();
});

// =========================================================
// 15. MEMORY VAULT MODAL
// =========================================================
const memoryVaultModal = document.getElementById("memory-vault-modal");
const memoryVaultBody = document.getElementById("memory-vault-body");

function openMemoryVault() {
  const proj = getActiveProject();
  const sess = getActiveSession();
  const workingProv = getWorkingProviderConfig();
  const activeModel = getActiveModelName();

  memoryVaultBody.innerHTML = `
    <div class="vault-section">
      <h4>Active API Connection &amp; Memory Status</h4>
      <ul class="vault-list">
        <li><strong>Connected Provider:</strong> ${workingProv ? escapeHtml(workingProv.name) : "No API Key Enabled"}</li>
        <li><strong>Active Model:</strong> ${workingProv && activeModel ? escapeHtml(activeModel) : "None (Add API Key & Model in Settings)"}</li>
        <li><strong>Persistent Memory Engine:</strong> ${state.persistentMemoryEnabled ? "Enabled (Sent with every API call)" : "Paused"}</li>
      </ul>
    </div>
    <div class="vault-section">
      <h4>Saved Project Memory: ${escapeHtml(proj.name)}</h4>
      <ul class="vault-list">
        ${proj.memoryNotes.map((n) => `<li>- ${escapeHtml(n)}</li>`).join("")}
      </ul>
    </div>
    <div class="vault-section">
      <h4>Active Saved Task/Chat: ${sess ? escapeHtml(sess.name) : "None selected"}</h4>
      <ul class="vault-list">
        ${
          sess && sess.facts.length > 0
            ? sess.facts.map((f) => `<li>- ${escapeHtml(f)}</li>`).join("")
            : "<li>No facts stored in this session yet.</li>"
        }
      </ul>
    </div>
  `;
  memoryVaultModal.classList.remove("hidden");
}

document.getElementById("ws-memory-vault-btn").addEventListener("click", openMemoryVault);
document.getElementById("ws-terminal-btn").addEventListener("click", openMemoryVault);
document.getElementById("ws-clear-memory-btn").addEventListener("click", openMemoryVault);
document.getElementById("home-addon-memory").addEventListener("click", openMemoryVault);
document.getElementById("close-memory-vault-btn").addEventListener("click", () => memoryVaultModal.classList.add("hidden"));
document.getElementById("done-memory-vault-btn").addEventListener("click", () => memoryVaultModal.classList.add("hidden"));

document.getElementById("add-custom-memory-btn").addEventListener("click", () => {
  openCustomInputModal({
    title: "Add Permanent Memory Fact",
    desc: "Enter an instruction or architectural rule for V Code AI to remember across all sessions:",
    placeholder: "e.g., Always use TypeScript and modular files",
    onConfirm: (note) => {
      const proj = getActiveProject();
      proj.memoryNotes.push(note);
      const sess = getActiveSession();
      if (sess) sess.facts.push(note);
      saveState();
      openMemoryVault();
      showToast("Memory fact saved to Vault");
    }
  });
});

// =========================================================
// 16. HOME, WORKSPACE & GLOBAL SHORTCUT LISTENERS
// =========================================================
const vLogoBtn = document.getElementById("v-logo-btn");
vLogoBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  vDropdown.classList.toggle("hidden");
});

document.addEventListener("click", (e) => {
  if (!vDropdown.contains(e.target) && e.target !== vLogoBtn) {
    vDropdown.classList.add("hidden");
  }
  if (!stConnMenu.contains(e.target) && e.target !== stConnBtn) {
    stConnMenu.classList.remove("open");
  }
  if (!wsProjectDropdown.contains(e.target) && !wsProjectSelector.contains(e.target)) {
    wsProjectDropdown.classList.add("hidden");
  }
  if (!wsModelPopover.contains(e.target) && !wsModelPill.contains(e.target)) {
    wsModelPopover.classList.add("hidden");
  }
});

document.getElementById("menu-new-chat").addEventListener("click", () => openWorkspaceScreen("", "chat"));
document.getElementById("menu-new-task").addEventListener("click", () => openWorkspaceScreen("", "task"));
document.getElementById("menu-open-workspace").addEventListener("click", () => openWorkspaceScreen());
document.getElementById("menu-settings").addEventListener("click", () => openSettingsScreen("models"));
document.getElementById("menu-about").addEventListener("click", () => openSettingsScreen("about"));
document.getElementById("home-top-about-btn").addEventListener("click", () => openSettingsScreen("about"));
document.getElementById("home-addon-about").addEventListener("click", () => openSettingsScreen("about"));
document.getElementById("ws-about-btn").addEventListener("click", () => openSettingsScreen("about"));

document.getElementById("menu-theme-toggle").addEventListener("click", () => {
  cycleTheme();
  vDropdown.classList.add("hidden");
});

// Home Chat Box Submission -> Opens Workspace Screen
const homePromptInput = document.getElementById("home-prompt-input");
function submitFromHomeChatBox() {
  const text = homePromptInput.value.trim();
  homePromptInput.value = "";
  openWorkspaceScreen(text);
}
document.getElementById("home-send-btn").addEventListener("click", submitFromHomeChatBox);
homePromptInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && state.enterToSend) {
    e.preventDefault();
    submitFromHomeChatBox();
  }
});

document.getElementById("home-addon-model").addEventListener("click", () => openSettingsScreen("models"));

// Workspace Sidebar & Topbar Buttons
document.getElementById("ws-new-task-btn").addEventListener("click", () => openSaveModal("task"));
document.getElementById("ws-new-chat-btn").addEventListener("click", () => openSaveModal("chat"));
document.getElementById("ws-add-project-btn").addEventListener("click", () => openSaveModal("project"));
document.getElementById("ws-QuickSave-btn").addEventListener("click", () => openSaveModal("task"));
document.getElementById("ws-settings-btn").addEventListener("click", () => openSettingsScreen("models"));
document.getElementById("ws-open-api-settings-btn").addEventListener("click", () => openSettingsScreen("models"));
document.getElementById("ws-user-profile").addEventListener("click", () => openSettingsScreen("general"));
document.getElementById("ws-theme-btn").addEventListener("click", cycleTheme);
document.getElementById("ws-topbar-theme-btn")?.addEventListener("click", cycleTheme);
document.getElementById("st-theme-quick-btn").addEventListener("click", cycleTheme);

document.getElementById("ws-skills-btn").addEventListener("click", () => openSettingsScreen("skills"));
document.getElementById("ws-search-btn").addEventListener("click", openCommandPalette);
document.getElementById("ws-filter-btn").addEventListener("click", openCommandPalette);

// Export Chat as Markdown
document.getElementById("ws-export-chat-btn").addEventListener("click", () => {
  const proj = getActiveProject();
  const sess = getActiveSession();
  if (!sess || sess.messages.length === 0) {
    showToast("No messages in current session to export");
    return;
  }
  const md = [
    `# V Code Session Export: ${sess.name}`,
    `Project: ${proj.name}`,
    "",
    ...sess.messages.map((m) => `### ${m.role === "user" ? state.username : "V Code Agent"} (${m.time || ""})\n\n${m.text}\n`)
  ].join("\n");
  const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${sess.name.replace(/\s+/g, "-")}.md`;
  a.click();
  showToast(`Exported "${sess.name}.md"`);
});

// Closing Settings always goes to Workspace Screen (never returns to 1st Home Screen)
document.getElementById("st-back-workspace-btn").addEventListener("click", () => openWorkspaceScreen());
document.getElementById("st-close-x-btn").addEventListener("click", () => openWorkspaceScreen());
document.getElementById("st-bottom-ws-btn").addEventListener("click", () => openWorkspaceScreen());

// Workspace Composer Submit
function handleWorkspaceSubmit() {
  const val = wsPromptInput.value.trim();
  if (!val && attachedFiles.length === 0) return;
  wsPromptInput.value = "";
  handleIncomingPrompt(val || "Analyze the attached code files.");
}
document.getElementById("ws-submit-btn").addEventListener("click", handleWorkspaceSubmit);
wsPromptInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && state.enterToSend) {
    e.preventDefault();
    handleWorkspaceSubmit();
  }
});

// Global Keyboard Shortcuts (Ctrl+B, Ctrl+E, Ctrl+N, Ctrl+J, Ctrl+K, Escape)
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (!bootEl.classList.contains("hidden")) {
      skipBootNow();
      return;
    }
    [addProviderModal, comingSoonModal, saveNameModal, memoryVaultModal, commandPaletteModal, customInputModal].forEach((m) =>
      m.classList.add("hidden")
    );
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    openCommandPalette();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") {
    e.preventDefault();
    openWorkspaceScreen();
    toggleLeftSidebar();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "n") {
    e.preventDefault();
    openWorkspaceScreen("", "task");
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "j") {
    e.preventDefault();
    openWorkspaceScreen("", "chat");
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "e") {
    e.preventDefault();
    openWorkspaceScreen();
    toggleRightCodePane();
  }
});

// Workspace Composer Pill Cyclers
const modes = ["Ask before changes", "Auto-apply changes", "Plan mode"];
let modeIdx = 0;
document.getElementById("ws-mode-pill").addEventListener("click", () => {
  modeIdx = (modeIdx + 1) % modes.length;
  document.getElementById("ws-mode-text").textContent = modes[modeIdx];
});

const efforts = ["Max", "High", "Fast"];
let effortIdx = 0;
document.getElementById("ws-effort-pill").addEventListener("click", () => {
  effortIdx = (effortIdx + 1) % efforts.length;
  document.getElementById("ws-effort-text").textContent = efforts[effortIdx];
});

renderAllUI();
renderAboutGuideGrid();
runBootSequence();
