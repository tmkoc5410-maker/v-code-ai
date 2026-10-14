// =========================================================
// V.CODE MOBILE STUDIO — TOUCH LOGIC & MULTI-MODEL ENGINE
// (100% Mobile Optimized | Pure English | Shared LocalStorage)
// =========================================================
const STORAGE_KEY = "vcode_persistent_memory_v6";
const VAULT_PREFIX = "vcvault:v1:";
const VAULT_SALT = "VCode::StudioVault::Secure::2026";

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
    defaultModel: "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
    models: ["meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "mistralai/Mixtral-8x7B-Instruct-v0.1"]
  },
  {
    name: "Local Ollama",
    tag: "Offline & Private",
    keyUrl: "http://localhost:11434",
    baseUrl: "http://localhost:11434/v1",
    defaultModel: "llama3",
    models: ["llama3", "codellama", "qwen2.5-coder"]
  }
];

const DEFAULT_PROVIDERS = {
  "Google Gemini": {
    name: "Google Gemini",
    official: true,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
    apiKey: "",
    models: []
  },
  "Groq": {
    name: "Groq",
    official: true,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://api.groq.com/openai/v1",
    apiKey: "",
    models: []
  },
  "OpenRouter": {
    name: "OpenRouter",
    official: true,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://openrouter.ai/api/v1",
    apiKey: "",
    models: []
  },
  "OpenAI": {
    name: "OpenAI",
    official: true,
    comingSoon: false,
    enabled: false,
    baseUrl: "https://api.openai.com/v1",
    apiKey: "",
    models: []
  },
  "V.ai": {
    name: "V.ai",
    official: true,
    comingSoon: true,
    enabled: false,
    baseUrl: "",
    apiKey: "",
    models: []
  }
};

const DEFAULT_STATE = {
  theme: "dark",
  fontSize: "14px",
  username: "V Code Dev",
  language: "English",
  persistentMemoryEnabled: true,
  enterToSend: true,
  selectedProvider: "Google Gemini",
  providers: structuredClone(DEFAULT_PROVIDERS),
  activeProvider: "",
  activeModel: "",
  activeProjectId: "proj_default",
  activeSessionId: null,
  projects: [
    {
      id: "proj_default",
      name: "VCodeProject",
      memoryNotes: ["Mobile Workspace initialized."],
      sessions: []
    }
  ]
};

// Vault Encryption & Security Helpers
function encryptVaultSecret(plainText) {
  const raw = String(plainText || "").trim();
  if (!raw || raw.startsWith(VAULT_PREFIX)) return raw;
  try {
    const bytes = new TextEncoder().encode(raw);
    const saltBytes = new TextEncoder().encode(VAULT_SALT);
    const xored = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      xored[i] = bytes[i] ^ saltBytes[i % saltBytes.length] ^ ((i * 31) & 0xff);
    }
    let bin = "";
    xored.forEach((b) => (bin += String.fromCharCode(b)));
    return VAULT_PREFIX + btoa(bin);
  } catch {
    return raw;
  }
}

function decryptVaultSecret(cipherText) {
  const raw = String(cipherText || "").trim();
  if (!raw || !raw.startsWith(VAULT_PREFIX)) return raw;
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

// DevTools & Anti-Inspection Lock
window.addEventListener("contextmenu", (e) => {
  if (e.target.tagName !== "TEXTAREA" && e.target.tagName !== "INPUT") {
    e.preventDefault();
    showMobToast("Inspection disabled for security");
  }
});

window.addEventListener("keydown", (e) => {
  const isInspectKey =
    e.key === "F12" ||
    ((e.ctrlKey || e.metaKey) && e.shiftKey && ["I", "J", "C"].includes(e.key.toUpperCase())) ||
    ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "u");
  if (isInspectKey) {
    e.preventDefault();
    showMobToast("DevTools shortcut blocked for security");
  }
}, true);

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
    return {
      ...structuredClone(DEFAULT_STATE),
      ...parsed,
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
  } catch {}
}

let state = loadState();
let mobAttachedFiles = [];
let mobCodeFiles = [];
let activeMobCodeIdx = 0;
let isEditingMobCode = false;

// Toast
function showMobToast(msg) {
  const container = document.getElementById("mob-toast-container");
  const el = document.createElement("div");
  el.className = "mob-toast";
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 2400);
}

// Themes
function applyMobTheme(themeName) {
  state.theme = themeName;
  document.documentElement.setAttribute("data-theme", themeName);
  saveState();
  showMobToast(`Theme: ${themeName.toUpperCase()}`);
}

document.querySelectorAll("[data-mob-theme]").forEach((btn) => {
  btn.addEventListener("click", () => applyMobTheme(btn.dataset.mobTheme));
});

document.getElementById("mob-theme-toggle-btn")?.addEventListener("click", () => {
  const order = ["dark", "light", "midnight"];
  const next = order[(order.indexOf(state.theme) + 1) % order.length];
  applyMobTheme(next);
});

// Desktop Switcher
document.getElementById("mob-desktop-mode-btn")?.addEventListener("click", () => {
  sessionStorage.setItem("vcode_prefer_desktop", "1");
  window.location.href = "index.html";
});
document.getElementById("mob-go-desktop-btn")?.addEventListener("click", () => {
  sessionStorage.setItem("vcode_prefer_desktop", "1");
  window.location.href = "index.html";
});

// Navigation Tabs Switcher
const tabButtons = document.querySelectorAll(".mob-nav-item");
const tabPanels = {
  chat: document.getElementById("panel-chat"),
  code: document.getElementById("panel-code"),
  projects: document.getElementById("panel-projects"),
  models: document.getElementById("panel-models"),
  settings: document.getElementById("panel-settings")
};

function switchMobTab(tabName) {
  tabButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tabName));
  Object.keys(tabPanels).forEach((k) => tabPanels[k]?.classList.toggle("active", k === tabName));
  if (tabName === "code") renderMobCodeExplorer();
  if (tabName === "projects") renderMobProjectsView();
  if (tabName === "models") renderMobModelsView();
}

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => switchMobTab(btn.dataset.tab));
});

document.getElementById("mob-top-proj-btn")?.addEventListener("click", () => switchMobTab("projects"));

// State Helpers
function getActiveProject() {
  return state.projects.find((p) => p.id === state.activeProjectId) || state.projects[0];
}

function getActiveSession() {
  const p = getActiveProject();
  if (!p) return null;
  return p.sessions.find((s) => s.id === state.activeSessionId) || null;
}

function isProviderReady(prov) {
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
  const act = state.providers[state.activeProvider];
  if (isProviderReady(act)) return act;
  const sel = state.providers[state.selectedProvider];
  if (isProviderReady(sel)) return sel;
  for (const k of Object.keys(state.providers)) {
    if (isProviderReady(state.providers[k])) return state.providers[k];
  }
  return null;
}

function getActiveModelName() {
  const wp = getWorkingProviderConfig();
  if (!wp) return null;
  const found = wp.models.find((m) => m.name === state.activeModel);
  return found ? found.name : wp.models[0].name;
}

function getAllWorkingCandidates() {
  const list = [];
  const seen = new Set();
  const wp = getWorkingProviderConfig();
  const wm = getActiveModelName();
  if (wp && wm) {
    seen.add(`${wp.name}::${wm}`);
    list.push({ prov: wp, model: wm });
  }
  Object.values(state.providers).forEach((p) => {
    if (isProviderReady(p)) {
      p.models.forEach((m) => {
        const k = `${p.name}::${m.name}`;
        if (!seen.has(k)) {
          seen.add(k);
          list.push({ prov: p, model: m.name });
        }
      });
    }
  });
  return list;
}

// Memory Safety Thresholds (Crash Prevention)
function getProjectMemoryMetrics(proj) {
  if (!proj) return { isAtLimit: false };
  let count = 0;
  let chars = 0;
  (proj.sessions || []).forEach((s) => {
    (s.messages || []).forEach((m) => {
      count++;
      chars += (m.text || "").length;
    });
  });
  const isAtLimit = count >= 45 || chars >= 380000;
  return { count, chars, isAtLimit };
}

// API Runner
async function callSingleProvider(prov, model, sysPrompt, historyMsgs) {
  const baseUrl = prov.baseUrl.replace(/\/$/, "");
  const apiKey = prov.apiKey.trim();

  if (baseUrl.includes("generativelanguage.googleapis.com") && !baseUrl.endsWith("/openai")) {
    const url = `${baseUrl}/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const contents = historyMsgs.map((m) => ({
      role: m.role === "user" ? "user" : "model",
      parts: [{ text: m.content }]
    }));
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: sysPrompt }] }, contents })
    });
    if (!resp.ok) {
      const err = redactSensitiveSecrets(await resp.text());
      throw new Error(`API Error (${resp.status}): ${err.slice(0, 160)}`);
    }
    const data = await resp.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || "No response text.";
  } else {
    const url = `${baseUrl}/chat/completions`;
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [{ role: "system", content: sysPrompt }, ...historyMsgs]
      })
    });
    if (!resp.ok) {
      const err = redactSensitiveSecrets(await resp.text());
      throw new Error(`API Error (${resp.status}): ${err.slice(0, 160)}`);
    }
    const data = await resp.json();
    return data.choices?.[0]?.message?.content || "Empty response.";
  }
}

async function runPromptWithMemory(promptText, session, project) {
  const candidates = getAllWorkingCandidates();
  if (candidates.length === 0) {
    return `**No Active API Key Connected**\n\nTo code on mobile:\n1. Switch to the **Models** tab below.\n2. Select **Google Gemini**, **Groq**, or **OpenRouter**.\n3. Paste your **API Key** (or tap **Harvest Free Models**).\n4. Tap **Enable API Key & Model**!`;
  }

  const sysPrompt = `You are V.Code AI Studio Mobile Assistant.\nActive Project: ${project.name}\nActive Task: ${session.name}\nAlways provide clean modular code with filename comment on line 1:\n// filename: app.js\n/* filename: style.css */\n<!-- filename: index.html -->`;

  const historyMsgs = (session.messages || [])
    .filter((m) => !m.temp)
    .slice(-12)
    .map((m) => ({
      role: m.role === "user" ? "user" : "assistant",
      content: m.text
    }));

  for (let i = 0; i < candidates.length; i++) {
    const { prov, model } = candidates[i];
    try {
      const reply = await callSingleProvider(prov, model, sysPrompt, historyMsgs);
      return reply;
    } catch (e) {
      if (i === candidates.length - 1) {
        return `**API Error (${prov.name} - ${model})**\n\`${redactSensitiveSecrets(e.message)}\``;
      }
    }
  }
  return "Unable to reach model.";
}

// Chat UI Rendering
function renderMobChatFeed() {
  const feed = document.getElementById("mob-chat-feed");
  const sess = getActiveSession();
  mobCodeFiles = [];

  if (!sess || !sess.messages || sess.messages.length === 0) {
    feed.innerHTML = `
      <div class="mob-chat-msg agent">
        <div class="mob-agent-box">
          <div class="mob-agent-header">
            <span class="mob-agent-tag">
              <span class="mob-logo-badge" style="width:18px;height:18px;font-size:11px;">V</span>
              <span>V.Code AI Studio</span>
            </span>
            <span style="color:var(--m-text-muted);">Ready</span>
          </div>
          <div class="mob-agent-text">
            Start a new coding task in <strong>${escapeHtml(getActiveProject().name)}</strong>! Type your instruction below or select a quick starter prompt.
          </div>
        </div>
      </div>
    `;
    return;
  }

  feed.innerHTML = sess.messages
    .map((m, idx) => {
      if (m.role === "user") {
        return `
          <div class="mob-chat-msg user">
            <div class="mob-user-bubble">${escapeHtml(m.text)}</div>
            <div class="mob-user-meta">${m.time || ""}</div>
          </div>
        `;
      }

      // Assistant message: parse code blocks
      const parts = [];
      const codeRegex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;
      let lastIdx = 0;
      let match;

      while ((match = codeRegex.exec(m.text)) !== null) {
        if (match.index > lastIdx) {
          parts.push(`<div style="margin-bottom:6px;">${escapeHtml(m.text.slice(lastIdx, match.index)).replace(/\n/g, "<br>")}</div>`);
        }
        const lang = match[1] || "js";
        const code = match[2].trim();
        const fnameMatch = code.match(/(?:\/\/|#|<!--|\/\*)\s*(?:filename|file):\s*([^\s*-->]+)/i);
        const fname = fnameMatch ? fnameMatch[1] : `file_${mobCodeFiles.length + 1}.${lang}`;
        const fileId = mobCodeFiles.length;

        mobCodeFiles.push({ filename: fname, lang, code, version: 1 });

        parts.push(`
          <div class="mob-code-card">
            <div class="mob-code-head">
              <div class="mob-code-title">
                <span>&lt;/&gt;</span>
                <span class="mob-code-name">${escapeHtml(fname)}</span>
              </div>
              <div class="mob-code-tools">
                <button type="button" class="mob-tool-btn" data-mob-open-code="${fileId}">Viewer</button>
                <button type="button" class="mob-tool-btn" data-mob-copy-code="${fileId}">Copy</button>
              </div>
            </div>
            <pre class="mob-code-snippet"><code>${escapeHtml(code.slice(0, 400))}${code.length > 400 ? "\n..." : ""}</code></pre>
          </div>
        `);
        lastIdx = codeRegex.lastIndex;
      }

      if (lastIdx < m.text.length) {
        parts.push(`<div>${escapeHtml(m.text.slice(lastIdx)).replace(/\n/g, "<br>")}</div>`);
      }

      return `
        <div class="mob-chat-msg agent">
          <div class="mob-agent-box">
            <div class="mob-agent-header">
              <span class="mob-agent-tag">
                <span class="mob-logo-badge" style="width:18px;height:18px;font-size:11px;">V</span>
                <span>V.Code</span>
              </span>
              <span style="font-size:10.5px;color:var(--m-text-muted);">${m.model || ""}</span>
            </div>
            <div class="mob-agent-text">${parts.join("")}</div>
          </div>
        </div>
      `;
    })
    .join("");

  feed.querySelectorAll("[data-mob-copy-code]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.mobCopyCode);
      const f = mobCodeFiles[idx];
      if (f) {
        navigator.clipboard.writeText(f.code);
        showMobToast(`Copied ${f.filename}`);
      }
    });
  });

  feed.querySelectorAll("[data-mob-open-code]").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeMobCodeIdx = Number(btn.dataset.mobOpenCode);
      switchMobTab("code");
    });
  });

  feed.scrollTop = feed.scrollHeight;
}

// Prompt Submission
async function submitMobPrompt() {
  const input = document.getElementById("mob-prompt-input");
  const val = input.value.trim();
  if (!val) return;

  const proj = getActiveProject();
  const memCheck = getProjectMemoryMetrics(proj);
  if (memCheck.isAtLimit) {
    showMobToast("Project memory full! Please create a New Project in Projects tab.");
    switchMobTab("projects");
    return;
  }

  input.value = "";
  let sess = getActiveSession();
  if (!sess) {
    sess = {
      id: "sess_" + Date.now(),
      name: val.slice(0, 32),
      kind: "task",
      messages: []
    };
    proj.sessions.unshift(sess);
    state.activeSessionId = sess.id;
  }

  sess.messages.push({
    role: "user",
    text: val,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  });

  const wp = getWorkingProviderConfig();
  const wm = getActiveModelName();
  const modelTag = wp && wm ? `${wp.name} / ${wm}` : "V.Code";

  const thinkingMsg = {
    role: "agent",
    text: "Generating code...",
    model: modelTag,
    temp: true
  };
  sess.messages.push(thinkingMsg);
  saveState();
  renderMobChatFeed();

  const reply = await runPromptWithMemory(val, sess, proj);
  sess.messages = sess.messages.filter((m) => !m.temp);
  sess.messages.push({
    role: "agent",
    text: reply,
    model: modelTag,
    time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  });
  saveState();
  renderMobChatFeed();
}

document.getElementById("mob-send-btn")?.addEventListener("click", submitMobPrompt);
document.getElementById("mob-prompt-input")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    submitMobPrompt();
  }
});

// Code Explorer Rendering
function renderMobCodeExplorer() {
  const tabsBar = document.getElementById("mob-code-tabs-bar");
  const titleEl = document.getElementById("mob-active-file-title");
  const verEl = document.getElementById("mob-active-file-ver");
  const linesEl = document.getElementById("mob-active-file-lines");
  const surface = document.getElementById("mob-code-surface");

  if (mobCodeFiles.length === 0) {
    tabsBar.innerHTML = `<div class="mob-tab-chip active">No Files</div>`;
    titleEl.textContent = "No file open";
    verEl.textContent = "v1";
    linesEl.textContent = "0 lines";
    surface.innerHTML = `<div style="padding:40px 10px;text-align:center;color:var(--m-text-muted);">No code files generated yet. Ask V.Code to write code in the Chat tab!</div>`;
    return;
  }

  if (activeMobCodeIdx >= mobCodeFiles.length) activeMobCodeIdx = 0;
  const activeF = mobCodeFiles[activeMobCodeIdx];

  tabsBar.innerHTML = mobCodeFiles
    .map(
      (f, i) => `
      <div class="mob-tab-chip ${i === activeMobCodeIdx ? "active" : ""}" data-switch-file="${i}">
        ${escapeHtml(f.filename)}
      </div>
    `
    )
    .join("");

  tabsBar.querySelectorAll("[data-switch-file]").forEach((chip) => {
    chip.addEventListener("click", () => {
      activeMobCodeIdx = Number(chip.dataset.switchFile);
      isEditingMobCode = false;
      renderMobCodeExplorer();
    });
  });

  titleEl.textContent = activeF.filename;
  verEl.textContent = `v${activeF.version || 1}`;
  const linesCount = activeF.code.split("\n").length;
  linesEl.textContent = `${linesCount} lines`;

  if (isEditingMobCode) {
    surface.innerHTML = `<textarea class="mob-code-editor-textarea" id="mob-active-editor-textarea">${escapeHtml(activeF.code)}</textarea>`;
    const ta = document.getElementById("mob-active-editor-textarea");
    ta?.addEventListener("input", () => {
      activeF.code = ta.value;
    });
  } else {
    surface.innerHTML = `<pre><code>${escapeHtml(activeF.code)}</code></pre>`;
  }
}

// Code Tools Listeners
document.getElementById("mob-code-edit-btn")?.addEventListener("click", () => {
  if (mobCodeFiles.length === 0) return;
  isEditingMobCode = !isEditingMobCode;
  document.getElementById("mob-code-edit-btn").textContent = isEditingMobCode ? "Done" : "Edit";
  renderMobCodeExplorer();
});

document.getElementById("mob-code-copy-btn")?.addEventListener("click", () => {
  const f = mobCodeFiles[activeMobCodeIdx];
  if (!f) return;
  navigator.clipboard.writeText(f.code);
  showMobToast(`Copied ${f.filename}`);
});

document.getElementById("mob-code-save-btn")?.addEventListener("click", () => {
  const f = mobCodeFiles[activeMobCodeIdx];
  if (!f) return;
  const blob = new Blob([f.code], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = f.filename;
  a.click();
  showMobToast(`Saved ${f.filename}`);
});

document.getElementById("mob-code-saveall-btn")?.addEventListener("click", () => {
  if (mobCodeFiles.length === 0) return;
  mobCodeFiles.forEach((f, i) => {
    setTimeout(() => {
      const blob = new Blob([f.code], { type: "text/plain" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = f.filename;
      a.click();
    }, i * 150);
  });
  showMobToast(`Saving ${mobCodeFiles.length} files...`);
});

// Projects View Rendering
function renderMobProjectsView() {
  const projList = document.getElementById("mob-projects-list");
  const sessList = document.getElementById("mob-sessions-list");
  const activeP = getActiveProject();

  projList.innerHTML = state.projects
    .map(
      (p) => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--m-surface-card);border:1px solid ${p.id === activeP.id ? "var(--m-accent)" : "var(--m-border)"};border-radius:9px;">
        <div style="display:flex;align-items:center;gap:8px;cursor:pointer;flex:1;" data-select-proj="${p.id}">
          <span style="font-weight:700;color:${p.id === activeP.id ? "var(--m-accent)" : "var(--m-text)"};">${escapeHtml(p.name)}</span>
          <span style="font-size:11px;color:var(--m-text-muted);">(${p.sessions.length} chats)</span>
        </div>
        ${state.projects.length > 1 ? `<button type="button" class="mob-tool-btn" data-del-proj="${p.id}" style="color:var(--m-diff-minus);">Del</button>` : ""}
      </div>
    `
    )
    .join("");

  projList.querySelectorAll("[data-select-proj]").forEach((el) => {
    el.addEventListener("click", () => {
      state.activeProjectId = el.dataset.selectProj;
      const p = getActiveProject();
      state.activeSessionId = p.sessions[0]?.id || null;
      saveState();
      renderAllMobUI();
      showMobToast(`Active Project: ${p.name}`);
    });
  });

  projList.querySelectorAll("[data-del-proj]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (state.projects.length <= 1) return;
      state.projects = state.projects.filter((p) => p.id !== btn.dataset.delProj);
      if (!state.projects.some((p) => p.id === state.activeProjectId)) {
        state.activeProjectId = state.projects[0].id;
      }
      saveState();
      renderAllMobUI();
      showMobToast("Project deleted");
    });
  });

  sessList.innerHTML =
    activeP.sessions.length === 0
      ? `<div style="padding:10px;font-size:12px;color:var(--m-text-muted);">No tasks saved in this project yet.</div>`
      : activeP.sessions
          .map(
            (s) => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--m-surface-card);border:1px solid ${s.id === state.activeSessionId ? "var(--m-accent)" : "var(--m-border)"};border-radius:9px;">
          <div style="cursor:pointer;flex:1;min-width:0;padding-right:8px;" data-select-sess="${s.id}">
            <div style="font-weight:600;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:${s.id === state.activeSessionId ? "var(--m-accent)" : "var(--m-text)"};">${escapeHtml(s.name)}</div>
            <div style="font-size:10.5px;color:var(--m-text-muted);">${s.messages.length} messages</div>
          </div>
          <button type="button" class="mob-tool-btn" data-del-sess="${s.id}" style="color:var(--m-diff-minus);">Del</button>
        </div>
      `
          )
          .join("");

  sessList.querySelectorAll("[data-select-sess]").forEach((el) => {
    el.addEventListener("click", () => {
      state.activeSessionId = el.dataset.selectSess;
      saveState();
      renderAllMobUI();
      switchMobTab("chat");
    });
  });

  sessList.querySelectorAll("[data-del-sess]").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeP.sessions = activeP.sessions.filter((s) => s.id !== btn.dataset.delSess);
      if (state.activeSessionId === btn.dataset.delSess) {
        state.activeSessionId = activeP.sessions[0]?.id || null;
      }
      saveState();
      renderAllMobUI();
      showMobToast("Task deleted");
    });
  });
}

document.getElementById("mob-new-proj-btn")?.addEventListener("click", () => {
  const name = prompt("Enter new project name:");
  if (!name || !name.trim()) return;
  const p = {
    id: "proj_" + Date.now(),
    name: name.trim(),
    memoryNotes: [],
    sessions: []
  };
  state.projects.push(p);
  state.activeProjectId = p.id;
  state.activeSessionId = null;
  saveState();
  renderAllMobUI();
  showMobToast(`Created project "${p.name}"`);
});

document.getElementById("mob-new-task-btn")?.addEventListener("click", () => {
  const name = prompt("Enter new task name:");
  if (!name || !name.trim()) return;
  const p = getActiveProject();
  const sess = {
    id: "sess_" + Date.now(),
    name: name.trim(),
    kind: "task",
    messages: []
  };
  p.sessions.unshift(sess);
  state.activeSessionId = sess.id;
  saveState();
  renderAllMobUI();
  switchMobTab("chat");
  showMobToast(`Task "${sess.name}" created`);
});

// Models & Providers View
function renderMobModelsView() {
  const provSelect = document.getElementById("mob-provider-select");
  const keyInput = document.getElementById("mob-api-key-input");
  const modelInput = document.getElementById("mob-model-input");
  const urlInput = document.getElementById("mob-baseurl-input");
  const tagEl = document.getElementById("mob-active-prov-tag");

  const provNames = Object.keys(state.providers);
  provSelect.innerHTML = provNames
    .map((name) => `<option value="${name}" ${name === state.selectedProvider ? "selected" : ""}>${name}</option>`)
    .join("");

  const prov = state.providers[state.selectedProvider] || state.providers["Google Gemini"];
  tagEl.textContent = prov.enabled && prov.apiKey ? `Enabled (${prov.models[0]?.name || ""})` : "Not Enabled";
  keyInput.value = prov.apiKey || "";
  modelInput.value = prov.models[0]?.name || (PROVIDER_CATALOG.find((c) => c.name === prov.name)?.defaultModel || "");
  urlInput.value = prov.baseUrl || "";
}

document.getElementById("mob-provider-select")?.addEventListener("change", (e) => {
  state.selectedProvider = e.target.value;
  saveState();
  renderMobModelsView();
});

document.getElementById("mob-save-provider-btn")?.addEventListener("click", () => {
  const prov = state.providers[state.selectedProvider];
  if (!prov) return;
  const key = document.getElementById("mob-api-key-input").value.trim();
  const model = document.getElementById("mob-model-input").value.trim();
  const url = document.getElementById("mob-baseurl-input").value.trim();

  if (!key) {
    showMobToast("Please enter an API Key");
    return;
  }
  if (!model) {
    showMobToast("Please enter a Model Name");
    return;
  }

  prov.apiKey = key;
  prov.models = [{ name: model, context: "API" }];
  if (url) prov.baseUrl = url;
  prov.enabled = true;
  state.activeProvider = prov.name;
  state.activeModel = model;
  saveState();
  renderAllMobUI();
  showMobToast(`${prov.name} (${model}) enabled!`);
});

document.getElementById("mob-load-free-btn")?.addEventListener("click", async () => {
  const box = document.getElementById("mob-free-chips-box");
  box.innerHTML = `<span style="font-size:12px;color:var(--m-accent);">Harvesting live free models...</span>`;

  try {
    const resp = await fetch("https://openrouter.ai/api/v1/models");
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    const freeModels = (data.data || [])
      .filter((m) => m.id && (m.id.endsWith(":free") || (m.pricing && m.pricing.prompt === "0")))
      .map((m) => m.id)
      .slice(0, 18);

    if (freeModels.length === 0) {
      freeModels.push("meta-llama/llama-3.2-3b-instruct:free", "google/gemini-2.0-flash-exp:free");
    }

    box.innerHTML = freeModels
      .map(
        (mId) => `
        <button type="button" class="mob-tool-btn" data-pick-free="${mId}" style="font-size:11px;padding:4px 8px;">
          ${mId}
        </button>
      `
      )
      .join("");

    box.querySelectorAll("[data-pick-free]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.getElementById("mob-model-input").value = btn.dataset.pickFree;
        showMobToast(`Selected: ${btn.dataset.pickFree}`);
      });
    });
  } catch {
    box.innerHTML = `
      <button type="button" class="mob-tool-btn" data-pick-free="gemini-2.5-flash">gemini-2.5-flash</button>
      <button type="button" class="mob-tool-btn" data-pick-free="llama-3.3-70b-versatile">llama-3.3-70b-versatile</button>
      <button type="button" class="mob-tool-btn" data-pick-free="meta-llama/llama-3.2-3b-instruct:free">meta-llama/llama-3.2-3b-instruct:free</button>
    `;
    box.querySelectorAll("[data-pick-free]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.getElementById("mob-model-input").value = btn.dataset.pickFree;
        showMobToast(`Selected: ${btn.dataset.pickFree}`);
      });
    });
  }
});

document.getElementById("mob-get-key-link-btn")?.addEventListener("click", () => {
  const cat = PROVIDER_CATALOG.find((c) => c.name === state.selectedProvider);
  window.open(cat ? cat.keyUrl : "https://openrouter.ai/keys", "_blank", "noopener,noreferrer");
});

// Clear All Keys
document.getElementById("mob-clear-keys-btn")?.addEventListener("click", () => {
  if (confirm("Wipe all saved API keys from mobile storage vault?")) {
    Object.values(state.providers).forEach((p) => {
      p.apiKey = "";
      p.enabled = false;
    });
    state.activeProvider = "";
    state.activeModel = "";
    saveState();
    renderAllMobUI();
    showMobToast("All API Keys cleared");
  }
});

// Overall Mobile UI Refresh
function escapeHtml(str) {
  return String(str || "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderAllMobUI() {
  const p = getActiveProject();
  const wp = getWorkingProviderConfig();
  const wm = getActiveModelName();

  const headerProj = document.getElementById("mob-header-proj-name");
  if (headerProj) headerProj.textContent = p.name;

  const headerModel = document.getElementById("mob-header-model-badge");
  if (headerModel) {
    headerModel.textContent = wp && wm ? wm : "Connect API";
  }

  document.documentElement.setAttribute("data-theme", state.theme || "dark");
  renderMobChatFeed();
  renderMobProjectsView();
  renderMobModelsView();
}

renderAllMobUI();
