// UI for inro. Every call into Go goes through the functions glaze binds on
// window as inro_<snake_case_method>.
//
// One message screen: what you put in the input decides what happens to it,
// and whatever can happen without the user happens by itself. A signed
// message is verified the moment it lands. An encrypted message picks its own
// key (the message names its recipients) and is opened immediately when that
// key needs no passphrase; otherwise the only question the app ever asks —
// the passphrase — is focused and Enter answers it.

const $ = (id) => document.getElementById(id);

const ENCRYPTED_HEADER = "-----BEGIN PGP MESSAGE-----";
const SIGNED_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----";

let keys = [];
let settings = { defaultKey: "", dataDir: "" };
let selected = null;

// lastInfo is WhoCanOpen's answer for the encrypted message currently in the
// input: which of my keys open it, and whether each needs a passphrase now.
let lastInfo = null;

function showError(err) {
  const box = $("alert");
  box.className = "alert alert-danger";
  box.textContent = String(err.message || err);
}

function showInfo(text) {
  const box = $("alert");
  box.className = "alert alert-success";
  box.textContent = text;
}

function clearAlert() {
  $("alert").className = "alert d-none";
}

// run wraps a bound call so a rejected promise from Go lands in the alert box
// instead of the console. A "passphrase required" rejection is not an error:
// it is the one question the app asks, so it becomes a focused prompt.
async function run(fn) {
  clearAlert();
  try {
    await fn();
  } catch (err) {
    const msg = String(err.message || err);
    if (/passphrase required/i.test(msg)) {
      askPassphrase(msg);
      return;
    }
    showError(err);
  }
}

function askPassphrase(hint) {
  $("ctl-passphrase").classList.remove("d-none");
  $("pass-hint").textContent = hint;
  $("passphrase").focus();
}

function keyLabel(k) {
  const name = k.nickname ? `${k.nickname} — ${k.identity}` : k.identity;
  return `${name} (${k.keyId})`;
}

function labelFor(fingerprint) {
  const k = keys.find((k) => k.fingerprint === fingerprint);
  return k ? keyLabel(k) : fingerprint;
}

function option(value, text) {
  const o = document.createElement("option");
  o.value = value;
  o.textContent = text;
  return o;
}

function fillSelect(select, list) {
  const previous = select.value;
  select.replaceChildren();

  for (const k of list) {
    select.append(option(k.fingerprint, keyLabel(k)));
  }

  const wanted = previous || settings.defaultKey;
  if (wanted && list.some((k) => k.fingerprint === wanted)) {
    select.value = wanted;
  }
}

function selectedValues(select) {
  return Array.from(select.selectedOptions).map((o) => o.value);
}

// detect classifies the input. The headers are what PGP itself puts there, so
// this never has to guess.
function detect(text) {
  const t = text.trim();
  if (t === "") {
    return "empty";
  }
  if (t.startsWith(ENCRYPTED_HEADER)) {
    return "encrypted";
  }
  if (t.startsWith(SIGNED_HEADER)) {
    return "signed";
  }
  return "plain";
}

// isComplete tells whether an armored block has arrived whole, so automatic
// actions never fire on a half-pasted message.
function isComplete(text, mode) {
  if (mode === "encrypted") {
    return text.includes("-----END PGP MESSAGE-----");
  }
  if (mode === "signed") {
    return text.includes("-----END PGP SIGNATURE-----");
  }
  return false;
}

const BADGES = {
  empty: ["Empty", "text-bg-secondary"],
  plain: ["Plain text", "text-bg-secondary"],
  encrypted: ["Encrypted message", "text-bg-primary"],
  signed: ["Signed message", "text-bg-primary"],
};

// openCandidate returns the entry in lastInfo for the key the open-key select
// currently points at.
function openCandidate() {
  if (!lastInfo) {
    return null;
  }
  const fp = $("open-key").value;
  return lastInfo.keys.find((k) => k.fingerprint === fp) || lastInfo.keys[0] || null;
}

// plan works out the single action available for the current input and
// controls: what the button says, whether it can run, and why not.
function plan() {
  const mode = detect($("in-text").value);

  if (mode === "encrypted") {
    if (lastInfo && !lastInfo.symmetric && lastInfo.keys.length === 0) {
      return {
        mode,
        label: "Decrypt",
        enabled: false,
        hint: "This message is not encrypted to any key in your keyring.",
      };
    }
    return { mode, label: "Decrypt", enabled: true, hint: "" };
  }

  if (mode === "signed") {
    return { mode, label: "Verify", enabled: true, hint: "" };
  }

  if (mode === "empty") {
    return { mode, label: "Encrypt", enabled: false, hint: "" };
  }

  const recipients = selectedValues($("recipients"));
  const signing = $("sign-toggle").checked;

  if (recipients.length > 0 && signing) {
    return { mode, label: "Encrypt & sign", enabled: true, hint: "" };
  }
  if (recipients.length > 0) {
    return { mode, label: "Encrypt", enabled: true, hint: "" };
  }
  if (signing) {
    return { mode, label: "Sign", enabled: true, hint: "The message stays readable." };
  }

  return {
    mode,
    label: "Encrypt",
    enabled: false,
    hint: "Pick a recipient, or turn on Sign.",
  };
}

// render points the screen at the current plan: only the controls the action
// actually needs are on show.
function render() {
  const p = plan();

  const [text, badgeClass] = BADGES[p.mode];
  $("detected").textContent = text;
  $("detected").className = `badge ${badgeClass}`;

  const plain = p.mode === "plain" || p.mode === "empty";
  const signing = plain && $("sign-toggle").checked;

  const candidate = openCandidate();
  const showKeyPick = p.mode === "encrypted" && lastInfo && lastInfo.keys.length > 1;
  const needsPass =
    signing ||
    (p.mode === "encrypted" &&
      (!lastInfo || lastInfo.symmetric || (candidate && candidate.locked)));

  $("ctl-plain").classList.toggle("d-none", !plain);
  $("ctl-encrypted").classList.toggle("d-none", !showKeyPick);
  $("ctl-passphrase").classList.toggle("d-none", !needsPass);
  $("sign-key").disabled = !signing;
  if (!needsPass) {
    $("pass-hint").textContent = "";
  }

  $("run").textContent = p.label;
  $("run").disabled = !p.enabled;
  $("hint").textContent = p.hint;
}

function renderSignature(sig) {
  const box = $("sig");
  box.classList.remove("d-none");

  if (!sig.signed) {
    box.className = "alert alert-secondary py-2 small mb-2";
    box.textContent = "Not signed.";
    return;
  }

  if (sig.verified) {
    box.className = "alert alert-success py-2 small mb-2";
    box.textContent = `Valid signature from ${sig.signedBy} (${sig.keyId}).`;
    return;
  }

  box.className = "alert alert-danger py-2 small mb-2";
  const who = sig.signedBy || (sig.keyId ? `key ${sig.keyId}` : "");
  box.textContent = who
    ? `Signature from ${who} could NOT be verified: ${sig.reason}`
    : `Signature could NOT be verified: ${sig.reason}`;
}

function hideSignature() {
  $("sig").classList.add("d-none");
}

function showResult(res) {
  $("out-text").value = res.text;
  renderSignature(res.signature);
}

// --- The automatic path -----------------------------------------------------

let autoTimer = null;
let autoBusy = false;

function scheduleAuto() {
  clearTimeout(autoTimer);
  autoTimer = setTimeout(() => {
    autoRun().catch(showError);
  }, 250);
}

// autoRun does whatever the pasted input allows without asking anything:
// verify runs outright; decrypt runs when a key is ready, and otherwise the
// passphrase prompt is put in front of the user.
async function autoRun() {
  if (autoBusy) {
    return;
  }
  autoBusy = true;
  try {
    const text = $("in-text").value;
    const mode = detect(text);
    if (!isComplete(text, mode)) {
      return;
    }

    if (mode === "signed") {
      await run(async () => showResult(await window.inro_verify(text)));
      return;
    }

    // Encrypted: find out who can open it, then open it or ask.
    lastInfo = await window.inro_who_can_open(text).catch(() => null);
    if (!lastInfo) {
      render();
      return;
    }

    const candidates = lastInfo.keys.map((c) => ({
      fingerprint: c.fingerprint,
      ...keys.find((k) => k.fingerprint === c.fingerprint),
    }));
    fillSelect($("open-key"), candidates);
    render();

    if (lastInfo.symmetric && lastInfo.keys.length === 0) {
      askPassphrase("This message is protected by a passphrase.");
      return;
    }

    const candidate = openCandidate();
    if (!candidate) {
      return; // not our message; plan() already says so
    }

    if (!candidate.locked) {
      await run(async () => showResult(await doDecrypt("")));
      return;
    }

    askPassphrase(`Passphrase for ${labelFor(candidate.fingerprint)} — Enter decrypts.`);
  } finally {
    autoBusy = false;
  }
}

async function doDecrypt(passphrase) {
  return window.inro_decrypt({
    message: $("in-text").value,
    key: $("open-key").value,
    passphrase: passphrase,
  });
}

// --- The manual path ---------------------------------------------------------

// execute runs the one action the plan settled on.
async function execute() {
  const p = plan();
  const text = $("in-text").value;

  if (p.mode === "encrypted") {
    showResult(await doDecrypt($("passphrase").value));
    $("passphrase").value = "";
    return;
  }

  if (p.mode === "signed") {
    showResult(await window.inro_verify(text));
    return;
  }

  const recipients = selectedValues($("recipients"));
  const signing = $("sign-toggle").checked;

  hideSignature();

  let out;
  if (recipients.length === 0) {
    out = await window.inro_sign({
      text: text,
      key: $("sign-key").value,
      passphrase: $("passphrase").value,
    });
  } else {
    out = await window.inro_encrypt({
      text: text,
      recipients: recipients,
      signWith: signing ? $("sign-key").value : "",
      passphrase: $("passphrase").value,
    });
  }
  $("passphrase").value = "";

  // Outgoing message: the next step is almost always pasting it somewhere,
  // so leave it selected — Cmd/Ctrl+C is enough.
  $("out-text").value = out;
  $("out-text").select();
}

// --- Keys tab ----------------------------------------------------------------

function renderKeyList() {
  const list = $("key-list");
  list.replaceChildren();

  if (keys.length === 0) {
    const empty = document.createElement("div");
    empty.className = "text-muted py-5 text-center";
    empty.textContent = "No keys yet. Generate one below, or import one.";
    list.append(empty);
    return;
  }

  for (const k of keys) {
    const item = document.createElement("button");
    item.className = "list-group-item list-group-item-action";
    item.addEventListener("click", () => openKey(k));

    const row = document.createElement("div");
    row.className = "d-flex align-items-center gap-2";

    const title = document.createElement("span");
    title.className = "flex-grow-1 text-truncate";
    title.textContent = k.nickname ? `${k.nickname} — ${k.identity}` : k.identity;
    row.append(title);

    if (k.private) {
      const badge = document.createElement("span");
      badge.className = "badge text-bg-primary";
      badge.textContent = "private";
      row.append(badge);
    }

    const id = document.createElement("small");
    id.className = "text-muted font-monospace d-block mt-1";
    id.textContent = `${k.keyId} · created ${k.created}`;

    item.append(row, id);
    list.append(item);
  }
}

async function refreshKeys() {
  keys = (await window.inro_list_keys()) || [];

  const privateKeys = keys.filter((k) => k.private);

  fillSelect($("recipients"), keys);
  fillSelect($("sign-key"), privateKeys);

  renderKeyList();
  render();
}

function openKey(k) {
  selected = k;

  $("key-modal-title").textContent = k.identity;
  $("key-modal-fingerprint").textContent = k.fingerprint;
  $("key-modal-nickname").value = k.nickname;
  $("key-modal-note").value = k.note;
  $("key-modal-export").value = "";

  run(async () => {
    $("key-modal-export").value = await window.inro_export_key(k.fingerprint);
  });

  bootstrap.Modal.getOrCreateInstance($("key-modal")).show();
}

function showKeysTab() {
  bootstrap.Tab.getOrCreateInstance(
    document.querySelector('[data-bs-target="#pane-keys"]'),
  ).show();
}

// --- Wiring -------------------------------------------------------------------

$("in-text").addEventListener("input", () => {
  lastInfo = null;
  if (detect($("in-text").value) === "empty") {
    $("out-text").value = "";
    hideSignature();
  }
  render();
  scheduleAuto();
});

$("recipients").addEventListener("change", render);
$("sign-toggle").addEventListener("change", () => {
  render();
  if ($("sign-toggle").checked) {
    $("passphrase").focus();
  }
});
$("open-key").addEventListener("change", render);

$("run").addEventListener("click", () => run(execute));

// Enter in the passphrase field answers the question it asks; Cmd/Ctrl+Enter
// in the input runs the action from anywhere.
$("passphrase").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !$("run").disabled) {
    e.preventDefault();
    run(execute);
  }
});
$("in-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && !$("run").disabled) {
    e.preventDefault();
    run(execute);
  }
});

$("open-file").addEventListener("click", () =>
  run(async () => {
    const text = await window.inro_open_text_file();
    if (!text) {
      return;
    }
    $("in-text").value = text;
    $("in-text").dispatchEvent(new Event("input"));
  }),
);

$("save-file").addEventListener("click", () =>
  run(async () => {
    if (!$("out-text").value) {
      return;
    }
    const path = await window.inro_save_text_file($("out-text").value);
    if (path) {
      showInfo(`Saved to ${path}.`);
    }
  }),
);

$("copy").addEventListener("click", () =>
  run(async () => {
    const text = $("out-text").value;
    if (!text) {
      return;
    }
    await navigator.clipboard.writeText(text);
    showInfo("Copied to the clipboard.");
  }),
);

$("clear").addEventListener("click", () => {
  $("in-text").value = "";
  $("out-text").value = "";
  $("passphrase").value = "";
  lastInfo = null;
  hideSignature();
  clearAlert();
  render();
  $("in-text").focus();
});

$("key-import-run").addEventListener("click", () =>
  run(async () => {
    const imported = await window.inro_import_key($("key-import").value);
    $("key-import").value = "";
    await refreshKeys();
    showInfo(`Imported ${imported.map((k) => k.identity).join(", ")}.`);
  }),
);

$("key-import-file").addEventListener("click", () =>
  run(async () => {
    const text = await window.inro_open_text_file();
    if (text) {
      $("key-import").value = text;
    }
  }),
);

$("gen-run").addEventListener("click", () =>
  run(async () => {
    const info = await window.inro_generate_key(
      $("gen-name").value,
      $("gen-email").value,
      $("gen-passphrase").value,
    );
    $("gen-name").value = "";
    $("gen-email").value = "";
    $("gen-passphrase").value = "";
    await refreshKeys();
    showInfo(`Generated ${info.identity} (${info.keyId}).`);
  }),
);

$("key-modal-save").addEventListener("click", () =>
  run(async () => {
    await window.inro_set_key_meta(
      selected.fingerprint,
      $("key-modal-nickname").value,
      $("key-modal-note").value,
    );
    bootstrap.Modal.getOrCreateInstance($("key-modal")).hide();
    await refreshKeys();
  }),
);

$("key-modal-delete").addEventListener("click", () =>
  run(async () => {
    if (!confirm(`Delete the key of ${selected.identity}?`)) {
      return;
    }
    await window.inro_delete_key(selected.fingerprint);
    bootstrap.Modal.getOrCreateInstance($("key-modal")).hide();
    await refreshKeys();
  }),
);

run(async () => {
  settings = await window.inro_settings();
  await refreshKeys();

  // First run: there is nothing to do on the message screen without keys,
  // so start where the work is.
  if (keys.length === 0) {
    showKeysTab();
    showInfo("Welcome. Generate your key pair below, or import one you already have.");
  }
});
