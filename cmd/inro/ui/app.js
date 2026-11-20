// UI for inro. Every call into Go goes through the functions glaze binds on
// window as inro_<snake_case_method>.
//
// One text field, several pages. What lands in the field decides what happens
// to it — a signed message is verified on the spot, an encrypted one picks its
// own key and is opened as soon as that key is usable, plain text goes out —
// and the result replaces the field, like a translator with a single box.
// The only question inro ever asks, the passphrase, lives in its own window,
// which doubles as gpg-style entry-plus-confirm when a new one is being set.

const $ = (id) => document.getElementById(id);

const ENCRYPTED_HEADER = "-----BEGIN PGP MESSAGE-----";
const SIGNED_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----";

let keys = [];
let settings = { defaultKey: "" };
let selectedKey = null;

// lastInfo is WhoCanOpen's answer for the encrypted message currently in the
// field: which of my keys open it, and whether each needs a passphrase now.
let lastInfo = null;

// restoreText holds the field's content from before an outgoing transform
// (encrypt/sign), the one case where the original exists nowhere else.
let restoreText = null;

// --- Alerts and banner --------------------------------------------------------

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

async function run(fn) {
  clearAlert();
  try {
    await fn();
  } catch (err) {
    showError(err);
  }
}

// banner shows the state of the message in the field: signature verdicts and
// what just happened to it.
function banner(kind, text, withRestore = false) {
  const box = $("banner");
  box.className = `alert alert-${kind} py-2 small mb-2`;
  box.replaceChildren(document.createTextNode(text));

  if (withRestore && restoreText !== null) {
    box.append(" ");
    const a = document.createElement("a");
    a.href = "#";
    a.textContent = "Restore original text";
    a.addEventListener("click", (e) => {
      e.preventDefault();
      setText(restoreText);
      restoreText = null;
      hideBanner();
    });
    box.append(a);
  }
}

function hideBanner() {
  $("banner").className = "d-none";
}

function signatureBanner(sig) {
  if (!sig.signed) {
    banner("secondary", "Decrypted. The message was not signed.");
    return;
  }
  if (sig.verified) {
    banner("success", `Valid signature from ${sig.signedBy} (${sig.keyId}).`);
    return;
  }
  const who = sig.signedBy || (sig.keyId ? `key ${sig.keyId}` : "");
  banner(
    "danger",
    who
      ? `Signature from ${who} could NOT be verified: ${sig.reason}`
      : `Signature could NOT be verified: ${sig.reason}`,
  );
}

// --- Passphrase window --------------------------------------------------------

let passResolve = null;
let passReject = null;
let passOp = null;

// askPass opens the passphrase window. create=true adds the confirm field and
// strength meter, for setting a NEW passphrase; confirmation of an existing
// one would only confirm a typo twice. When op is given, OK runs it with the
// typed passphrase and a wrong one is reported INSIDE the window — it stays
// open for another try, like pinentry — resolving with op's result. Without
// op it resolves with the passphrase itself. Cancel resolves null either way.
function askPass({ title, hint, create = false, op = null }) {
  return new Promise((resolve, reject) => {
    passResolve = resolve;
    passReject = reject;
    passOp = op;

    $("pass-title").textContent = title;
    $("pass-hint").textContent = hint || "";
    $("pass-create").classList.toggle("d-none", !create);
    $("pass-input").value = "";
    $("pass-confirm").value = "";
    $("pass-error").classList.add("d-none");
    updateMeter();

    bootstrap.Modal.getOrCreateInstance($("pass-modal")).show();
  });
}

function passStrength(p) {
  if (!p) {
    return { pct: 0, cls: "bg-secondary", label: "Empty: the key will be stored unprotected." };
  }
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[^A-Za-z0-9]/.test(p)) pool += 33;
  const bits = Math.round(p.length * Math.log2(pool));
  if (bits < 40) return { pct: 25, cls: "bg-danger", label: `Weak (~${bits} bits).` };
  if (bits < 60) return { pct: 50, cls: "bg-warning", label: `Fair (~${bits} bits).` };
  if (bits < 80) return { pct: 75, cls: "bg-info", label: `Good (~${bits} bits).` };
  return { pct: 100, cls: "bg-success", label: `Strong (~${bits} bits).` };
}

function updateMeter() {
  const s = passStrength($("pass-input").value);
  $("pass-meter").style.width = `${s.pct}%`;
  $("pass-meter").className = `progress-bar ${s.cls}`;
  $("pass-strength").textContent = s.label;
}

function passError(text) {
  $("pass-error").textContent = text;
  $("pass-error").classList.remove("d-none");
}

// hidePassModal survives Bootstrap's transition race: hide() during the
// fade-in is silently ignored, which left a zombie window when OK was hit
// fast enough. If the hide is swallowed, the pending shown handler retries.
function hidePassModal() {
  const el = $("pass-modal");
  const modal = bootstrap.Modal.getOrCreateInstance(el);
  const retry = () => modal.hide();
  el.addEventListener("shown.bs.modal", retry, { once: true });
  el.addEventListener(
    "hidden.bs.modal",
    () => el.removeEventListener("shown.bs.modal", retry),
    { once: true },
  );
  modal.hide();
}

function finishPass(value) {
  const resolve = passResolve;
  passResolve = null;
  passReject = null;
  passOp = null;
  hidePassModal();
  if (resolve) {
    resolve(value);
  }
}

function isWrongPassphrase(msg) {
  return /passphrase required|unlock|checksum|wrong passphrase/i.test(msg);
}

$("pass-ok").addEventListener("click", async () => {
  const create = !$("pass-create").classList.contains("d-none");
  const value = $("pass-input").value;
  if (create && value !== $("pass-confirm").value) {
    passError("The passphrases do not match.");
    return;
  }

  if (!passOp) {
    finishPass(value);
    return;
  }

  // Run the operation from inside the window: a wrong passphrase keeps it
  // open for another try instead of closing and reopening.
  $("pass-ok").disabled = true;
  try {
    const result = await passOp(value);
    finishPass(result);
  } catch (err) {
    const msg = String(err.message || err);
    if (isWrongPassphrase(msg)) {
      passError("Wrong passphrase, try again.");
      $("pass-input").select();
      return;
    }
    const reject = passReject;
    passResolve = null;
    passReject = null;
    passOp = null;
    hidePassModal();
    if (reject) {
      reject(err);
    }
  } finally {
    $("pass-ok").disabled = false;
  }
});
$("pass-cancel").addEventListener("click", () => finishPass(null));
$("pass-input").addEventListener("input", updateMeter);
$("pass-modal").addEventListener("shown.bs.modal", () => $("pass-input").focus());
$("pass-modal").addEventListener("hidden.bs.modal", () => {
  $("pass-input").value = "";
  $("pass-confirm").value = "";
  if (passResolve) {
    // Closed some other way (Esc): treat as cancel.
    const resolve = passResolve;
    passResolve = null;
    passReject = null;
    passOp = null;
    resolve(null);
  }
});
for (const id of ["pass-input", "pass-confirm"]) {
  $(id).addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("pass-ok").click();
    }
  });
}

// withPassphrase runs fn with no passphrase first (the unlocked-key cache may
// make that enough); when fn instead demands one, the window takes over and
// drives the retries. Resolves with fn's result, or null when cancelled — so
// fn must resolve to something non-null on success.
async function withPassphrase(fn, title) {
  try {
    return await fn("");
  } catch (err) {
    const msg = String(err.message || err);
    if (!/passphrase required/i.test(msg)) {
      throw err;
    }
    const hint = msg.replace(/^passphrase required( to unlock)?[:\s]*/i, "");
    return askPass({ title, hint, op: fn });
  }
}

// --- Pages ---------------------------------------------------------------------

const PAGES = ["message", "keys", "generate", "import", "key", "about"];

function showPage(name) {
  for (const p of PAGES) {
    $(`page-${p}`).classList.toggle("d-none", p !== name);
  }
  const onKeys = name !== "message";
  $("nav-message").className = `btn btn-sm ${onKeys ? "btn-outline-secondary" : "btn-light"}`;
  $("nav-keys").className = `btn btn-sm ${onKeys ? "btn-light" : "btn-outline-secondary"}`;
}

async function showAbout() {
  showPage("about");
  const info = await window.inro_about();
  $("about-version").textContent = info.version;
  $("about-go").textContent = info.goVersion;
  $("about-deps").replaceChildren(
    ...(info.deps || []).flatMap((d) => [document.createTextNode(d), document.createElement("br")]),
  );
}

$("nav-message").addEventListener("click", () => showPage("message"));
$("nav-keys").addEventListener("click", () => showPage("keys"));
$("goto-generate").addEventListener("click", () => showPage("generate"));
$("goto-import").addEventListener("click", () => showPage("import"));
for (const btn of document.querySelectorAll(".inro-back")) {
  btn.addEventListener("click", () => showPage("keys"));
}
for (const btn of document.querySelectorAll(".inro-back-message")) {
  btn.addEventListener("click", () => showPage("message"));
}
document.querySelector(".navbar-brand").addEventListener("click", () => run(showAbout));

// inroMenu is the entry point the native application menu calls (through
// glaze's Eval); each action lands on the same handler its on-screen control
// uses, so the menu can never drift from the UI.
window.inroMenu = (action) => {
  const actions = {
    about: () => run(showAbout),
    open: () => $("open-file").click(),
    save: () => $("save-file").click(),
    message: () => showPage("message"),
    keys: () => showPage("keys"),
  };
  const fn = actions[action];
  if (fn) {
    fn();
  }
};

// --- The message field -----------------------------------------------------------

function keyLabel(k) {
  const name = k.nickname ? `${k.nickname} - ${k.identity}` : k.identity;
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
    const o = option(k.fingerprint, k.expired ? `${keyLabel(k)} [expired]` : keyLabel(k));
    o.disabled = Boolean(k.expired);
    select.append(o);
  }
  const wanted = previous || settings.defaultKey;
  const usable = list.some((k) => k.fingerprint === wanted && !k.expired);
  if (wanted && usable) {
    select.value = wanted;
  }
}

function selectedValues(select) {
  return Array.from(select.selectedOptions).map((o) => o.value);
}

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

// setText replaces the field programmatically, without triggering the
// automatic flow that reacts to typing and pasting.
function setText(value) {
  $("text").value = value;
  render();
}

function plan() {
  const mode = detect($("text").value);

  if (mode === "encrypted") {
    if (lastInfo && !lastInfo.symmetric && lastInfo.keys.length === 0) {
      return {
        mode,
        label: "Decrypt",
        icon: "bi-unlock",
        enabled: false,
        hint: "Not encrypted to any key in your keyring.",
      };
    }
    return { mode, label: "Decrypt", icon: "bi-unlock", enabled: true, hint: "" };
  }

  if (mode === "signed") {
    return { mode, label: "Verify", icon: "bi-patch-check", enabled: true, hint: "" };
  }

  if (mode === "empty") {
    return { mode, label: "Encrypt", icon: "bi-lock-fill", enabled: false, hint: "" };
  }

  const recipients = selectedValues($("recipients"));
  const signing = $("sign-toggle").checked && $("sign-key").value !== "";

  if (recipients.length > 0 && signing) {
    return { mode, label: "Encrypt & sign", icon: "bi-lock-fill", enabled: true, hint: "" };
  }
  if (recipients.length > 0) {
    return { mode, label: "Encrypt", icon: "bi-lock-fill", enabled: true, hint: "" };
  }
  if (signing) {
    return {
      mode,
      label: "Sign",
      icon: "bi-pen",
      enabled: true,
      hint: "The message stays readable.",
    };
  }
  let hint = "Pick a recipient, or turn on Sign.";
  if ($("sign-toggle").checked && $("sign-key").value === "") {
    hint = "Pick a recipient, or generate a private key to sign with.";
  }
  return { mode, label: "Encrypt", icon: "bi-lock-fill", enabled: false, hint: hint };
}

function render() {
  const p = plan();

  const [text, badgeClass] = BADGES[p.mode];
  $("detected").textContent = text;
  $("detected").className = `badge ${badgeClass}`;

  const plain = p.mode === "plain" || p.mode === "empty";
  $("ctl-plain").classList.toggle("d-none", !plain);
  $("ctl-encrypted").classList.toggle(
    "d-none",
    !(p.mode === "encrypted" && lastInfo && lastInfo.keys.length > 1),
  );
  $("sign-key").disabled = !(plain && $("sign-toggle").checked);

  $("run-label").textContent = p.label;
  $("run-icon").className = `bi ${p.icon}`;
  $("run").disabled = !p.enabled;
  $("hint").textContent = p.hint;
}

// --- Operations -----------------------------------------------------------------

async function doDecrypt(passphrase) {
  return window.inro_decrypt({
    message: $("text").value,
    key: $("open-key").value,
    passphrase: passphrase,
  });
}

async function decryptFlow() {
  const res = await withPassphrase((pass) => doDecrypt(pass), "Unlock key");
  if (res === null) {
    return;
  }
  restoreText = null;
  setText(res.text);
  signatureBanner(res.signature);
}

async function verifyFlow() {
  const res = await window.inro_verify($("text").value);
  restoreText = null;
  setText(res.text);
  signatureBanner(res.signature);
}

async function sendFlow() {
  const text = $("text").value;
  const recipients = selectedValues($("recipients"));
  const signKey = $("sign-key").value;
  const signing = $("sign-toggle").checked && signKey !== "";

  let out;
  if (recipients.length === 0) {
    out = await withPassphrase(
      (pass) => window.inro_sign({ text: text, key: signKey, passphrase: pass }),
      "Unlock signing key",
    );
  } else {
    out = await withPassphrase(
      (pass) =>
        window.inro_encrypt({
          text: text,
          recipients: recipients,
          signWith: signing ? signKey : "",
          passphrase: pass,
        }),
      "Unlock signing key",
    );
  }
  if (out === null) {
    return;
  }

  restoreText = text;
  setText(out);

  const what =
    recipients.length === 0
      ? "Signed."
      : `Encrypted to ${recipients.map(labelFor).join(", ")}${signing ? ", signed" : ""}.`;
  banner("secondary", `${what} The result replaced your text. Copy or save it.`, true);

  $("text").select();
}

async function execute() {
  const p = plan();
  hideBanner();
  if (p.mode === "encrypted") {
    return decryptFlow();
  }
  if (p.mode === "signed") {
    return verifyFlow();
  }
  return sendFlow();
}

// --- The automatic path -----------------------------------------------------------

let autoTimer = null;
let autoBusy = false;

function scheduleAuto() {
  clearTimeout(autoTimer);
  autoTimer = setTimeout(() => {
    autoRun().catch(showError);
  }, 250);
}

async function autoRun() {
  if (autoBusy) {
    return;
  }
  autoBusy = true;
  try {
    const text = $("text").value;
    const mode = detect(text);
    if (!isComplete(text, mode)) {
      return;
    }

    if (mode === "signed") {
      await run(verifyFlow);
      return;
    }

    lastInfo = await window.inro_who_can_open(text).catch(() => null);
    if (!lastInfo) {
      render();
      return;
    }
    lastInfo.keys = lastInfo.keys || [];

    const candidates = lastInfo.keys.map((c) => ({
      fingerprint: c.fingerprint,
      ...keys.find((k) => k.fingerprint === c.fingerprint),
    }));
    fillSelect($("open-key"), candidates);
    render();

    if (!lastInfo.symmetric && lastInfo.keys.length === 0) {
      return; // plan() already tells the user this is not their message
    }

    await run(decryptFlow);
  } finally {
    autoBusy = false;
  }
}

// --- Message page wiring ------------------------------------------------------------

$("text").addEventListener("input", () => {
  lastInfo = null;
  restoreText = null;
  hideBanner();
  if (detect($("text").value) === "empty") {
    clearAlert();
  }
  render();
  scheduleAuto();
});

$("recipients").addEventListener("change", render);
$("sign-toggle").addEventListener("change", render);
$("open-key").addEventListener("change", render);

$("run").addEventListener("click", () => run(execute));

$("text").addEventListener("keydown", (e) => {
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
    $("text").value = text;
    $("text").dispatchEvent(new Event("input"));
  }),
);

$("save-file").addEventListener("click", () =>
  run(async () => {
    if (!$("text").value) {
      return;
    }
    const path = await window.inro_save_text_file($("text").value, "message.asc");
    if (path) {
      showInfo(`Saved to ${path}.`);
    }
  }),
);

$("copy").addEventListener("click", () =>
  run(async () => {
    const text = $("text").value;
    if (!text) {
      return;
    }
    await navigator.clipboard.writeText(text);
    showInfo("Copied to the clipboard.");
  }),
);

$("clear").addEventListener("click", () => {
  restoreText = null;
  lastInfo = null;
  hideBanner();
  clearAlert();
  setText("");
  $("text").focus();
});

// --- Keys pages -----------------------------------------------------------------------

function renderKeyList() {
  const list = $("key-list");
  list.replaceChildren();

  if (keys.length === 0) {
    const empty = document.createElement("div");
    empty.className = "text-muted py-5 text-center";
    empty.textContent = "No keys yet. Generate your key pair, or import one.";
    list.append(empty);
    return;
  }

  for (const k of keys) {
    const item = document.createElement("button");
    item.className = "list-group-item list-group-item-action";
    item.addEventListener("click", () => openKeyPage(k));

    const row = document.createElement("div");
    row.className = "d-flex align-items-center gap-2";

    const title = document.createElement("span");
    title.className = "flex-grow-1 text-truncate";
    title.textContent = k.nickname ? `${k.nickname} - ${k.identity}` : k.identity;
    row.append(title);

    if (k.expired) {
      const badge = document.createElement("span");
      badge.className = "badge text-bg-danger";
      badge.textContent = "expired";
      row.append(badge);
    }
    if (k.certifiedBy && k.certifiedBy.length > 0) {
      const badge = document.createElement("span");
      badge.className = "badge text-bg-success";
      badge.textContent = "certified";
      badge.title = `Certified by ${k.certifiedBy.join(", ")}`;
      row.append(badge);
    }
    if (k.private) {
      const badge = document.createElement("span");
      badge.className = "badge text-bg-primary";
      badge.textContent = "private";
      row.append(badge);
    }

    const id = document.createElement("small");
    id.className = "text-muted font-monospace d-block mt-1";
    const expiry = k.expires ? ` · ${k.expired ? "expired" : "expires"} ${k.expires}` : "";
    id.textContent = `${k.keyId} · created ${k.created}${expiry}`;

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

function openKeyPage(k) {
  selectedKey = k;
  disarmDelete();

  $("key-title").textContent = k.nickname ? `${k.nickname} - ${k.identity}` : k.identity;
  $("key-private-badge").classList.toggle("d-none", !k.private);
  $("key-fingerprint").textContent = k.fingerprint;

  const expiry = k.expires ? ` · ${k.expired ? "EXPIRED" : "expires"} ${k.expires}` : " · never expires";
  $("key-dates").textContent = `${k.keyId} · created ${k.created}${expiry}`;
  $("key-dates").classList.toggle("text-danger", Boolean(k.expired));

  const cert = $("key-certified");
  if (k.certifiedBy && k.certifiedBy.length > 0) {
    cert.className = "small mb-3 text-success";
    cert.textContent = `Certified by ${k.certifiedBy.join(", ")}.`;
  } else {
    cert.className = "small mb-3 text-muted";
    cert.textContent = "No certifications from keys in your keyring.";
  }

  $("key-nickname").value = k.nickname;
  $("key-note").value = k.note;
  $("key-export").value = "";
  $("key-private-block").classList.toggle("d-none", !k.private);
  $("key-private-export").value = "";
  $("key-private-export").classList.add("d-none");

  // Certifying needs one of MY private keys that is not this key.
  const signers = keys.filter((s) => s.private && s.fingerprint !== k.fingerprint);
  $("key-certify-block").classList.toggle("d-none", signers.length === 0);
  fillSelect($("certify-with"), signers);

  run(async () => {
    $("key-export").value = await window.inro_export_key(k.fingerprint);
  });

  showPage("key");
}

$("key-save").addEventListener("click", () =>
  run(async () => {
    await window.inro_set_key_meta(
      selectedKey.fingerprint,
      $("key-nickname").value,
      $("key-note").value,
    );
    await refreshKeys();
    showInfo("Saved.");
  }),
);

$("certify-run").addEventListener("click", () =>
  run(async () => {
    const target = selectedKey.fingerprint;
    const signer = $("certify-with").value;
    const done = await withPassphrase(
      (pass) => window.inro_certify_key(target, signer, pass).then(() => true),
      "Unlock certifying key",
    );
    if (done === null) {
      return;
    }
    await refreshKeys();
    openKeyPage(keys.find((k) => k.fingerprint === target));
    showInfo(`Certified with ${labelFor(signer)}.`);
  }),
);

async function privateKeyBlock() {
  return window.inro_export_private_key(selectedKey.fingerprint);
}

$("key-private-show").addEventListener("click", () =>
  run(async () => {
    const box = $("key-private-export");
    if (!box.classList.contains("d-none")) {
      box.classList.add("d-none");
      return;
    }
    box.value = await privateKeyBlock();
    box.classList.remove("d-none");
  }),
);

$("key-private-copy").addEventListener("click", () =>
  run(async () => {
    await navigator.clipboard.writeText(await privateKeyBlock());
    showInfo("Private key copied to the clipboard.");
  }),
);

$("key-private-save").addEventListener("click", () =>
  run(async () => {
    const path = await window.inro_save_text_file(
      await privateKeyBlock(),
      `${selectedKey.keyId}-private.asc`,
    );
    if (path) {
      showInfo(`Saved to ${path}.`);
    }
  }),
);

$("key-export-copy").addEventListener("click", () =>
  run(async () => {
    await navigator.clipboard.writeText($("key-export").value);
    showInfo("Public key copied to the clipboard.");
  }),
);

// confirm() never shows in the app's webview (glaze implements no JS dialog
// panels), so deletion confirms on the button itself: first click arms it,
// a second click within a few seconds deletes, anything else disarms.
let deleteArmTimer = null;

function disarmDelete() {
  clearTimeout(deleteArmTimer);
  deleteArmTimer = null;
  $("key-delete").className = "btn btn-outline-danger btn-sm ms-auto";
  $("key-delete").innerHTML = '<i class="bi bi-trash"></i> Delete key';
}

$("key-delete").addEventListener("click", () =>
  run(async () => {
    if (deleteArmTimer === null) {
      $("key-delete").className = "btn btn-danger btn-sm ms-auto";
      $("key-delete").innerHTML = '<i class="bi bi-trash-fill"></i> Click again to delete';
      deleteArmTimer = setTimeout(disarmDelete, 4000);
      return;
    }
    disarmDelete();
    await window.inro_delete_key(selectedKey.fingerprint);
    await refreshKeys();
    showPage("keys");
    showInfo(`Deleted the key of ${selectedKey.identity}.`);
  }),
);

$("key-import-run").addEventListener("click", () =>
  run(async () => {
    const imported = await window.inro_import_key($("key-import").value);
    $("key-import").value = "";
    await refreshKeys();
    showPage("keys");
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
    const name = $("gen-name").value.trim();
    const email = $("gen-email").value.trim();
    if (!name || !email) {
      showError(new Error("Name and email are required."));
      return;
    }

    const pass = await askPass({
      title: "Set a passphrase",
      hint: "This passphrase protects the new private key on disk.",
      create: true,
    });
    if (pass === null) {
      return;
    }

    const info = await window.inro_generate_key(
      name,
      email,
      pass,
      Number($("gen-expiry").value),
    );
    $("gen-name").value = "";
    $("gen-email").value = "";
    await refreshKeys();
    showPage("keys");
    showInfo(`Generated ${info.identity} (${info.keyId}).`);
  }),
);

// --- Platform behaviour ------------------------------------------------------------------

// The page is an app, not a document: no browser context menu (with its
// Reload) outside the text fields and away from selected text. Inside fields
// and on selections the native menus stay; editing shortcuts (Cmd+A/C/X/V)
// are the system's job entirely — a shim here once double-pasted, because
// with the application menubar installed the webview handles them natively.
document.addEventListener("contextmenu", (e) => {
  if (e.target.closest("textarea, input")) {
    return;
  }
  if (String(document.getSelection())) {
    return;
  }
  e.preventDefault();
});

// --- Startup ---------------------------------------------------------------------------

run(async () => {
  settings = await window.inro_settings();
  await refreshKeys();

  // First run: there is nothing to do on the message page without keys, so
  // start where the work is.
  if (keys.length === 0) {
    showPage("keys");
    showInfo("Welcome. Generate your key pair, or import one you already have.");
  }
});
