// UI for inro. Every call into Go goes through the functions glaze binds on
// window as inro_<snake_case_method>.
//
// There is one message screen rather than one per operation: what you put in
// the input decides what can be done with it. An armored block can only be
// opened, a clear-signed block can only be checked, and plain text can only go
// out. So the app detects the input and offers the one action that fits.

const $ = (id) => document.getElementById(id);

const ENCRYPTED_HEADER = "-----BEGIN PGP MESSAGE-----";
const SIGNED_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----";

let keys = [];
let settings = { defaultKey: "", dataDir: "" };
let selected = null;

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
// instead of the console, where nobody would see it.
async function run(fn) {
  clearAlert();
  try {
    await fn();
  } catch (err) {
    showError(err);
  }
}

function keyLabel(k) {
  const name = k.nickname ? `${k.nickname} — ${k.identity}` : k.identity;
  return `${name} (${k.keyId})`;
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

const BADGES = {
  empty: ["Empty", "text-bg-secondary"],
  plain: ["Plain text", "text-bg-secondary"],
  encrypted: ["Encrypted message", "text-bg-primary"],
  signed: ["Signed message", "text-bg-primary"],
};

// plan works out the single action available for the current input and
// controls: what the button says, whether it can run, and why not.
function plan() {
  const mode = detect($("in-text").value);

  if (mode === "encrypted") {
    const hasKey = $("open-key").value !== "";
    return {
      mode,
      label: "Decrypt",
      enabled: hasKey,
      hint: hasKey ? "" : "Import your private key first.",
    };
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

  $("ctl-plain").classList.toggle("d-none", !plain);
  $("ctl-encrypted").classList.toggle("d-none", p.mode !== "encrypted");
  $("ctl-passphrase").classList.toggle("d-none", !(signing || p.mode === "encrypted"));
  $("sign-key").disabled = !signing;

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
  const who = sig.signedBy || `key ${sig.keyId}`;
  box.textContent = `Signature from ${who} could NOT be verified: ${sig.reason}`;
}

function hideSignature() {
  $("sig").classList.add("d-none");
}

// execute runs the one action the plan settled on.
async function execute() {
  const p = plan();
  const text = $("in-text").value;

  if (p.mode === "encrypted") {
    const res = await window.inro_decrypt({
      message: text,
      key: $("open-key").value,
      passphrase: $("passphrase").value,
    });
    $("out-text").value = res.text;
    renderSignature(res.signature);
    return;
  }

  if (p.mode === "signed") {
    const res = await window.inro_verify(text);
    $("out-text").value = res.text;
    renderSignature(res.signature);
    return;
  }

  const recipients = selectedValues($("recipients"));
  const signing = $("sign-toggle").checked;

  hideSignature();

  if (recipients.length === 0) {
    $("out-text").value = await window.inro_sign({
      text: text,
      key: $("sign-key").value,
      passphrase: $("passphrase").value,
    });
    return;
  }

  $("out-text").value = await window.inro_encrypt({
    text: text,
    recipients: recipients,
    signWith: signing ? $("sign-key").value : "",
    passphrase: $("passphrase").value,
  });
}

function renderKeyList() {
  const list = $("key-list");
  list.replaceChildren();

  if (keys.length === 0) {
    const empty = document.createElement("div");
    empty.className = "text-muted py-5 text-center";
    empty.textContent = "No keys yet. Import one on the right.";
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
  fillSelect($("open-key"), privateKeys);

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

$("in-text").addEventListener("input", render);
$("recipients").addEventListener("change", render);
$("sign-toggle").addEventListener("change", render);

$("run").addEventListener("click", () =>
  run(async () => {
    await execute();
    $("passphrase").value = "";
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
});
