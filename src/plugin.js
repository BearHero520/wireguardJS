const ROOT = "/data/kano_wireguard";
const CONFIG_PATH = `${ROOT}/wg0.conf`;
const BOOT = "/sdcard/ufi_tools_boot.sh";
const BOOT_LINE = `sh ${ROOT}/service.sh >/dev/null 2>&1 &`;
const ID = "IFRAME_KANO_Wireguard_Embedded";
const COLLAPSE = "#collapse_Wireguard_Embedded";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const quote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
const state = { busy: false, polling: false, pendingRefresh: false, timer: null, open: false, installed: false, version: "", running: false, boot: false, loaded: false, saved: "", view: "logs", generation: 0, auto: true };

if (typeof runShellWithRoot !== "function" || typeof createToast !== "function") {
  console.error("WireGuard: this plugin requires the KANO device management page.");
  return;
}
for (let attempt = 0; !document.querySelector(".functions-container") && attempt < 100; attempt++) await sleep(100);
const anchor = document.querySelector(".functions-container");
if (!anchor || document.getElementById(ID)) return;

const toast = (text, error = false) => createToast(text, error ? "red" : "green", error ? 6500 : 3500);
async function shell(script, timeout = 30000) {
  const wrapped = `sh -c ${quote(script)}; code=$?; printf '\\n__KANO_WG_EXIT__%s\\n' "$code"; exit "$code"`;
  const response = await runShellWithRoot(wrapped, timeout);
  const raw = String(response?.content || "");
  const match = /(?:^|\n)__KANO_WG_EXIT__(\d+)\s*$/.exec(raw);
  const text = match ? raw.slice(0, match.index).replace(/\n$/, "") : raw;
  if (!match || Number(match[1]) !== 0) throw new Error(WGConfig.redact(text).slice(-1800) || "设备命令未完成，请检查连接和 root 权限。");
  return text;
}

const container = document.createElement("section");
container.id = ID;
container.innerHTML = `
  <style>
    #${ID}{margin-top:12px;width:100%;font-size:14px;letter-spacing:0}
    #${ID} *{box-sizing:border-box;letter-spacing:0}
    #${ID} .wg-heading,#${ID} .wg-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
    #${ID} .wg-heading{padding:10px 0;border-bottom:1px solid #8884}
    #${ID} .wg-heading strong{font-size:18px}
    #${ID} .wg-version,#${ID} .wg-note{font-size:12px;opacity:.75}
    #${ID} .wg-toolbar{padding:10px 0}
    #${ID} button{min-height:34px;margin:0!important;padding:6px 10px;border:1px solid #8885;border-radius:6px;background:transparent;color:inherit;cursor:pointer;font-size:13px;max-width:100%;white-space:normal}
    #${ID} button:hover:not(:disabled){background:#8882}
    #${ID} button:disabled{opacity:.45;cursor:default}
    #${ID} button:focus-visible,#${ID} textarea:focus-visible{outline:2px solid #168a74;outline-offset:2px}
    #${ID} button.wg-primary{background:#137b66;color:white;border-color:#137b66}
    #${ID} button.wg-danger{color:#d34444}
    #${ID} .wg-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px}
    #${ID} .wg-pane{min-width:0}
    #${ID} textarea{display:block;width:100%;height:340px;min-height:180px;resize:vertical;border:1px solid #8885;border-radius:6px;background:#8881;color:inherit;padding:10px;font:12px/1.65 ui-monospace,Consolas,monospace;white-space:pre;overflow:auto;tab-size:2}
    #${ID} .wg-tabs{display:flex;gap:4px;min-height:40px;align-items:center}
    #${ID} [aria-selected="true"]{border-color:#168a74;background:#168a741a}
    #${ID} .wg-feedback{min-height:24px;margin:8px 0;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}
    #${ID} .wg-feedback[data-error="true"]{color:#d34444}
    #${ID} .wg-switch{display:inline-flex;align-items:center;gap:5px;font-size:12px;cursor:pointer}
    #${ID} .wg-switch input{margin:0;width:16px;height:16px;accent-color:#137b66}
    #${ID} .wg-status{font-size:12px;overflow-wrap:anywhere}
    #${ID} .wg-status[data-state="running"]{color:#168a74}
    #${ID} .wg-status[data-state="error"]{color:#d34444}
    #${ID} .wg-spacer{flex:1}
    @media(max-width:680px){#${ID} .wg-grid{grid-template-columns:minmax(0,1fr)}#${ID} textarea{height:270px}#${ID} .wg-toolbar{gap:6px}}
  </style>
  <div class="wg-heading">
    <strong>WireGuard</strong><span class="wg-version">v${VERSION}</span>
    <span id="Wireguard_embedded_status_badge" class="wg-status" role="status">正在连接设备</span>
    <span class="wg-spacer"></span><div id="collapse_Wireguard_Embedded_btn"></div>
  </div>
  <div class="collapse" id="collapse_Wireguard_Embedded" data-name="close" style="height:0;overflow:hidden">
    <div class="collapse_box">
      <div class="wg-toolbar" id="Wireguard_embedded_action_box">
        <button data-action="install">安装 / 升级</button>
        <button data-action="start" class="wg-primary" data-installed>启动</button>
        <button data-action="stop" data-installed>停止</button>
        <button data-action="restart" data-installed>重启</button>
        <label class="wg-switch"><input id="wg-boot" type="checkbox" data-installed>开机自启</label>
        <span class="wg-spacer"></span><button data-action="uninstall" class="wg-danger" data-installed>卸载</button>
      </div>
      <div class="wg-grid">
        <div class="wg-pane">
          <div class="wg-toolbar">
            <strong>配置</strong><span id="wg-dirty" class="wg-note"></span><span class="wg-spacer"></span>
            <button data-action="read" data-installed>读取</button><button data-action="validate">校验</button>
            <button data-action="save" data-installed class="wg-primary">保存</button>
          </div>
          <textarea id="Wireguard_embedded_config" aria-label="WireGuard 配置" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
          <div class="wg-toolbar">
            <button data-action="import">导入</button><button data-action="export">导出</button>
            <button data-action="backup" data-installed>备份</button><button data-action="restore" data-installed>恢复备份</button>
            <input id="wg-import" type="file" accept=".conf,.txt" hidden>
          </div>
          <div id="wg-feedback" class="wg-feedback" aria-live="polite"></div>
        </div>
        <div class="wg-pane">
          <div class="wg-toolbar">
            <div class="wg-tabs" role="tablist" aria-label="设备信息">
              <button role="tab" data-view="logs" aria-selected="true">日志</button>
              <button role="tab" data-view="status" aria-selected="false">连接状态</button>
              <button role="tab" data-view="diagnostics" aria-selected="false">诊断</button>
            </div>
            <span class="wg-spacer"></span><button data-action="refresh" title="刷新设备信息" aria-label="刷新设备信息">刷新</button>
          </div>
          <textarea id="Wireguard_embedded_textarea" aria-label="设备输出" readonly spellcheck="false"></textarea>
          <div class="wg-toolbar">
            <label class="wg-switch"><input id="wg-auto" type="checkbox" checked>自动刷新</label>
            <span id="wg-updated" class="wg-note"></span><span class="wg-spacer"></span>
            <button data-action="export-log">导出日志</button>
          </div>
        </div>
      </div>
    </div>
  </div>`;
anchor.insertAdjacentElement("afterend", container);
const find = (selector) => container.querySelector(selector);
const editor = find("#Wireguard_embedded_config");
const output = find("#Wireguard_embedded_textarea");
const feedback = find("#wg-feedback");
const badge = find("#Wireguard_embedded_status_badge");
const dirty = () => editor.value !== state.saved;
function report(message, error = false) { feedback.textContent = message; feedback.dataset.error = String(error); }
function syncControls() {
  container.querySelectorAll("button[data-action], input[data-installed]").forEach((button) => {
    button.disabled = state.busy || (button.hasAttribute("data-installed") && !state.installed);
  });
  find('[data-action="save"]').disabled = state.busy || !state.installed || !state.loaded;
  find('[data-action="stop"]').disabled = state.busy || !state.running;
  editor.readOnly = state.busy;
  find("#wg-boot").checked = state.boot;
  find("#wg-dirty").textContent = dirty() ? "未保存" : state.loaded ? "已读取" : "";
}

async function confirmAction(title, message) {
  const overlay = document.createElement("div");
  overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:#0008;display:flex;align-items:center;justify-content:center;padding:20px";
  const dialog = document.createElement("div");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-label", title);
  dialog.style.cssText = "width:100%;max-width:420px;background:#fff;color:#202324;border-radius:8px;padding:22px;box-shadow:0 12px 40px #0004;font-size:14px";
  const heading = document.createElement("strong"); heading.textContent = title;
  const paragraph = document.createElement("p"); paragraph.textContent = message; paragraph.style.cssText = "line-height:1.7;overflow-wrap:anywhere";
  const buttons = document.createElement("div"); buttons.style.cssText = "display:flex;justify-content:flex-end;gap:10px";
  const cancel = document.createElement("button"); cancel.textContent = "取消";
  const accept = document.createElement("button"); accept.textContent = "确认";
  for (const button of [cancel, accept]) button.style.cssText = "padding:8px 18px;border:1px solid #bbb;border-radius:6px;cursor:pointer;background:#fff;color:#222";
  buttons.append(cancel, accept); dialog.append(heading, paragraph, buttons); overlay.append(dialog);
  const previousFocus = document.activeElement;
  document.body.append(overlay); cancel.focus();
  return new Promise((resolve) => {
    const finish = (value) => { overlay.remove(); previousFocus?.focus(); resolve(value); };
    cancel.onclick = () => finish(false); accept.onclick = () => finish(true);
    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") finish(false);
      if (event.key === "Tab") { event.preventDefault(); (document.activeElement === cancel ? accept : cancel).focus(); }
    });
  });
}

async function requireRoot() {
  if ((await shell("id -u", 10000)).trim() !== "0") throw new Error("请先在管理页面启用高级功能和 root 权限。");
}
async function operation(label, action) {
  if (state.busy) return;
  state.busy = true; clearTimeout(state.timer); state.generation++; syncControls(); report(label);
  try { await requireRoot(); await action(); }
  catch (error) { report(error.message || String(error), true); toast(error.message || String(error), true); }
  finally { state.busy = false; syncControls(); await refresh(false); schedule(); }
}
async function readConfig(ask = true) {
  if (ask && dirty() && !await confirmAction("读取配置", "当前未保存的修改将被设备上的配置替换。")) return;
  const value = await shell(`set -e; [ -f ${quote(CONFIG_PATH)} ]; [ "$(wc -c < ${quote(CONFIG_PATH)})" -le 65536 ]; cat ${quote(CONFIG_PATH)}`, 10000);
  editor.value = value.trim() + "\n"; state.saved = editor.value; state.loaded = true; syncControls(); report("配置已读取。");
}
function checkConfig(show = true) {
  const result = WGConfig.validate(editor.value);
  if (show) report(result.valid ? `校验通过，${result.peers} 个节点。${result.warnings.length ? "\n" + result.warnings.join("\n") : ""}` : result.errors.join("\n"), !result.valid);
  return result;
}
function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const link = document.createElement("a"); link.href = url; link.download = name; document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
async function install() {
  if (state.installed && !await confirmAction("升级资源包", "保留设备上的配置和备份。运行中的连接会短暂中断；升级失败时会尝试恢复旧版本。")) return;
  const token = `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  const archive = `/data/local/tmp/kano-wireguard-${token}.tar.gz`;
  const base64 = `${archive}.b64`;
  try {
    await shell(`umask 077; mkdir -p /data/local/tmp && : > ${quote(base64)}`);
    for (let offset = 0; offset < EMBEDDED_PACKAGE.length; offset += 4096) {
      report(`正在写入资源包 ${Math.round(offset / EMBEDDED_PACKAGE.length * 100)}%`);
      await shell(`printf '%s' ${quote(EMBEDDED_PACKAGE.slice(offset, offset + 4096))} >> ${quote(base64)}`);
    }
    await shell(`set -e; umask 077
if command -v base64 >/dev/null 2>&1; then base64 -d ${quote(base64)} > ${quote(archive)}
elif command -v toybox >/dev/null 2>&1; then toybox base64 -d ${quote(base64)} > ${quote(archive)}
else busybox base64 -d ${quote(base64)} > ${quote(archive)}; fi
[ -s ${quote(archive)} ]`);
    report("正在校验和安装资源包。");
    await shell(`sh -c ${quote(INSTALL_SCRIPT)} installer ${quote(archive)} ${quote(PACKAGE_SHA256)}`, 120000);
    state.installed = true;
    if (!dirty()) await readConfig(false);
    toast("安装完成，已有配置已保留。"); report("资源包安装完成。");
  } finally {
    await shell(`rm -f ${quote(base64)} ${quote(archive)}`).catch(() => {});
  }
}

async function saveConfig() {
  if (state.version !== VERSION) throw new Error(`设备资源为 v${state.version || "未知"}，请先点击“安装 / 升级”更新至 v${VERSION}。`);
  const validation = checkConfig();
  if (!validation.valid) throw new Error(validation.errors.join("\n"));
  if (typeof KANO_baseURL === "undefined" || typeof common_headers === "undefined") throw new Error("管理页面缺少上传接口。");
  const form = new FormData();
  form.append("file", new File([validation.normalized], "wg0.conf", { type: "text/plain" }));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  const headers = new Headers(common_headers);
  headers.delete("Content-Type");
  let response;
  try { response = await fetch(`${KANO_baseURL}/upload_img`, { method: "POST", headers, body: form, signal: controller.signal }); }
  finally { clearTimeout(timeout); }
  if (!response.ok) throw new Error(`配置上传失败：HTTP ${response.status}`);
  const data = await response.json();
  if (typeof data.url !== "string" || !/^\/[A-Za-z0-9_./-]+$/.test(data.url) || data.url.includes("..") || data.url.startsWith("//")) throw new Error("上传接口返回了无效的文件路径。");
  const path = `/data/data/com.minikano.f50_sms/files${data.url}`;
  await shell(`sh ${quote(`${ROOT}/scripts/manage.sh`)} save ${quote(path)}`);
  editor.value = validation.normalized; state.saved = editor.value; syncControls();
  report(state.running ? "配置已保存，旧配置已备份。重启后生效。" : "配置已保存，旧配置已备份。");
  toast("配置保存成功。");
}

const actions = {
  install: () => operation("准备安装。", install),
  read: () => operation("正在读取配置。", () => readConfig()),
  validate: () => checkConfig(),
  save: () => operation("正在保存配置。", saveConfig),
  start: () => operation("正在启动。", async () => { if (dirty() && !await confirmAction("启动", "当前编辑尚未保存，将使用设备上已保存的配置启动。")) return; await shell(`sh ${quote(`${ROOT}/scripts/run.sh`)} start`, 120000); report("启动完成，等待节点握手。"); }),
  stop: () => operation("正在停止。", async () => { await shell(`sh ${quote(`${ROOT}/scripts/run.sh`)} stop`, 60000); report("已停止。"); }),
  restart: () => operation("正在重启。", async () => { if (dirty() && !await confirmAction("重启", "当前编辑尚未保存，将使用设备上已保存的配置重启。")) return; await shell(`sh ${quote(`${ROOT}/scripts/run.sh`)} restart`, 120000); report("重启完成，等待节点握手。"); }),
  backup: () => operation("正在备份。", async () => { await shell(`sh ${quote(`${ROOT}/scripts/manage.sh`)} backup`); report("设备上已保存的配置已备份。"); }),
  restore: () => operation("准备恢复。", async () => { if (!await confirmAction("恢复备份", "备份将替换当前配置和未保存的编辑，当前设备配置会成为新备份。运行中的连接需要重启后生效。")) return; await shell(`sh ${quote(`${ROOT}/scripts/manage.sh`)} restore`); await readConfig(false); report("备份已恢复，重启后生效。"); }),
  uninstall: () => operation("准备卸载。", async () => { if (!await confirmAction("卸载 WireGuard", "将停止连接，并删除资源、配置、备份和开机自启项。")) return; await shell(`sh ${quote(`${ROOT}/scripts/manage.sh`)} uninstall`, 60000); state.installed = false; state.running = false; state.boot = false; state.loaded = false; state.saved = ""; editor.value = ""; report("已卸载。"); }),
  refresh: () => refresh(true),
  import: () => find("#wg-import").click(),
  export: async () => { if (!editor.value.trim()) return toast("没有可导出的配置。", true); if (await confirmAction("导出配置", "导出的文件包含私钥，请妥善保管。")) download("wg0.conf", editor.value); },
  "export-log": () => download(`wireguard-${state.view}.txt`, WGConfig.redact(output.value))
};

container.querySelectorAll("button[data-action]").forEach((button) => button.addEventListener("click", () => Promise.resolve(actions[button.dataset.action]()).catch((error) => toast(error.message, true))));
editor.addEventListener("input", syncControls);
find("#wg-boot").addEventListener("change", (event) => {
  const enabled = event.target.checked;
  operation("正在设置开机自启。", async () => { await shell(`sh ${quote(`${ROOT}/scripts/manage.sh`)} ${enabled ? "boot-on" : "boot-off"}`); state.boot = enabled; report(enabled ? "已启用开机自启。" : "已关闭开机自启。"); });
});
find("#wg-auto").addEventListener("change", (event) => { state.auto = event.target.checked; schedule(); });
find("#wg-import").addEventListener("change", async (event) => {
  const file = event.target.files[0]; event.target.value = "";
  if (!file) return;
  try {
    if (file.size > 65536) throw new Error("配置文件不能超过 64 KiB。");
    if (dirty() && !await confirmAction("导入配置", "当前未保存的编辑将被导入内容替换。")) return;
    const result = WGConfig.validate(await file.text());
    editor.value = result.normalized;
    state.loaded = state.installed; syncControls(); checkConfig();
  } catch (error) { toast(error.message, true); }
});
container.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => {
  state.view = button.dataset.view; state.generation++;
  container.querySelectorAll("[data-view]").forEach((item) => item.setAttribute("aria-selected", String(item === button)));
  output.value = "正在读取。"; refresh(true);
}));

async function refresh(showErrors = false) {
  if (state.busy || !container.isConnected) return;
  if (state.polling) { state.pendingRefresh = state.pendingRefresh || showErrors; return; }
  state.polling = true;
  const generation = state.generation;
  const view = state.view;
  try {
    const status = await shell(`
if [ -f ${quote(`${ROOT}/scripts/manage.sh`)} ]; then echo INSTALLED=1; else echo INSTALLED=0; fi
if [ -f ${quote(`${ROOT}/service.sh`)} ]; then echo PRESENT=1; fi
if [ -f ${quote(`${ROOT}/VERSION`)} ]; then printf 'VERSION='; cat ${quote(`${ROOT}/VERSION`)}; fi
if ${quote(`${ROOT}/bin/wg`)} show interfaces 2>/dev/null | tr ' ' '\\n' | grep -qx wg0; then
  echo RUNNING=1
  printf 'HANDSHAKE='; ${quote(`${ROOT}/bin/wg`)} show wg0 latest-handshakes | awk 'BEGIN {latest=0} {if ($2>latest) latest=$2} END {print latest}'
else echo RUNNING=0; fi
if [ -f ${quote(BOOT)} ] && grep -qxF ${quote(BOOT_LINE)} ${quote(BOOT)}; then echo BOOT=1; else echo BOOT=0; fi
`, 10000);
    if (generation !== state.generation || state.busy) return;
    state.installed = /^INSTALLED=1$/m.test(status); state.running = /^RUNNING=1$/m.test(status); state.boot = /^BOOT=1$/m.test(status);
    const installedVersion = /^VERSION=(.*)$/m.exec(status)?.[1];
    state.version = installedVersion || "";
    const handshake = Number(/^HANDSHAKE=(\d+)$/m.exec(status)?.[1] || 0);
    const recentHandshake = handshake > 0 && Date.now() / 1000 - handshake < 180;
    badge.textContent = state.running ? (recentHandshake ? "运行中 · 最近已握手" : handshake ? "运行中 · 握手较早" : "运行中 · 等待握手") : state.installed ? "已停止" : /^PRESENT=1$/m.test(status) ? "旧版资源 · 请升级" : "未安装";
    if (state.installed && state.version !== VERSION) badge.textContent += " · 资源待升级";
    badge.dataset.state = state.running ? "running" : "stopped";
    badge.title = installedVersion ? `设备资源 v${installedVersion}` : "";
    syncControls();
    if (!state.open) return;
    let text;
    if (view === "logs") text = await shell(`for file in ${quote(`${ROOT}/logs/run.log`)} ${quote(`${ROOT}/logs/wireguard.log.1`)} ${quote(`${ROOT}/logs/wireguard.log`)}; do if [ -f "$file" ]; then tail -n 100 "$file"; fi; done`, 10000);
    else if (view === "status") text = state.running ? await shell(`${quote(`${ROOT}/bin/wg`)} show wg0`, 10000) : "WireGuard 已停止。";
    else if (state.installed && showErrors) text = await shell(`sh ${quote(`${ROOT}/scripts/manage.sh`)} diagnostics; exit 0`, 30000);
    else if (view === "diagnostics") return;
    if (generation !== state.generation || state.busy || view !== state.view) return;
    const atBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 40;
    output.value = WGConfig.redact(text || (view === "logs" ? "暂无日志。" : "尚无连接。"));
    if (atBottom) output.scrollTop = output.scrollHeight;
    find("#wg-updated").textContent = new Date().toLocaleTimeString();
  } catch (error) {
    if (generation !== state.generation) return;
    badge.textContent = "设备连接异常"; badge.dataset.state = "error";
    if (showErrors) { output.value = error.message; toast(error.message, true); }
  } finally {
    state.polling = false;
    if (state.pendingRefresh) { state.pendingRefresh = false; setTimeout(() => refresh(true), 0); }
    else schedule();
  }
}
function schedule() {
  clearTimeout(state.timer);
  if (state.open && state.auto && !state.busy && !document.hidden && container.isConnected) state.timer = setTimeout(() => refresh(false), 5000);
}
async function setOpen(open) {
  state.open = open; state.generation++; clearTimeout(state.timer);
  if (open) {
    await refresh(false);
    if (state.installed && !state.loaded && !dirty()) {
      try { await readConfig(false); } catch (error) { report(error.message, true); }
    }
    schedule();
  }
}
document.addEventListener("visibilitychange", () => { if (document.hidden) clearTimeout(state.timer); else if (state.open) refresh(false); });
window.addEventListener("beforeunload", (event) => { if (dirty()) { event.preventDefault(); event.returnValue = ""; } });
if (typeof collapseGen === "function") {
  collapseGen("#collapse_Wireguard_Embedded_btn", COLLAPSE, COLLAPSE, (value) => setOpen(value === "open"));
  let open = false;
  try { open = localStorage.getItem(COLLAPSE) === "open"; } catch { /* Storage can be disabled in embedded browsers. */ }
  await setOpen(open);
} else {
  const button = document.createElement("button"); button.textContent = "展开";
  find("#collapse_Wireguard_Embedded_btn").append(button);
  button.onclick = () => { const open = !state.open; find(COLLAPSE).style.height = open ? "auto" : "0"; button.textContent = open ? "收起" : "展开"; setOpen(open); };
}
await refresh(false);
syncControls();
