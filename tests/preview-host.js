/* Browser-only device simulator. It never executes a shell or contacts a device. */
const sampleKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(1)));
const peerKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(2)));
const exampleConfig = `[Interface]\nPrivateKey = ${sampleKey}\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\nNAT = true\nLANInterface = br0\n\n[Peer]\nPublicKey = ${peerKey}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n`;
window.previewDevice = { installed: true, version: "2.1.0", running: false, boot: false, config: exampleConfig, backup: exampleConfig, failSave: false, failRead: false, uploaded: "", calls: [], active: 0, maxActive: 0 };
const KANO_baseURL = "https://preview.invalid";
const common_headers = {};
window.createToast = (message, color, duration = 3000) => {
  const toast = document.createElement("div"); toast.className = "toast"; toast.textContent = message;
  toast.dataset.color = color; document.querySelector(".toasts").append(toast); setTimeout(() => toast.remove(), duration);
};
window.collapseGen = (buttonSelector, panelSelector, storageKey, callback) => {
  const button = document.createElement("button"); button.textContent = "收起";
  const panel = document.querySelector(panelSelector); panel.style.height = "auto";
  document.querySelector(buttonSelector).append(button);
  let open = true;
  localStorage.setItem(storageKey, "open");
  button.onclick = () => { open = !open; button.textContent = open ? "收起" : "展开"; panel.style.height = open ? "auto" : "0"; callback(open ? "open" : "close"); };
};
window.runShellWithRoot = async (command) => {
  const device = window.previewDevice;
  device.calls.push(command); device.active++; device.maxActive = Math.max(device.maxActive, device.active);
  await new Promise((resolve) => setTimeout(resolve, 25));
  let content = "";
  let code = 0;
  const script = command.replaceAll("'\\''", "'");
  if (script.includes("INSTALLED=1")) content = `INSTALLED=${Number(device.installed)}\nPRESENT=${Number(device.installed)}\nVERSION=${device.version}\nRUNNING=${Number(device.running)}\nHANDSHAKE=${device.running ? Math.floor(Date.now()/1000) - 20 : 0}\nBOOT=${Number(device.boot)}`;
  else if (script.includes("id -u")) content = "0";
  else if (script.includes("wc -c") && script.includes("cat '/data/kano_wireguard/wg0.conf'")) {
    if (device.failRead) { code = 1; content = "Configuration read failed"; } else content = device.config;
  }
  else if (script.includes("manage.sh' save")) {
    if (device.failSave) { code = 1; content = "mv: No space left on device"; }
    else { device.backup = device.config; device.config = device.uploaded; content = "SAVED"; }
  }
  else if (script.includes("manage.sh' backup")) { device.backup = device.config; content = "BACKED_UP"; }
  else if (script.includes("manage.sh' restore")) { const old = device.config; device.config = device.backup; device.backup = old; content = "RESTORED"; }
  else if (script.includes("manage.sh' boot-on")) device.boot = true;
  else if (script.includes("manage.sh' boot-off")) device.boot = false;
  else if (script.includes("manage.sh' uninstall")) { device.installed = false; device.running = false; device.boot = false; }
  else if (script.includes("manage.sh' diagnostics")) content = "Version: 2.1.0\nArchitecture: aarch64\nIdentity: uid=0(root)\n\nInterfaces:\nbr0  UP  192.168.1.1/24\nwg0  UP  10.0.0.2/24\n\nIPv6 policy rules:\n100: from all fwmark 0x2 lookup 101\n\nConfiguration check: passed";
  else if (script.includes("run.sh' start") || script.includes("run.sh' restart")) device.running = true;
  else if (script.includes("run.sh' stop")) device.running = false;
  else if (script.includes("show wg0")) content = `interface: wg0\n  public key: ${sampleKey}\n  private key: (hidden)\n\npeer: ${peerKey}\n  endpoint: 203.0.113.5:51820\n  allowed ips: 0.0.0.0/0\n  latest handshake: 20 seconds ago\n  transfer: 2.18 MiB received, 544 KiB sent`;
  else if (script.includes("tail -n")) content = "2026-09-30 12:00:00 wireguard started\n2026-09-30 12:00:01 applied DNS rules\n2026-09-30 12:00:01 LAN policy routing active";
  else if (script.includes("installer '/data/local/tmp/")) { device.installed = true; device.version = "2.1.0"; content = "INSTALLED"; }
  device.active--;
  return { success: code === 0, content: `${content}\n__KANO_WG_EXIT__${code}\n` };
};
window.fetch = async (url, options) => {
  if (url !== `${KANO_baseURL}/upload_img`) throw new Error("Network access is disabled in the preview.");
  window.previewDevice.uploaded = await options.body.get("file").text();
  return new Response(JSON.stringify({ url: "/uploads/preview-wg0.conf" }), { status: 200, headers: { "Content-Type": "application/json" } });
};
