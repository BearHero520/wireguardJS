const { test, expect } = require("@playwright/test");
const { pathToFileURL } = require("node:url");
const path = require("node:path");
const url = pathToFileURL(path.resolve(__dirname, "../preview.html")).href;
const editor = "#Wireguard_embedded_config";

test.beforeEach(async ({ page }) => {
  await page.goto(url);
  await expect(page.locator(editor)).toHaveValue(/PrivateKey/);
});
test("validates, saves with backup, and marks restart required", async ({ page }) => {
  await page.locator('[data-action="start"]').click();
  await expect(page.locator("#Wireguard_embedded_status_badge")).toHaveText(/运行中/);
  const config = await page.locator(editor).inputValue();
  await page.locator(editor).fill(config.replace("10.0.0.2/24", "10.0.0.3/24"));
  await page.locator('[data-action="save"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/重启后生效/);
  expect(await page.evaluate(() => previewDevice.backup)).toBe(config);
  expect(await page.evaluate(() => previewDevice.config)).toContain("10.0.0.3/24");
});
test("reports save failure and preserves unsaved editing", async ({ page }) => {
  await page.evaluate(() => { previewDevice.failSave = true; });
  const config = await page.locator(editor).inputValue();
  await page.locator(editor).fill(config.replace("10.0.0.2/24", "10.0.0.4/24"));
  await page.locator('[data-action="save"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/No space left/);
  await expect(page.locator("#wg-dirty")).toHaveText("未保存");
  expect(await page.evaluate(() => previewDevice.config)).toBe(config);
});
test("read failure does not erase the editor", async ({ page }) => {
  const config = await page.locator(editor).inputValue();
  await page.evaluate(() => { previewDevice.failRead = true; });
  await page.locator('[data-action="read"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/read failed/);
  await expect(page.locator(editor)).toHaveValue(config);
});
test("invalid IPv6 config never uploads", async ({ page }) => {
  const config = await page.locator(editor).inputValue();
  await page.locator(editor).fill(config.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/129"));
  await page.locator('[data-action="save"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/IPv4/);
  expect(await page.evaluate(() => previewDevice.uploaded)).toBe("");
});
test("cancel uninstall leaves the installed device unchanged", async ({ page }) => {
  await page.locator('[data-action="uninstall"]').click();
  await page.getByRole("dialog").getByRole("button", { name: "取消" }).click();
  expect(await page.evaluate(() => previewDevice.installed)).toBe(true);
});
test("accepts and saves a complete dual-stack configuration", async ({ page }) => {
  const config = await page.locator(editor).inputValue();
  const dual = config.replace("Address = 10.0.0.2/24", "Address = 10.6.0.2/32, fd00:6::2/128").replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0");
  await page.locator(editor).fill(dual);
  await page.locator('[data-action="save"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/配置已保存/);
  expect(await page.evaluate(() => previewDevice.config)).toContain("fd00:6::2/128");
  expect(await page.evaluate(() => previewDevice.config)).toContain("0.0.0.0/0, ::/0");
});
test("old device resources must be upgraded before saving new configurations", async ({ page }) => {
  await page.evaluate(() => { previewDevice.version = "2.0.0"; });
  await page.locator('[data-action="refresh"]').click();
  await expect(page.locator("#Wireguard_embedded_status_badge")).toHaveText(/资源待升级/);
  await page.locator('[data-action="save"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/安装 \/ 升级/);
  expect(await page.evaluate(() => previewDevice.uploaded)).toBe("");
});
test("NAT6 routed mode warns about server routes and preserves IPv4 NAT on save", async ({ page }) => {
  const config = await page.locator(editor).inputValue();
  const routed = config.replace("Address = 10.0.0.2/24", "Address = 10.6.0.2/32, fd00:6::2/128")
    .replace("NAT = true", "NAT = true\nNAT6 = false")
    .replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0");
  await page.locator(editor).fill(routed);
  await page.locator('[data-action="validate"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/AllowedIPs.*LAN IPv6/);
  await page.locator('[data-action="save"]').click();
  await expect(page.locator("#wg-feedback")).toHaveText(/配置已保存/);
  expect(await page.evaluate(() => previewDevice.config)).toContain("NAT = true\nNAT6 = false");
});
for (const viewport of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
  test(`layout and diagnostics at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await page.getByRole("tab", { name: "诊断" }).click();
    await expect(page.locator("#Wireguard_embedded_textarea")).toHaveValue(/Architecture/);
    const size = await page.evaluate(() => ({ width: document.documentElement.scrollWidth, viewport: innerWidth }));
    expect(size.width).toBeLessThanOrEqual(size.viewport);
    const panes = await page.locator(".wg-pane").evaluateAll((elements) => elements.map((element) => { const r = element.getBoundingClientRect(); return { x:r.x, y:r.y, right:r.right, bottom:r.bottom }; }));
    if (viewport.width < 680) expect(panes[1].y).toBeGreaterThanOrEqual(panes[0].bottom);
    else expect(panes[1].x).toBeGreaterThanOrEqual(panes[0].right);
    await page.screenshot({ path: `test-results/preview-${viewport.width}.png`, fullPage: true });
  });
}
