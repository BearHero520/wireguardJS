const { defineConfig } = require("@playwright/test");
const fs = require("node:fs");
const edge = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
module.exports = defineConfig({
  testDir: "./tests",
  testMatch: "ui.spec.cjs",
  timeout: 20000,
  fullyParallel: true,
  workers: 2,
  reporter: "list",
  use: { headless: true, launchOptions: fs.existsSync(edge) ? { executablePath: edge } : {} }
});
