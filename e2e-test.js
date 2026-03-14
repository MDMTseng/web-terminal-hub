const { chromium } = require('playwright');

const HUB_URL = process.env.TEST_URL || 'http://localhost:9090';
const TUNNEL_URL = process.env.TUNNEL_URL || '';

async function runTest(url, label) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  E2E Test: ${label}`);
  console.log(`  URL: ${url}`);
  console.log(`${'='.repeat(60)}\n`);

  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  page.on('console', msg => {
    console.log(`  [browser:${msg.type()}] ${msg.text()}`);
  });

  page.on('requestfailed', req => {
    console.log(`  [network:FAIL] ${req.method()} ${req.url()} - ${req.failure()?.errorText}`);
  });

  page.on('websocket', ws => {
    console.log(`  [ws:open] ${ws.url()}`);
    ws.on('framereceived', frame => {
      const data = frame.payload;
      if (typeof data === 'string') {
        const preview = data.length > 150 ? data.substring(0, 150) + '...' : data;
        console.log(`  [ws:recv] ${preview}`);
      } else {
        console.log(`  [ws:recv] <binary>`);
      }
    });
    ws.on('framesent', frame => {
      const data = frame.payload;
      if (typeof data === 'string') {
        console.log(`  [ws:sent] ${data.substring(0, 100)}`);
      } else {
        console.log(`  [ws:sent] <binary>`);
      }
    });
    ws.on('close', () => console.log(`  [ws:close]`));
  });

  try {
    // Step 1: Load hub
    console.log('[step 1] Loading hub page...');
    const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
    console.log(`  Status: ${resp.status()}`);

    // Step 2: Welcome screen
    console.log('\n[step 2] Checking welcome screen...');
    const welcomeVisible = await page.isVisible('#welcome');
    console.log(`  Welcome visible: ${welcomeVisible}`);

    // Step 3: Create bash terminal
    console.log('\n[step 3] Creating Bash terminal...');
    await page.click('.quick-launch button:first-child');
    console.log('  Clicked Bash, waiting 5s...');
    await page.waitForTimeout(5000);

    // Step 4: Check tabs
    console.log('\n[step 4] Checking tabs...');
    const tabs = await page.$$('.tab');
    console.log(`  Tabs: ${tabs.length}`);

    // Step 5: Check terminal container
    console.log('\n[step 5] Checking terminal...');
    const containers = await page.$$('.terminal-container');
    console.log(`  Containers: ${containers.length}`);

    // Step 6: Check if xterm rendered
    const xtermExists = await page.isVisible('.xterm');
    console.log(`  xterm visible: ${xtermExists}`);

    // Step 7: Check API
    console.log('\n[step 7] Checking API...');
    const apiResp = await page.evaluate(async () => {
      const r = await fetch('/api/terminals');
      return await r.json();
    });
    console.log(`  Active terminals: ${JSON.stringify(apiResp)}`);

    // Step 8: Try typing something
    console.log('\n[step 8] Typing "echo hello"...');
    await page.keyboard.type('echo hello');
    await page.waitForTimeout(1000);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(2000);

    // Step 9: Screenshot
    const screenshotPath = url.includes('localhost')
      ? '/c/Users/TRS001/.claude/web-terminal-hub/test-local.png'
      : '/c/Users/TRS001/.claude/web-terminal-hub/test-tunnel.png';
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`\n[step 9] Screenshot: ${screenshotPath}`);

    // Wait
    console.log('\n[waiting] 5s more...');
    await page.waitForTimeout(5000);

  } catch (err) {
    console.error(`\n[ERROR] ${err.message}`);
  } finally {
    await browser.close();
    console.log('\n[done] Browser closed.');
  }
}

(async () => {
  await runTest(HUB_URL, 'Local');
  if (TUNNEL_URL) {
    await runTest(TUNNEL_URL, 'Cloudflare Tunnel');
  }
})();
