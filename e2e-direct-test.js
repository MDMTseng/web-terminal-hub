const { chromium } = require('playwright');

// Test ttyd directly — does it crash when accessed directly?
async function runTest() {
  console.log('Testing ttyd DIRECTLY on port 7681...\n');

  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();

  page.on('console', msg => console.log(`[browser:${msg.type()}] ${msg.text()}`));
  page.on('websocket', ws => {
    console.log(`[ws:open] ${ws.url()}`);
    ws.on('framereceived', frame => {
      console.log(`[ws:recv] <${typeof frame.payload === 'string' ? frame.payload.length + ' chars' : 'binary'}>`);
    });
    ws.on('framesent', frame => {
      console.log(`[ws:sent] <${typeof frame.payload === 'string' ? frame.payload.length + ' chars' : 'binary'}>`);
    });
    ws.on('close', () => console.log(`[ws:close]`));
  });
  page.on('requestfailed', req => {
    console.log(`[network:FAIL] ${req.method()} ${req.url()} - ${req.failure()?.errorText}`);
  });

  try {
    // First start a ttyd directly
    const resp = await page.goto('http://localhost:7681/', { waitUntil: 'networkidle', timeout: 10000 });
    console.log(`Status: ${resp.status()}`);
    console.log(`Title: ${await page.title()}`);

    // Wait and observe
    console.log('\nWaiting 10s to observe WebSocket behavior...');
    await page.waitForTimeout(10000);

    console.log('\nTaking screenshot...');
    await page.screenshot({ path: '/c/Users/TRS001/.claude/web-terminal-hub/direct-test-screenshot.png' });

  } catch (err) {
    console.error(`ERROR: ${err.message}`);
  } finally {
    await browser.close();
    console.log('Done.');
  }
}

runTest();
