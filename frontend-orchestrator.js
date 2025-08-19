const { createClient } = require('redis');
const fetch = require('node-fetch');

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const CHANNEL = process.env.CURSOR_CHANNEL || 'cursor-messages';
const SERVICE = 'frontend';

const client = createClient({ url: REDIS_URL });
const subscriber = client.duplicate();

const CV_ENDPOINTS = [
  '/cvs',
  '/cvs/1', // Example: you may want to replace '1' with a valid ID or test for 404
  '/cvs/create',
];
const BASE_URL = 'https://api-gw-production.up.railway.app';

async function checkCvEndpoints() {
  const results = [];
  for (const endpoint of CV_ENDPOINTS) {
    try {
      const res = await fetch(BASE_URL + endpoint);
      const body = await res.text();
      results.push({
        endpoint,
        status: res.status,
        ok: res.ok,
        snippet: body.slice(0, 100)
      });
    } catch (e) {
      results.push({
        endpoint,
        status: 'error',
        ok: false,
        snippet: e.message
      });
    }
  }
  return results;
}

async function main() {
  await client.connect();
  await subscriber.connect();

  await subscriber.subscribe(CHANNEL, async (message) => {
    console.log(`[${CHANNEL}] Received:`, message);
    let data;
    let isJson = false;
    try {
      data = JSON.parse(message);
      isJson = true;
    } catch (e) {
      data = { text: message };
    }
    // Determine if the message is for this service
    const addressedToService =
      (isJson && (data.service === SERVICE || data.service === 'all')) ||
      (!isJson && (data.text || '').toLowerCase().includes(SERVICE));
    if (!addressedToService) return;
    // Handle explicit JSON actions
    if (isJson && data.action) {
      if (data.action === 'check-cv-endpoints') {
        const results = await checkCvEndpoints();
        await client.publish(CHANNEL, JSON.stringify({
          service: SERVICE,
          action: 'cv-endpoints-status',
          checklist: results,
          timestamp: new Date().toISOString()
        }));
        return;
      }
      if (data.action === 'check-cv-service') {
        const response = {
          service: SERVICE,
          action: 'cv-service-status',
          status: 'CV service is up and reachable!',
          timestamp: new Date().toISOString()
        };
        await client.publish(CHANNEL, JSON.stringify(response));
        return;
      }
    }
    // Robustly extract text for conversational messages
    let text = '';
    if (isJson && typeof message === 'string') {
      text = message.toLowerCase();
    } else if (data.text) {
      text = data.text.toLowerCase();
    } else {
      text = String(message).toLowerCase();
    }
    if (text.includes('check cv endpoints')) {
      const results = await checkCvEndpoints();
      await client.publish(CHANNEL, JSON.stringify({
        service: SERVICE,
        action: 'cv-endpoints-status',
        checklist: results,
        conversational: true,
        timestamp: new Date().toISOString()
      }));
      return;
    }
    if (text.includes('check cv service')) {
      const response = {
        service: SERVICE,
        action: 'cv-service-status',
        status: 'CV service is up and reachable!',
        conversational: true,
        timestamp: new Date().toISOString()
      };
      await client.publish(CHANNEL, JSON.stringify(response));
      return;
    }
    // Fallback conversational response
    await client.publish(CHANNEL, JSON.stringify({
      service: SERVICE,
      action: 'conversational-response',
      message: `Hi! I received your message: "${text}". How can I help you with the frontend?`,
      timestamp: new Date().toISOString()
    }));
  });

  process.stdin.on('data', async (data) => {
    const msg = data.toString().trim();
    if (msg) {
      await client.publish(CHANNEL, msg);
      console.log(`[${CHANNEL}] Sent:`, msg);
    }
  });

  console.log(`Frontend orchestrator listening on channel "${CHANNEL}". Type a message and press Enter to send.`);
}

main().catch(console.error); 