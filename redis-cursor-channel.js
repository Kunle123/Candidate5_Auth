const { createClient } = require('redis');
const { exec } = require('child_process');

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const CHANNEL = process.env.CURSOR_CHANNEL || 'cursor-messages';
const SERVICE = process.env.CURSOR_SERVICE || 'general'; // Set this per instance (e.g., 'auth', 'cv', 'frontend')

const client = createClient({ url: REDIS_URL });
const subscriber = client.duplicate();

async function main() {
  await client.connect();
  await subscriber.connect();

  // Listen for messages
  await subscriber.subscribe(CHANNEL, async (message) => {
    console.log(`[${CHANNEL}] Received:`, message);
    let data;
    try {
      data = JSON.parse(message);
    } catch (e) {
      // Not a JSON message, ignore or log
      return;
    }
    // Only respond if the message is for this service or for all
    if (data.service === SERVICE || data.service === 'all') {
      if (data.action === 'test') {
        // Example: Run tests for this service
        exec('npm test', (err, stdout, stderr) => {
          const response = {
            service: SERVICE,
            action: 'test-result',
            status: err ? 'fail' : 'pass',
            output: stdout || stderr || (err && err.message)
          };
          client.publish(CHANNEL, JSON.stringify(response));
        });
      } else if (data.action === 'status') {
        // Example: Respond with service status
        const response = {
          service: SERVICE,
          action: 'status-result',
          status: 'running',
          timestamp: new Date().toISOString()
        };
        client.publish(CHANNEL, JSON.stringify(response));
      }
      // Add more actions as needed
    }
  });

  // Send a message from stdin (raw or JSON)
  process.stdin.on('data', async (data) => {
    const msg = data.toString().trim();
    if (msg) {
      await client.publish(CHANNEL, msg);
      console.log(`[${CHANNEL}] Sent:`, msg);
    }
  });

  console.log(`Listening on channel "${CHANNEL}" as service "${SERVICE}". Type a message and press Enter to send.`);
}

main().catch(console.error); 