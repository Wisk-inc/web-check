import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { main, parseArgs, toOptions } from '../cli.js';
import { renderHtml } from '../lib/report.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('arguments are split into positionals and typed flags', () => {
  const { positional, flags } = parseArgs([
    'jamaica',
    'lottery',
    '--depth=2',
    '--pages',
    'all',
    '--json',
    '--query',
    'a',
    '--query',
    'b',
  ]);
  assert.deepEqual(positional, ['jamaica', 'lottery']);
  assert.deepEqual(flags, { depth: '2', pages: 'all', json: true, query: ['a', 'b'] });
  assert.throws(() => parseArgs(['--nope']), /Unknown option/);
  assert.throws(() => parseArgs(['--depth']), /needs a value/);
});

test('--deep widens every limit but respects explicit choices', () => {
  const deep = toOptions({ deep: true, depth: '1', time: '60' });
  assert.equal(deep.depth, '1');
  assert.equal(deep.pages, 'all');
  assert.equal(deep.timeBudgetMs, 60000);
  assert.equal(toOptions({ 'no-cache': true }).cacheDir, false);
});

test('usage mistakes exit with code 2 and a pointer to help', async () => {
  const write = process.stderr.write;
  let captured = '';
  process.stderr.write = (chunk) => {
    captured += chunk;
    return true;
  };
  try {
    assert.equal(await main(['bogus']), 2);
    assert.equal(await main(['investigate']), 2);
    assert.equal(await main(['hunt']), 2);
  } finally {
    process.stderr.write = write;
  }
  assert.match(captured, /Unknown command "bogus"/);
  assert.match(captured, /cli\.js help/);
});

test('the hosted page is in step with the viewer sources', () => {
  const built = fs.readFileSync(
    path.join(here, '..', '..', 'public', 'scam-finder', 'index.html'),
    'utf8',
  );
  assert.equal(
    built,
    renderHtml(null),
    'run "node scam-finder/cli.js build-viewer" after editing scam-finder/viewer/',
  );
});

// Talk to the MCP server the way a client does: JSON-RPC lines over stdin and stdout
const mcpSession = (messages) =>
  new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(here, '..', 'mcp-server.js')], {
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    const replies = [];
    let buffer = '';
    const expected = messages.filter((message) => message.id !== undefined).length;
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) if (line.trim()) replies.push(JSON.parse(line));
      if (replies.length >= expected) child.stdin.end();
    });
    child.on('error', reject);
    child.on('close', () => resolve(replies));
    for (const message of messages) child.stdin.write(`${JSON.stringify(message)}\n`);
  });

test('the MCP server completes a handshake and lists its tools', async () => {
  const replies = await mcpSession([
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'test', version: '0' },
      },
    },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'list_hunt_profiles', arguments: {} },
    },
    {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'get_domain_details', arguments: { result_file: '/nonexistent.json' } },
    },
    { jsonrpc: '2.0', id: 5, method: 'no/such/method' },
    {
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: { name: 'contact_lookup', arguments: { value: '+1 876 555 0142' } },
    },
  ]);
  const byId = Object.fromEntries(replies.map((message) => [message.id, message]));
  assert.equal(byId[1].result.protocolVersion, '2025-06-18');
  assert.equal(byId[1].result.serverInfo.name, 'scam-finder');
  const tools = byId[2].result.tools.map((tool) => tool.name);
  assert.deepEqual(tools, [
    'investigate_url',
    'hunt_scams',
    'get_domain_details',
    'render_report',
    'radar_status',
    'radar_sites',
    'radar_site',
    'radar_events',
    'radar_scan',
    'radar_ingest',
    'contact_lookup',
    'list_hunt_profiles',
  ]);
  for (const tool of byId[2].result.tools) assert.equal(tool.inputSchema.type, 'object');
  const profiles = JSON.parse(byId[3].result.content[0].text);
  assert.ok(profiles.some((profile) => profile.id === 'jamaica'));
  // A failing tool is a readable result for the model, not a protocol error
  assert.equal(byId[4].result.isError, true);
  assert.equal(byId[5].error.code, -32601);
  const contact = JSON.parse(byId[6].result.content[0].text);
  assert.equal(contact.country, 'JM');
  assert.match(contact.caveat, /not as the identity of a person/);
});
