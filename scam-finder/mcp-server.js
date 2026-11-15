#!/usr/bin/env node
// Model Context Protocol server for the scam finder, so AI agents can call it as tools
// Speaks JSON-RPC over stdin/stdout with no dependencies:
//
//   { "mcpServers": { "scam-finder": { "command": "node", "args": ["scam-finder/mcp-server.js"] } } }
//
// Each run saves its full result to disk and returns a short digest, so a big investigation
// never floods the agent's context; get_domain_details reads back any part of it on demand

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { PROFILES, defang, hunt, investigate } from './lib/index.js';
import { compactResult, renderHtml, renderMarkdown } from './lib/report.js';

const SERVER = { name: 'scam-finder', version: '1.0.0' };
const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const OUT_DIR = process.env.SCAM_FINDER_OUT_DIR || path.join(os.tmpdir(), 'scam-finder-results');

const INSTRUCTIONS =
  'Scam Finder maps the websites and infrastructure behind a scam link using public data ' +
  '(urlscan.io, DNS, RDAP, Certificate Transparency and scam blocklists). Start with ' +
  'investigate_url for a specific link, or hunt_scams to collect fresh leads by theme ' +
  '(for example the "jamaica" profile). Both save a full JSON result and an interactive HTML ' +
  'map to disk and return a digest; use get_domain_details to drill into one domain. Risk ' +
  'scores are evidence-based estimates for triage, not proof: say so when reporting them, ' +
  'and keep indicators defanged (hxxp, [.]) when quoting them to people.';

const depthSchema = {
  type: 'integer',
  minimum: 0,
  maximum: 2,
  description:
    '0 = profile the target only; 1 = also find sites sharing its fingerprints (default); 2 = search again from every campaign found (slower, wider).',
};
const limitsSchema = {
  time_budget_seconds: {
    type: 'integer',
    minimum: 10,
    maximum: 900,
    description: 'Stop gracefully after this long and return what was found. Default 120.',
  },
  max_domains: {
    type: 'integer',
    minimum: 1,
    maximum: 2000,
    description: 'Stop collecting after this many domains. Default 400.',
  },
  live_checks: {
    type: 'integer',
    minimum: 0,
    maximum: 2000,
    description:
      'How many of the sites found to visit, to confirm what they serve right now. Default 15.',
  },
  feeds: {
    type: 'string',
    description: 'Blocklists to check against: none, light, default or all. Default "default".',
  },
  domains_in_reply: {
    type: 'integer',
    minimum: 1,
    maximum: 200,
    description:
      'How many domains to include in the reply digest (highest risk first). Default 30.',
  },
};

const TOOLS = [
  {
    name: 'investigate_url',
    description:
      'Investigate a suspicious URL or domain. Profiles it (page content, cloaking, kit signatures, registration, DNS, hosting, blocklists), ' +
      'then finds other sites that share its fingerprints: the same kit files, page title, dedicated server, TLS certificate or tracking IDs. ' +
      'Returns a risk score with the reasons behind it, the campaigns and related domains found, and paths to the full JSON result and an interactive HTML map. ' +
      'Read-only: it only fetches public pages and public intelligence sources.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description:
            'The URL or domain to investigate. Defanged input (hxxps://example[.]com) is accepted.',
        },
        depth: depthSchema,
        ...limitsSchema,
      },
      required: ['target'],
    },
  },
  {
    name: 'hunt_scams',
    description:
      'Collect fresh scam leads without a starting link, from saved hunt profiles, raw urlscan.io search queries, or keywords matched against blocklists. ' +
      `Profiles: ${Object.entries(PROFILES)
        .map(([id, profile]) => `${id} (${profile.name})`)
        .join('; ')}. ` +
      'Leads are candidates, each scored on its own evidence; many will be legitimate sites that merely matched a query, so check scores and reasons before calling anything a scam.',
    inputSchema: {
      type: 'object',
      properties: {
        profiles: {
          type: 'array',
          items: { type: 'string', enum: Object.keys(PROFILES) },
          description: 'Hunt profiles to run.',
        },
        queries: {
          type: 'array',
          items: { type: 'string' },
          description: 'Extra urlscan.io search queries, e.g. page.title:"claim your prize".',
        },
        keywords: {
          type: 'array',
          items: { type: 'string' },
          description: 'Words to look for in blocklisted hostnames, e.g. "jncb".',
        },
        ...limitsSchema,
      },
    },
  },
  {
    name: 'get_domain_details',
    description:
      'Read the complete record for one or more domains from a saved result: every risk signal, registration and DNS data, live-check findings, scan history and how each was found. ' +
      'Use the result_file path returned by investigate_url or hunt_scams.',
    inputSchema: {
      type: 'object',
      properties: {
        result_file: { type: 'string', description: 'Path of a saved result JSON file.' },
        domains: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Domains to look up (defanged or not). Omit to list every domain with its score.',
        },
      },
      required: ['result_file'],
    },
  },
  {
    name: 'render_report',
    description:
      'Re-render a saved result as an interactive HTML map (single self-contained file) or a Markdown report, and return the path written.',
    inputSchema: {
      type: 'object',
      properties: {
        result_file: { type: 'string', description: 'Path of a saved result JSON file.' },
        format: {
          type: 'string',
          enum: ['html', 'markdown'],
          description: 'Output format. Default html.',
        },
        output_file: {
          type: 'string',
          description: 'Where to write it. Defaults to next to the result file.',
        },
      },
      required: ['result_file'],
    },
  },
  {
    name: 'list_hunt_profiles',
    description: 'List the saved hunt profiles with what each one searches for.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);

const slug = (text) =>
  String(text)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40) || 'result';

// Save the full result and its map, returning where they went
const saveResult = (result, label) => {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const base = path.join(
    OUT_DIR,
    `${new Date().toISOString().replace(/[:.]/g, '-')}-${slug(label)}`,
  );
  const files = { result_file: `${base}.json`, html_map: `${base}.html` };
  fs.writeFileSync(files.result_file, JSON.stringify(result));
  fs.writeFileSync(files.html_map, renderHtml(result));
  return files;
};

const loadResult = (file) => {
  const result = JSON.parse(fs.readFileSync(path.resolve(String(file)), 'utf8'));
  if (result.tool !== 'scam-finder') throw new Error(`${file} is not a scam-finder result`);
  return result;
};

const engineOptions = (args, progress) => ({
  depth: args.depth,
  maxDomains: args.max_domains,
  pages: args.live_checks,
  feeds: args.feeds,
  timeBudgetMs: (args.time_budget_seconds || 120) * 1000,
  onProgress: progress,
});

const digest = (result, files, args) => ({
  ...compactResult(result, { limit: args.domains_in_reply || 30 }),
  files,
  next: 'Use get_domain_details with result_file for the full record of any domain. Open html_map in a browser for the interactive map.',
});

const handlers = {
  async investigate_url(args, progress) {
    if (!args.target) throw new Error('target is required');
    const result = await investigate(String(args.target), engineOptions(args, progress));
    return digest(result, saveResult(result, result.seed.domain), args);
  },

  async hunt_scams(args, progress) {
    const spec = {
      profiles: args.profiles || [],
      queries: args.queries || [],
      keywords: args.keywords || [],
    };
    const result = await hunt(spec, engineOptions(args, progress));
    return digest(result, saveResult(result, `hunt-${spec.profiles.join('-') || 'custom'}`), args);
  },

  async get_domain_details(args) {
    const result = loadResult(args.result_file);
    if (!args.domains?.length) {
      return result.domains.map((domain) => ({
        domain: defang(domain.domain),
        score: domain.risk.score,
        level: domain.risk.level,
        state: domain.state,
        campaign: domain.campaign,
      }));
    }
    const wanted = new Set(
      args.domains.map((name) =>
        String(name)
          .toLowerCase()
          .replace(/\[\.\]/g, '.')
          .trim(),
      ),
    );
    const found = result.domains.filter((domain) => wanted.has(domain.domain));
    if (!found.length) throw new Error(`None of those domains are in ${args.result_file}`);
    return found;
  },

  async render_report(args) {
    const result = loadResult(args.result_file);
    const format = args.format === 'markdown' ? 'markdown' : 'html';
    const extension = format === 'markdown' ? '.md' : '.html';
    const output = path.resolve(
      args.output_file || String(args.result_file).replace(/\.json$/i, '') + extension,
    );
    fs.writeFileSync(output, format === 'markdown' ? renderMarkdown(result) : renderHtml(result));
    return { format, output_file: output };
  },

  async list_hunt_profiles() {
    return Object.entries(PROFILES).map(([id, profile]) => ({
      id,
      name: profile.name,
      description: profile.description,
      searches: profile.queries.map((query) => query.why),
      keywords: profile.keywords,
    }));
  },
};

const callTool = async (id, params) => {
  const handler = handlers[params?.name];
  if (!handler) {
    send({ jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${params?.name}` } });
    return;
  }
  const token = params._meta?.progressToken;
  let step = 0;
  const progress =
    token === undefined
      ? undefined
      : ({ stage, message }) => {
          step += 1;
          send({
            jsonrpc: '2.0',
            method: 'notifications/progress',
            params: { progressToken: token, progress: step, message: `${stage}: ${message}` },
          });
        };
  try {
    const output = await handler(params.arguments || {}, progress);
    send({
      jsonrpc: '2.0',
      id,
      result: { content: [{ type: 'text', text: JSON.stringify(output, null, 1) }] },
    });
  } catch (error) {
    // Tool failures go back as results the model can read and react to, not protocol errors
    send({
      jsonrpc: '2.0',
      id,
      result: { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true },
    });
  }
};

export const handleMessage = async (message) => {
  const { id, method, params } = message;
  const isRequest = id !== undefined && id !== null;
  switch (method) {
    case 'initialize': {
      const requested = params?.protocolVersion;
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: PROTOCOL_VERSIONS.includes(requested) ? requested : PROTOCOL_VERSIONS[0],
          capabilities: { tools: {} },
          serverInfo: SERVER,
          instructions: INSTRUCTIONS,
        },
      });
      return;
    }
    case 'ping':
      send({ jsonrpc: '2.0', id, result: {} });
      return;
    case 'tools/list':
      send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      return;
    case 'tools/call':
      await callTool(id, params);
      return;
    default:
      // Notifications (no id) need no reply; unknown requests get a proper error
      if (isRequest)
        send({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `Method not found: ${method}` },
        });
  }
};

export const start = () => {
  const lines = readline.createInterface({ input: process.stdin, terminal: false });
  lines.on('line', (line) => {
    const text = line.trim();
    if (!text) return;
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    for (const item of Array.isArray(message) ? message : [message]) {
      handleMessage(item).catch((error) => {
        if (item?.id !== undefined)
          send({ jsonrpc: '2.0', id: item.id, error: { code: -32603, message: error.message } });
      });
    }
  });
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) start();
