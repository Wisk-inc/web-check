// Test doubles: a network that answers from canned routes, so the suite never goes online

import { HostLimiter, NetContext } from '../lib/net.js';

// Build the response shape that lib/net.js's `request` returns
export const reply = (body, { status = 200, headers = {} } = {}) => {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const bytes = Buffer.from(text);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: {
      'content-type': typeof body === 'string' ? 'text/html' : 'application/json',
      ...headers,
    },
    bytes,
    truncated: false,
    text,
    json: () => JSON.parse(text),
  };
};

// A NetContext whose requests are served by `routes`: functions (url, opts) => reply | undefined
// Anything no route answers gets a 404 and is recorded in `unmatched`
export const fakeNet = (routes) => {
  const unmatched = [];
  const calls = [];
  const request = async (url, opts = {}) => {
    calls.push(url);
    for (const route of routes) {
      const response = route(url, opts);
      if (response) return { url, ...response };
    }
    unmatched.push(url);
    return { url, ...reply('not found', { status: 404 }) };
  };
  const instant = { concurrency: 8, minIntervalMs: 0 };
  const limiter = new HostLimiter({
    'urlscan.io': instant,
    'api.certspotter.com': instant,
    'ip.thc.org': instant,
    'rdap.org': instant,
  });
  const ctx = new NetContext({ request, cacheDir: false, limiter });
  return { ctx, unmatched, calls };
};

const DNS_TYPES = { A: 1, NS: 2, MX: 15, TXT: 16, AAAA: 28, SOA: 6 };

// A DNS-over-HTTPS route backed by a table like { 'example.test': { A: ['203.0.113.5'] } }
export const dnsRoute = (table) => (url) => {
  if (!url.startsWith('https://dns.google/resolve')) return undefined;
  const params = new URL(url).searchParams;
  const name = params.get('name');
  const type = params.get('type');
  const records = table[name];
  if (!records) return reply({ Status: 3 });
  return reply({
    Status: 0,
    Answer: (records[type] || []).map((data) => ({ name, type: DNS_TYPES[type], data })),
  });
};

// One urlscan.io search hit
export const scanHit = ({
  id,
  host,
  title,
  url,
  ip = '203.0.113.20',
  asn = 'AS64500',
  time = '2026-11-10T10:00:00.000Z',
  ageDays = 5,
  tags = [],
}) => ({
  _id: id,
  task: { uuid: id, time, url: url || `https://${host}/`, domain: host, tags },
  page: {
    domain: host,
    apexDomain: host,
    url: url || `https://${host}/`,
    title,
    ip,
    asn,
    asnname: 'EXAMPLE-NET - Example Hosting, ZZ',
    server: 'nginx',
    status: '200',
    apexDomainAgeDays: ageDays,
  },
  sort: [1, id],
  screenshot: `https://urlscan.io/screenshots/${id}.png`,
});
