import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hunt, investigate } from '../lib/index.js';
import { compactResult, renderHtml, renderMarkdown, renderText } from '../lib/report.js';
import { FeedIndex, parseFeed } from '../lib/sources/feeds.js';
import { normalizeScan, search } from '../lib/sources/urlscan.js';
import { dnsRoute, fakeNet, reply, scanHit } from './helpers.js';

const SEED = 'https://badkit.example/AbCdEf/token?1115262603011539197&s=wa&';
const TITLE = '🇯🇲Acme - Independence Day Gift!🎁';

const seedHtml = `<html><head><title>${TITLE}</title>
<meta property="og:image" content="https://badkit.example/metaconfig/images/en/01.jpg">
<meta property="og:url" content="https://www.whatsapp.com/"></head>
<body><script>var p = navigator.platform; if (p == atob('V2lu') || atob('TWFj') || atob('WDEx') || atob('YQ==')) { location.href = '/404bbb' + 1; }</script></body></html>`;

// A small pretend internet: one kit site, two siblings found through the scan archive,
// a neighbour on the same server, and a well-known site that must be ignored
const world = () => [
  dnsRoute({
    'badkit.example': {
      A: ['203.0.113.10'],
      NS: ['ada.ns.cloudflare.com.', 'bob.ns.cloudflare.com.'],
    },
    'sib-one.example': {
      A: ['203.0.113.11'],
      NS: ['ada.ns.cloudflare.com.', 'bob.ns.cloudflare.com.'],
    },
    'sib-two.example': {},
    'neighbour.example': { A: ['203.0.113.10'], NS: ['ns1.host.example.'] },
    '10.113.0.203.origin.asn.cymru.com': {
      TXT: ['"64500 | 203.0.113.0/24 | ZZ | test | 2020-01-01"'],
    },
    'AS64500.asn.cymru.com': {
      TXT: ['"64500 | ZZ | test | 2020-01-01 | EXAMPLE-NET - Example Hosting, ZZ"'],
    },
  }),
  (url) =>
    url === 'https://data.iana.org/rdap/dns.json'
      ? reply({ services: [[['example'], ['https://rdap.test/']]] })
      : undefined,
  (url) => {
    if (!url.startsWith('https://rdap.test/domain/')) return undefined;
    const name = url.split('/').pop();
    if (name === 'sib-two.example') return reply({ errorCode: 404 }, { status: 404 });
    // The bakery next door has been around for years; the kit domains are three weeks old
    const age = name === 'neighbour.example' ? 4000 : 20;
    return reply({
      events: [
        {
          eventAction: 'registration',
          eventDate: new Date(Date.now() - age * 86400000).toISOString(),
        },
      ],
      nameservers: [{ ldhName: 'ada.ns.cloudflare.com' }, { ldhName: 'bob.ns.cloudflare.com' }],
      entities: [
        {
          roles: ['registrar'],
          vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]],
          entities: [
            {
              roles: ['abuse'],
              vcardArray: ['vcard', [['email', {}, 'text', 'abuse@registrar.example']]],
            },
          ],
        },
        {
          roles: ['registrant'],
          vcardArray: [
            'vcard',
            [
              ['fn', {}, 'text', 'A Private Person'],
              ['email', {}, 'text', 'person@mail.example'],
            ],
          ],
        },
      ],
    });
  },
  (url) => (url.startsWith('https://badkit.example/AbCdEf/token') ? reply(seedHtml) : undefined),
  (url) =>
    /^https:\/\/(badkit|sib-one)\.example\/$/.test(url)
      ? reply('404codeaaag', { headers: { 'content-type': 'text/plain' } })
      : undefined,
  (url) =>
    url.startsWith('https://sib-one.example/XyZ/')
      ? reply(seedHtml.replaceAll('badkit', 'sib-one'))
      : undefined,
  (url) =>
    url === 'https://neighbour.example/'
      ? reply(
          '<html><head><title>Riverside Bakery, fresh bread daily</title></head><body>Opening hours</body></html>',
        )
      : undefined,
  (url) =>
    url === 'https://badkit.example/metaconfig/images/en/01.jpg'
      ? reply('x'.repeat(2048), { headers: { 'content-type': 'image/jpeg' } })
      : undefined,
  (url) =>
    url.startsWith('https://api.certspotter.com/')
      ? reply([
          { dns_names: ['badkit.example', '*.badkit.example'], not_before: '2026-10-01T00:00:00Z' },
        ])
      : undefined,
  (url, opts) =>
    url === 'https://ip.thc.org/api/v1/lookup' && opts.method === 'POST'
      ? reply({
          matching_records: 2,
          domains: [{ domain: 'badkit.example' }, { domain: 'neighbour.example' }],
        })
      : undefined,
  (url) => {
    if (!url.startsWith('https://urlscan.io/api/v1/search/')) return undefined;
    const query = new URL(url).searchParams.get('q');
    if (query.startsWith('filename:"metaconfig/images/en/01.jpg"')) {
      return reply({
        total: 4,
        search_date_limit_days: 30,
        results: [
          scanHit({
            id: 's1',
            host: 'sib-one.example',
            title: TITLE,
            url: 'https://sib-one.example/XyZ/jm-en?1&s=wa&',
          }),
          scanHit({
            id: 's2',
            host: 'sib-two.example',
            title: '👉Other Brand - Founders Day Gift!🎁',
            url: 'https://sib-two.example/QrS/ph-en?2&s=ms&',
            tags: ['@phish_report'],
          }),
          scanHit({ id: 's3', host: 'www.google.com', title: 'Google' }),
          scanHit({
            id: 's4',
            host: 'sib-one.example',
            title: TITLE,
            url: 'https://sib-one.example/XyZ/jm-en?3&s=wa&',
            time: '2026-11-12T10:00:00.000Z',
          }),
        ],
      });
    }
    if (query.startsWith('hash:'))
      return reply({
        total: 9000,
        results: [
          scanHit({ id: 'h1', host: 'unrelated-popular.example', title: 'Popular library user' }),
        ],
      });
    return reply({ total: 0, results: [], search_date_limit_days: 30 });
  },
  (url) =>
    url.includes('/openphish/')
      ? reply('https://sib-two.example/QrS/login\nhttps://listed-elsewhere.example/\n')
      : undefined,
];

const run = async (options = {}) => {
  const { ctx, unmatched, calls } = fakeNet(world());
  const result = await investigate(SEED, {
    ctx,
    feeds: 'openphish',
    pages: 5,
    rdap: 5,
    ...options,
  });
  return { result, unmatched, calls };
};

test('an investigation profiles the seed, finds its siblings and scores them', async () => {
  const { result, unmatched } = await run();
  assert.deepEqual(
    unmatched,
    [],
    'every request should have been answered by the pretend internet',
  );
  assert.equal(result.tool, 'scam-finder');
  assert.equal(result.partial, false);
  assert.deepEqual(result.sources.errors, []);

  const [seed] = result.domains;
  assert.equal(seed.role, 'seed');
  assert.equal(seed.domain, 'badkit.example');
  assert.equal(seed.risk.level, 'critical');
  assert.equal(seed.kits[0].id, 'whatsapp-brand-gift');
  assert.equal(seed.state, 'live');
  assert.equal(seed.targets[0].country, 'JM');
  assert.equal(seed.registration.registrar, 'Example Registrar');
  assert.equal(seed.registration.abuseEmail, 'abuse@registrar.example');
  assert.equal(seed.nameservers.accountLevel, true);
  assert.equal(seed.network[0].asn, 64500);

  const names = result.domains.map((domain) => domain.domain);
  assert.ok(names.includes('sib-one.example'));
  assert.ok(names.includes('sib-two.example'));
  assert.ok(names.includes('neighbour.example'), 'a site on the same dedicated server is a lead');
  assert.ok(!names.some((name) => name.includes('google')), 'well-known sites are never leads');
  assert.ok(
    !names.includes('unrelated-popular.example'),
    'a search with thousands of matches is not a fingerprint',
  );
});

test('personal registrant details never reach the result', async () => {
  const { result } = await run();
  const dump = JSON.stringify(result);
  assert.doesNotMatch(dump, /A Private Person/);
  assert.doesNotMatch(dump, /person@mail\.example/);
});

test('related sites carry their own evidence', async () => {
  const { result } = await run();
  const byName = Object.fromEntries(result.domains.map((domain) => [domain.domain, domain]));

  const one = byName['sib-one.example'];
  assert.equal(one.state, 'live');
  assert.equal(
    one.kits[0].id,
    'whatsapp-brand-gift',
    'confirmed by visiting it, not just by association',
  );
  assert.equal(one.scans.count, 2);
  assert.equal(one.foundBy[0].type, 'kit');
  assert.equal(one.risk.level, 'critical');
  assert.equal(one.campaign, byName['badkit.example'].campaign, 'same title means same campaign');

  const two = byName['sib-two.example'];
  assert.equal(two.state, 'offline');
  assert.equal(two.blocklists[0].feed, 'openphish');
  assert.ok(two.risk.signals.some((signal) => signal.id === 'blocklist'));
  assert.notEqual(two.campaign, one.campaign);

  // The neighbour was only found by sharing a server: a lead, not a verdict
  const neighbour = byName['neighbour.example'];
  assert.equal(neighbour.foundBy[0].type, 'ip');
  assert.equal(neighbour.title, 'Riverside Bakery, fresh bread daily');
  assert.deepEqual(neighbour.kits, []);
  assert.equal(
    neighbour.risk.level,
    'low',
    `a long-established bakery on the same server scored ${neighbour.risk.score}`,
  );

  const pair = result.links.find((link) => link.kind === 'nameservers');
  assert.deepEqual(pair.domains, ['badkit.example', 'sib-one.example']);
  assert.ok(result.links.some((link) => link.kind === 'file' && link.domains.length === 3));
  assert.ok(
    result.links.some(
      (link) => link.kind === 'server' && link.domains.includes('neighbour.example'),
    ),
  );
  assert.equal(result.pivots.find((pivot) => pivot.type === 'hash').status, 'too-common');
  assert.ok(result.graph.nodes.some((node) => node.type === 'seed'));
});

test('depth 0 profiles the target without searching for others', async () => {
  const { result, calls } = await run({ depth: 0 });
  assert.equal(result.domains.length, 1);
  assert.equal(result.domains[0].risk.level, 'critical');
  assert.ok(!calls.some((url) => url.includes('filename')));
});

test('a spent time budget yields a partial result rather than an error', async () => {
  const { ctx } = fakeNet(world());
  ctx.budget = { expired: () => true, left: () => 0, elapsed: () => 0 };
  const result = await investigate(SEED, { ctx, feeds: 'none' });
  assert.equal(result.partial, true);
  assert.equal(result.domains[0].domain, 'badkit.example');
});

test('reports defang every indicator and survive hostile titles', async () => {
  const { result } = await run();
  result.domains[1].title = '</script><script>alert(1)</script>';
  const text = renderText(result);
  const markdown = renderMarkdown(result);
  for (const output of [text, markdown]) {
    assert.match(output, /badkit\[\.\]example/);
    assert.doesNotMatch(output, /https?:\/\/(badkit|sib-one|sib-two)\.example/);
  }
  const html = renderHtml(result);
  assert.match(html, /<title>Scam Map<\/title>/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.match(html, /\\u003c\/script\\u003e/);
  assert.equal(
    html.match(/<\/script>/g).length,
    2,
    'only the two script blocks of the page itself',
  );
  assert.match(
    renderHtml(result, { title: 'Gift <b>Scam</b> Map' }),
    /<title>Gift bScam\/b Map<\/title>/,
  );
  const fragment = renderHtml(result, { fragment: true });
  assert.doesNotMatch(fragment, /<html|<body|<!doctype/i);
  assert.match(fragment, /^<title>Scam Map<\/title>/);

  const digest = compactResult(result, { limit: 2 });
  assert.equal(digest.domains.length, 2);
  assert.equal(digest.domainsOmitted, result.domains.length - 2);
  assert.ok(JSON.stringify(digest).length < 6000);
});

test('hunts collect leads from queries and blocklist keywords', async () => {
  const { ctx } = fakeNet(world());
  const result = await hunt(
    { queries: ['filename:"metaconfig/images/en/01.jpg"'], keywords: ['listed'] },
    { ctx, feeds: 'openphish', pages: 0, rdap: 0 },
  );
  assert.equal(result.kind, 'hunt');
  const names = result.domains.map((domain) => domain.domain);
  assert.ok(names.includes('sib-one.example'));
  assert.ok(names.includes('listed-elsewhere.example'));
  assert.ok(result.domains.every((domain) => domain.role === 'related'));
  await assert.rejects(hunt({ profiles: ['nope'] }, { ctx }), /Unknown hunt profile/);
  await assert.rejects(hunt({}, { ctx }), /Nothing to hunt for/);
});

test('feeds are parsed in every format and matched up the hostname', () => {
  assert.deepEqual(parseFeed('# comment\nhttps://a.example/x\nnot a url\n', 'urls'), [
    ['a.example', 'https://a.example/x'],
  ]);
  assert.deepEqual(
    parseFeed('0.0.0.0 b.example\n127.0.0.1 localhost\n', 'hosts').map(([host]) => host),
    ['b.example'],
  );
  assert.deepEqual(
    parseFeed('*.c.example\n||d.example^\n! note\n', 'domains').map(([host]) => host),
    ['c.example', 'd.example'],
  );
  assert.deepEqual(
    parseFeed('{"blacklist":["e.example"]}', 'metamask').map(([host]) => host),
    ['e.example'],
  );
  assert.deepEqual(parseFeed('not json', 'metamask'), []);

  const index = new FeedIndex();
  index.add('openphish', [
    ['evil.example', null],
    ['login.shop.example', 'https://login.shop.example/a'],
  ]);
  index.add('gaso', [['evil.example', null]]);
  assert.deepEqual(
    index.lookup('www.evil.example').map((hit) => hit.feed),
    ['openphish', 'gaso'],
  );
  assert.equal(
    index.lookup('shop.example').length,
    0,
    'a listed subdomain does not condemn its parent',
  );
  assert.equal(index.lookup('login.shop.example')[0].listed, 'login.shop.example');
  assert.equal(index.filter((host) => host.includes('shop')).length, 1);
});

test('urlscan results are normalised and paged', async () => {
  const scan = normalizeScan(scanHit({ id: 'a', host: 'sub.site.example', title: 'T' }));
  assert.equal(scan.domain, 'site.example');
  assert.equal(scan.asn, 64500);
  assert.equal(scan.report, 'https://urlscan.io/result/a/');

  const pages = [];
  const { ctx } = fakeNet([
    (url) => {
      const params = new URL(url).searchParams;
      pages.push(params.get('search_after'));
      const start = params.get('search_after') ? 100 : 0;
      const count = start ? 30 : 100;
      return reply({
        total: 130,
        results: Array.from({ length: count }, (unused, index) =>
          scanHit({ id: `id${start + index}`, host: `h${start + index}.example`, title: 'x' }),
        ),
      });
    },
  ]);
  const found = await search(ctx, 'page.title:"x"', { maxResults: 500 });
  assert.equal(found.scans.length, 130);
  assert.deepEqual(pages, [null, '1,id99']);
});
