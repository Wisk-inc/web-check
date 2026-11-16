import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  currencyCountries,
  findBrands,
  findLures,
  isWellKnown,
  lexical,
  matchSignatures,
  nameShape,
  namedCountries,
  targetCountries,
  urlShape,
  usableTitle,
} from '../lib/heuristics.js';
import { scoreProfile } from '../lib/score.js';
import {
  defang,
  flagCountries,
  isPrivateIp,
  normalizeTitle,
  parseTarget,
  refang,
  registrableDomain,
} from '../lib/util.js';

const KIT_TITLE = '🇯🇲Grace - National Heroes’ Day Gift!💸';

test('parseTarget accepts URLs, bare domains and defanged indicators', () => {
  assert.equal(parseTarget('example.buzz').url, 'https://example.buzz/');
  assert.equal(parseTarget('hxxps://evil[.]example[.]buzz/a?b=1').host, 'evil.example.buzz');
  assert.equal(parseTarget('hxxps://evil[.]example[.]buzz/a?b=1').domain, 'example.buzz');
  assert.equal(parseTarget('https://example.com/x').hasPath, true);
  assert.throws(() => parseTarget(''), /No target/);
  assert.throws(() => parseTarget('ftp://example.com'), /Only http and https/);
  assert.throws(() => parseTarget('localhost'), /no usable hostname/);
});

test('defang and refang are inverses for URLs and domains', () => {
  assert.equal(defang('https://a.example.com/p.html?x=1'), 'hxxps://a[.]example[.]com/p.html?x=1');
  assert.equal(defang('a.example.com'), 'a[.]example[.]com');
  for (const value of ['https://a.example.com/p.html?x=1', 'a.example.com']) {
    assert.equal(refang(defang(value)), value);
  }
});

test('registrableDomain handles country suffixes and hosting platforms', () => {
  assert.equal(registrableDomain('login.bank.com.jm'), 'bank.com.jm');
  assert.equal(registrableDomain('www.shop.co.uk'), 'shop.co.uk');
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
  // Each tenant of a hosting platform counts as its own site
  assert.equal(registrableDomain('63812-006001-24f.pages.dev'), '63812-006001-24f.pages.dev');
  assert.equal(registrableDomain('x.y.scam-site.vercel.app'), 'scam-site.vercel.app');
  assert.equal(registrableDomain('203.0.113.9'), '203.0.113.9');
});

test('isPrivateIp covers the ranges a public scanner must refuse', () => {
  for (const ip of [
    '10.1.2.3',
    '127.0.0.1',
    '169.254.169.254',
    '172.20.0.1',
    '192.168.1.1',
    '100.64.0.1',
    '::1',
    'fd00::1',
    '::ffff:10.0.0.1',
  ]) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '203.0.113.9', '172.32.0.1', '2606:4700::1111']) {
    assert.equal(isPrivateIp(ip), false, ip);
  }
});

test('titles are compared without emoji, case or punctuation', () => {
  assert.equal(
    normalizeTitle(KIT_TITLE),
    normalizeTitle('grace – national heroes day gift'.replace('–', '-')),
  );
  assert.deepEqual(flagCountries(KIT_TITLE), ['JM']);
  assert.equal(usableTitle(KIT_TITLE), true);
  assert.equal(usableTitle('Home'), false);
  assert.equal(usableTitle('Just a moment...'), false);
  assert.equal(usableTitle('01.jpg (800×450)'), false);
});

test('machine-made names are told apart from words', () => {
  for (const name of ['mlqla.buzz', 'obtnq.buzz', 'rymjq.buzz'])
    assert.equal(lexical(name).randomLooking, true, name);
  for (const name of ['google.com', 'graceful.org', 'secure-paypal-login.xyz'])
    assert.equal(lexical(name).randomLooking, false, name);
  assert.equal(nameShape('mlqla.buzz'), 'letters5.buzz');
  assert.equal(nameShape('sub.abc123.co.uk'), 'alnum6.co.uk');
});

test('urlShape reads the structure of a chain-message link', () => {
  const shape = urlShape(
    'https://mlqla.buzz/ZJbHjpfJ/bqi0pf46u19CL-zdeNzTqUVMtQfWWcj_eu4nL_P01eydwMxpf/1794772668130?1115262603011539197&s=wa&',
  );
  assert.equal(shape.longToken, true);
  assert.equal(shape.timestamp, true);
  assert.equal(shape.shareSource, 'wa');
  assert.equal(urlShape('https://example.com/about').shareSource, null);
  assert.equal(urlShape('not a url'), null);
});

test('lures need a strong cue or two weak ones', () => {
  assert.equal(findLures(KIT_TITLE)[0].id, 'giveaway');
  assert.equal(findLures('Verify your account - Online Banking')[0].id, 'account-phishing');
  assert.equal(findLures('🇧🇩৬০ জিবি ফ্রি ইন্টারনেট')[0].id, 'giveaway');
  // Ordinary shop and church wording must not trip it
  assert.deepEqual(findLures('Buy gift cards online'), []);
  assert.deepEqual(findLures('Grace Community Church - Welcome'), []);
  assert.deepEqual(findLures(''), []);
});

test('brands are matched as whole words and official domains are recognised', () => {
  const borrowed = findBrands({ title: KIT_TITLE, host: 'mlqla.buzz' });
  assert.equal(borrowed[0].id, 'grace');
  assert.equal(borrowed[0].official, false);
  assert.equal(findBrands({ host: 'www.jncb.com' })[0].official, true);
  assert.equal(findBrands({ host: 'jncb-secure-login.top' })[0].inDomain, true);
  // "ups" inside "groups" is not UPS
  assert.equal(findBrands({ title: 'Support groups near you', host: 'example.org' }).length, 0);
  assert.equal(isWellKnown('www.whatsapp.com'), true);
  assert.equal(isWellKnown('vercel.app'), true);
  assert.equal(isWellKnown('some-tenant.vercel.app'), false);
  assert.equal(isWellKnown('mlqla.buzz'), false);
});

test('target country comes from the most reliable evidence available', () => {
  const brands = (title) => findBrands({ title, host: 'x.buzz' });
  const targets = (title) =>
    targetCountries({ title, brands: brands(title), lures: findLures(title) }).map(
      (hit) => hit.country,
    );
  assert.deepEqual(targets(KIT_TITLE), ['JM']);
  assert.deepEqual(targets('Get EGP 3,000 for Free!'), ['EG']);
  assert.deepEqual(targets('👉Globe - Bonifacio Day Gift!🎁'), ['PH']);
  assert.deepEqual(targets('🎉Ethio Telecom - Kennaa Waggaa 16ffaa!💸'), ['ET']);
  assert.deepEqual(targets('تمام پاکستانیوں کو 13,000 روپے'), ['PK']);
  assert.deepEqual(targets('Airtel - दिवाली का तोहफ़ा!'), ['IN']);
  assert.deepEqual(targets('Welcome'), []);
  // An acronym or everyday word is only read as a brand when there is bait beside it
  assert.deepEqual(targets('JPS - Supply Chain Consulting'), []);
  assert.deepEqual(targets('Lynk & Co 01 plug-in hybrid'), []);
  assert.deepEqual(targets('PNB - Diwali Gift!'), ['IN']);
  assert.deepEqual(currencyCountries('₹৮,০০০ নগদ'), ['IN']);
  assert.deepEqual(namedCountries('Welcome to Georgia Tech'), []);
  assert.deepEqual(namedCountries('All Nigerians can apply'), ['NG']);
});

const kitProfile = () => ({
  domain: 'mlqla.buzz',
  role: 'seed',
  urls: ['https://mlqla.buzz/AbCdEf/x?123&s=wa&'],
  root: { status: 200, length: 11, sample: '404codeaaag' },
  page: {
    status: 200,
    bodyLength: 2600,
    title: KIT_TITLE,
    requestedUrl: 'https://mlqla.buzz/AbCdEf/x?123&s=wa&',
    resources: [
      { kind: 'image', host: 'mlqla.buzz', path: '/metaconfig/images/en/01.jpg', sameSite: true },
    ],
    og: { spoofedHost: 'www.whatsapp.com' },
    behaviour: { deviceCloaking: true },
    forms: { passwordFields: 0, cardFields: 0, actionHosts: [] },
  },
});

test('the WhatsApp gift kit is recognised from several independent markers', () => {
  const [kit] = matchSignatures(kitProfile(), 'href = `/404bbb${x}`');
  assert.equal(kit.id, 'whatsapp-brand-gift');
  assert.ok(kit.evidence.length >= 4);
  assert.ok(
    kit.evidence.every((line) => !line.includes('/^')),
    'evidence should be plain English',
  );
  // The front-page stub alone is enough, since nothing else answers that way
  assert.equal(
    matchSignatures({ domain: 'x.buzz', root: { sample: 'bbb404codeaaa' } })[0].id,
    'whatsapp-brand-gift',
  );
  assert.deepEqual(
    matchSignatures({ domain: 'example.com', page: { title: 'Welcome', resources: [] } }),
    [],
  );
});

test('scores add up evidence and stay low without it', () => {
  const profile = kitProfile();
  profile.kits = matchSignatures(profile, '/404bbb${');
  profile.lures = findLures(KIT_TITLE);
  profile.brands = findBrands({ title: KIT_TITLE, host: profile.domain });
  profile.lexical = lexical(profile.domain);
  profile.urlShape = urlShape(profile.urls[0]);
  profile.registration = { ageDays: 64 };
  const risk = scoreProfile(profile);
  assert.equal(risk.level, 'critical');
  assert.ok(risk.signals.some((signal) => signal.id === 'kit:whatsapp-brand-gift'));
  assert.ok(risk.signals.every((signal) => signal.weight > 0 && signal.weight < 1));

  const plain = scoreProfile({
    domain: 'smallbakery.com',
    lures: [],
    brands: [],
    kits: [],
    lexical: lexical('smallbakery.com'),
    registration: { ageDays: 4000 },
  });
  assert.equal(plain.level, 'low');
  assert.equal(plain.score, 0);

  const wellKnown = scoreProfile({ domain: 'whatsapp.com', lures: [], brands: [] });
  assert.equal(wellKnown.benign, true);
});

test('an old domain with one weak signal is discounted, not condemned', () => {
  const risk = scoreProfile({
    domain: 'giftshop-jamaica.com',
    lures: findLures('Jamaica gift baskets - prizes and rewards for you'),
    brands: [],
    kits: [],
    lexical: lexical('giftshop-jamaica.com'),
    registration: { ageDays: 3000 },
    association: [{ type: 'query', weight: 0.2, label: 'Matched a hunt query' }],
  });
  assert.equal(risk.level, 'low');
  assert.ok(risk.mitigations.length === 1);
});
