import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assertPublicHost,
  crawlPage,
  distinctiveResources,
  extractFingerprint,
  pathDistinctiveness,
} from '../lib/page.js';
import { dnsRoute, fakeNet, reply } from './helpers.js';

const b64 = (text) => Buffer.from(text).toString('base64');

// A stand-in for a cloaked chain-message landing page: spoofed preview, platform check hidden
// behind atob(), and a script hand-off to the next stage. Written for the test, not copied
const stubPage = (
  next,
) => `<!DOCTYPE html><html><head><title>🇯🇲Acme &amp; Co - Independence Day Gift!🎁</title>
<meta property="og:image" content="https://kit.example/metaconfig/images/en/01.jpg?t=1">
<meta property="og:url" content="https://www.whatsapp.com/">
<meta name="description" content="Everyone can get a gift"></head><body>
<script>
  var p = navigator[atob('${b64('platform')}')];
  var win = p.indexOf(atob('${b64('Win')}')) == 0, mac = p.indexOf(atob('${b64('Mac')}')) == 0;
  var a = atob('${b64('href')}'), c = atob('${b64('click')}');
  if (win || mac) { var el = document.createElement('a'); el.setAttribute(a, \`/404bbb\${Math.random()}\`); el[c](); }
  else { top.location.href = \`${next}/\${Date.now()}\` + location.search; }
</script></body></html>`;

const landingPage = `<html lang="en"><head><title>Acme Gift</title>
<link rel="stylesheet" href="/static/css/gWTXMAM2.css"><script src="/static/js/DUlSoPcA.js"></script>
<script src="https://cdn.example-analytics.net/a.js"></script>
<script>gtag('config', 'G-ABCD123456'); fbq('init', '123456789012345');</script></head>
<body><h1>Congratulations!</h1><p>Share it with 5 groups to claim your gift.</p>
<a href="https://t.me/giftsupport_bot">Help</a>
<form action="https://collector.example.org/submit"><input type="password" name="pin"><input name="cardnumber"></form>
</body></html>`;

test('fingerprints come out of a cloaked stub page', () => {
  const url = 'https://kit.example/AbCdEf/token?123&s=wa&';
  const print = extractFingerprint(stubPage('/AbCdEf/stage2'), url);
  assert.equal(print.title, '🇯🇲Acme & Co - Independence Day Gift!🎁');
  assert.equal(print.og.spoofedHost, 'www.whatsapp.com');
  assert.equal(print.behaviour.deviceCloaking, true);
  assert.ok(print.behaviour.hiddenStrings.includes('platform'));
  assert.equal(print.resources[0].path, '/metaconfig/images/en/01.jpg');
  // The script's hand-off is followed, with its placeholders filled in and the query carried over
  assert.equal(print.redirectTargets.length, 1);
  assert.match(
    print.redirectTargets[0],
    /^https:\/\/kit\.example\/AbCdEf\/stage2\/\d{13}\?123&s=wa&$/,
  );
});

test('trackers, contacts and forms are extracted from a landing page', () => {
  const print = extractFingerprint(landingPage, 'https://kit.example/land');
  assert.deepEqual(print.trackers.map((tracker) => `${tracker.kind}:${tracker.id}`).sort(), [
    'facebook-pixel:123456789012345',
    'google-analytics:G-ABCD123456',
  ]);
  assert.deepEqual(print.contacts, [{ kind: 'telegram', id: 'giftsupport_bot' }]);
  assert.equal(print.forms.passwordFields, 1);
  assert.equal(print.forms.cardFields, 1);
  assert.deepEqual(print.forms.actionHosts, ['collector.example.org']);
  assert.ok(print.externalHosts.includes('cdn.example-analytics.net'));
  assert.equal(print.language, 'en');
  assert.match(print.text, /Share it with 5 groups/);
  assert.doesNotMatch(print.text, /gtag/);
});

test('markup in a title stays text, and malformed pages do not hang the parser', () => {
  const print = extractFingerprint(
    '<title>&lt;script&gt;alert(1)&lt;/script&gt;</title>',
    'https://x.example/',
  );
  assert.equal(print.title, '<script>alert(1)</script>');
  const hostile = '<script'.repeat(20000) + '<style'.repeat(20000);
  const started = Date.now();
  extractFingerprint(hostile, 'https://x.example/');
  assert.ok(Date.now() - started < 2000);
});

test('only unusual resource paths are used to link sites', () => {
  assert.equal(pathDistinctiveness('/js/jquery.min.js'), 0);
  assert.equal(pathDistinctiveness('/wp-content/themes/flatsome/assets/js/flatsome.js'), 0);
  assert.ok(pathDistinctiveness('/metaconfig/images/en/01.jpg') >= 1);
  assert.ok(pathDistinctiveness('/assets/index-3f9a2c1b77.js') >= 2);
  const picks = distinctiveResources([
    { sameSite: true, path: '/js/jquery.min.js' },
    { sameSite: true, path: '/metaconfig/images/en/01.jpg' },
    { sameSite: false, path: '/metaconfig/images/en/02.jpg' },
    { sameSite: true, path: '/cdn-cgi/scripts/email-decode.min.js' },
  ]);
  assert.deepEqual(
    picks.map((item) => item.path),
    ['/metaconfig/images/en/01.jpg'],
  );
});

test('private and local hosts are refused before any request is made', async () => {
  const { ctx, calls } = fakeNet([
    dnsRoute({ 'rebind.example': { A: ['10.0.0.5'] }, 'ok.example': { A: ['203.0.113.7'] } }),
  ]);
  await assert.rejects(assertPublicHost(ctx, 'localhost'), /local hostname/);
  await assert.rejects(assertPublicHost(ctx, '169.254.169.254'), /private address/);
  await assert.rejects(assertPublicHost(ctx, 'printer.local'), /local hostname/);
  await assert.rejects(assertPublicHost(ctx, 'rebind.example'), /resolves to a private address/);
  await assertPublicHost(ctx, 'ok.example');
  await assertPublicHost(ctx, '203.0.113.7');
  assert.ok(calls.every((url) => url.startsWith('https://dns.google/')));
});

test('crawlPage follows HTTP and script redirects, and stops at private targets', async () => {
  const routes = [
    dnsRoute({
      'kit.example': { A: ['203.0.113.7'] },
      'short.example': { A: ['203.0.113.8'] },
      'trap.example': { A: ['203.0.113.9'] },
    }),
    (url) =>
      url === 'https://short.example/go'
        ? reply('', {
            status: 302,
            headers: { location: 'https://kit.example/AbCdEf/token?9&s=wa&' },
          })
        : undefined,
    (url) =>
      url.startsWith('https://kit.example/AbCdEf/token')
        ? reply(stubPage('/AbCdEf/stage2'))
        : undefined,
    (url) =>
      url.startsWith('https://kit.example/AbCdEf/stage2/') ? reply(landingPage) : undefined,
    (url) =>
      url === 'https://trap.example/'
        ? reply('', {
            status: 302,
            headers: { location: 'http://169.254.169.254/latest/meta-data/' },
          })
        : undefined,
  ];
  const { ctx, unmatched } = fakeNet(routes);
  const page = await crawlPage(ctx, 'https://short.example/go');
  assert.equal(page.stages.length, 2);
  assert.equal(page.stages[0].redirects[0].location, 'https://kit.example/AbCdEf/token?9&s=wa&');
  assert.deepEqual(page.redirectHosts.sort(), ['kit.example', 'short.example']);
  assert.equal(page.forms.passwordFields, 1);
  assert.ok(page.resources.some((resource) => resource.path === '/static/js/DUlSoPcA.js'));
  assert.match(page.rawHtml, /404bbb/);
  assert.deepEqual(unmatched, []);

  await assert.rejects(crawlPage(ctx, 'https://trap.example/'), /private address/);
});
