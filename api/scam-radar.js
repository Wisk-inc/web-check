// Read-only window onto the Radar database built by `node scam-finder/cli.js radar run`
// (see scam-finder/README.md). It never scans anything itself: scanning is the daemon's job
//
//   /api/scam-radar?view=status            headline numbers
//   /api/scam-radar?view=map               the watchlist, shaped for the map at /scam-finder/
//   /api/scam-radar?view=sites&state=live  watched sites, filterable
//   /api/scam-radar?view=site&name=x.com   one domain with its history
//   /api/scam-radar?view=events            recent takedowns and changes

import fs from 'node:fs';
import { RadarStore, defaultDbPath } from '../scam-finder/lib/radar/store.js';
import { describeEvent, overview, radarMap, siteReport } from '../scam-finder/lib/radar/view.js';

const number = (value, fallback, max) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && value !== undefined && value !== ''
    ? Math.min(max, parsed)
    : fallback;
};

const views = {
  status: (store) => overview(store),
  map: (store, query) =>
    radarMap(store, {
      limit: number(query.limit, 800, 2000),
      minRisk: number(query.minRisk, 40, 100),
      query: query.q,
      state: query.state,
    }),
  sites: (store, query) =>
    store
      .listSites({
        limit: number(query.limit, 50, 500),
        minRisk: number(query.minRisk, 0, 100),
        state: query.state,
        query: query.q,
        order: query.order,
      })
      .map(({ detail, ...site }) => ({
        ...site,
        signals: detail.signals,
        findings: detail.findings,
        targets: detail.targets,
      })),
  site: (store, query) =>
    siteReport(store, String(query.name || '').toLowerCase()) || {
      error: 'That domain is not in the index',
    },
  events: (store, query) =>
    store
      .recentEvents({
        limit: number(query.limit, 100, 1000),
        types: query.types ? String(query.types).split(',') : undefined,
      })
      .map(describeEvent),
};

const answer = async (query) => {
  // The combined /api endpoint calls every check with just a URL; Radar has no per-URL check
  if (query.url && !query.view)
    return { skipped: 'Radar is not a per-site check. Use /api/scam-radar?view=status' };
  const view = views[query.view || 'status'];
  if (!view) return { error: `Unknown view. Choose one of: ${Object.keys(views).join(', ')}` };
  const file = defaultDbPath();
  if (!fs.existsSync(file)) {
    return {
      skipped: 'No Radar database yet. Build one with: node scam-finder/cli.js radar ingest all',
    };
  }
  const store = await RadarStore.open(file);
  try {
    return view(store, query);
  } catch (error) {
    return { error: `Radar could not answer: ${error.message}` };
  } finally {
    store.close();
  }
};

const headers = {
  'Access-Control-Allow-Origin': process.env.API_CORS_ORIGIN || '*',
  'Content-Type': 'application/json;charset=UTF-8',
};

// Works as an Express or Vercel handler (request, response) and as a Netlify one (event)
export const handler = async (first, second) => {
  const express = second && typeof second.status === 'function';
  const body = await answer((express ? first.query : first.queryStringParameters) || {});
  if (express) return second.status(200).json(body);
  return { statusCode: 200, body: JSON.stringify(body), headers };
};

export default handler;
