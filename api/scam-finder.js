import middleware from './_common/middleware.js';
import { investigate } from '../scam-finder/lib/index.js';

// Leave room to send the reply before the shared middleware gives up on the request
const TIMEOUT = parseInt(process.env.PUBLIC_API_TIMEOUT_LIMIT || '40000', 10);
const BUDGET = Math.max(8000, TIMEOUT - 7000);

const numberParam = (value, max) => {
  const number = Number(value);
  return Number.isFinite(number) && value !== undefined && value !== ''
    ? Math.min(max, number)
    : undefined;
};

// Profile a suspect site and find others sharing its fingerprints (scam-finder/README.md)
const scamFinderHandler = async (url, request) => {
  const query = request?.query || request?.queryStringParameters || {};
  try {
    return await investigate(url, {
      quick: true,
      depth: numberParam(query.depth, 2),
      maxDomains: numberParam(query.limit, 400),
      pages: numberParam(query.pages, 20),
      timeBudgetMs: BUDGET,
    });
  } catch (error) {
    return { error: `Scam finder could not investigate this target: ${error.message}` };
  }
};

export const handler = middleware(scamFinderHandler);
export default handler;
