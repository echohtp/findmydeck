// Steam OpenID 2.0 login — spec §2.1. Uses the maintained `openid` lib;
// the assertion is verified server-side (openid.mode=check_authentication
// round-trip to steamcommunity.com happens inside verifyAssertion).
// A client-posted SteamID is never trusted anywhere in this codebase.

import openid from 'openid';

const STEAM_OP = 'https://steamcommunity.com/openid';
const CLAIMED_ID_RE = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/;

export function makeRelyingParty(baseUrl) {
  return new openid.RelyingParty(
    `${baseUrl}/auth/steam/return`, // return_to
    baseUrl,                        // realm
    true,                           // stateless
    false,                          // strict mode off (Steam's dialect quirks)
    [],
  );
}

export function authUrl(rp) {
  return new Promise((resolve, reject) => {
    rp.authenticate(STEAM_OP, false, (err, url) => (err ? reject(err) : resolve(url)));
  });
}

/** Verify the return request; resolve to a SteamID64 string or null. */
export function verifyReturn(rp, requestUrl) {
  return new Promise((resolve) => {
    rp.verifyAssertion(requestUrl, (err, result) => {
      if (err || !result?.authenticated) return resolve(null);
      const m = CLAIMED_ID_RE.exec(result.claimedIdentifier || '');
      resolve(m ? m[1] : null);
    });
  });
}
