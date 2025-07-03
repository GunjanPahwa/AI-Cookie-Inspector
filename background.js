chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scanCookies") {
    (async () => {
      const cookies = await chrome.cookies.getAll({ url: request.url });
      const analyzedCookies = await Promise.all(
        cookies.map(async cookie => ({
          ...cookie,
          analysis: await analyzeCookie(cookie)
        }))
      );
      sendResponse({ cookies: analyzedCookies });
    })();
    return true;
  }
});

async function analyzeCookie(cookie) {
  // Enhanced detection rules
  const isMalicious = [
    'doubleclick.net',
    'googleadservices.com',
    'facebook.com',
    'scorecardresearch.com'
  ].some(domain => cookie.domain.includes(domain));

  const isSuspicious = [
    '_ga', '_gid', '_fbp', '__gads'
  ].some(pattern => cookie.name.includes(pattern));

  return {
    isMalicious,
    isSuspicious,
    riskScore: isMalicious ? 0.9 : isSuspicious ? 0.6 : 0.1,
    reasons: [
      ...(isMalicious ? ["Known tracker"] : []),
      ...(isSuspicious ? ["Suspicious pattern"] : []),
      ...(!cookie.secure ? ["Not secure"] : [])
    ]
  };
}