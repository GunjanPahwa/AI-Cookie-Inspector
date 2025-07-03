document.addEventListener('DOMContentLoaded', async () => {
  // Load icon paths
  const iconPath = chrome.runtime.getURL('icons/icon32.png');
  document.querySelector('.header img').src = iconPath;

  // Scan cookies on load
  await scanCookies();

  // Setup buttons
  document.getElementById('blockAllBtn').addEventListener('click', blockMaliciousCookies);
});

async function scanCookies() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;

  const { cookies } = await chrome.runtime.sendMessage({ 
    action: "scanCookies", 
    url: tab.url 
  });

  displayResults(cookies);
}

function displayResults(cookies) {
  const malicious = cookies.filter(c => c.analysis.isMalicious);
  const suspicious = cookies.filter(c => c.analysis.riskScore > 0.4 && !c.isMalicious);

  // Update stats
  document.getElementById('totalCookies').textContent = cookies.length;
  document.getElementById('maliciousCookies').textContent = malicious.length;
  document.getElementById('suspiciousCookies').textContent = suspicious.length;

  // Display cookies
  const list = document.getElementById('cookieList');
  list.innerHTML = '';

  cookies.forEach(cookie => {
    const item = document.createElement('div');
    item.className = `cookie-item ${
      cookie.analysis.isMalicious ? 'cookie-malicious' : 
      cookie.analysis.riskScore > 0.4 ? 'cookie-suspicious' : 'cookie-safe'
    }`;

    item.innerHTML = `
      <div class="cookie-header">
        <div>
          <div class="cookie-name">${cookie.name}</div>
          <div class="cookie-domain">${cookie.domain}</div>
        </div>
        <div class="cookie-risk">
          ${cookie.analysis.isMalicious ? '🚫 Malicious' : 
           cookie.analysis.riskScore > 0.4 ? '⚠️ Suspicious' : '✅ Safe'}
        </div>
      </div>
      <div class="cookie-reasons">
        ${cookie.analysis.reasons.join(', ')}
      </div>
      <div class="cookie-actions">
        <button class="btn-block" data-name="${cookie.name}" data-domain="${cookie.domain}">
          Block
        </button>
        <button class="btn-ignore">
          Ignore
        </button>
      </div>
    `;

    list.appendChild(item);
  });

  // Add event listeners to block buttons
  document.querySelectorAll('.btn-block').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const name = e.target.getAttribute('data-name');
      const domain = e.target.getAttribute('data-domain');
      blockCookie(name, domain);
    });
  });
}

async function blockCookie(name, domain) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.cookies.remove({
      url: `https://${domain}`,
      name: name
    });
    alert(`Blocked cookie: ${name}`);
    scanCookies(); // Refresh the list
  } catch (error) {
    console.error('Block failed:', error);
  }
}

async function blockMaliciousCookies() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const { cookies } = await chrome.runtime.sendMessage({ 
    action: "scanCookies", 
    url: tab.url 
  });

  const malicious = cookies.filter(c => c.analysis.isMalicious);
  
  await Promise.all(
    malicious.map(cookie => 
      chrome.cookies.remove({
        url: `https://${cookie.domain}`,
        name: cookie.name
      })
    )
  );

  alert(`Blocked ${malicious.length} malicious cookies`);
  scanCookies();
}