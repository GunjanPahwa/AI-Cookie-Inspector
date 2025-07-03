class CookieMonitor {
    constructor() {
        this.init();
    }

    init() {
        this.monitorScripts();
    }

    monitorScripts() {
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeName === 'SCRIPT') {
                        this.analyzeScript(node);
                    }
                });
            });
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    }

    analyzeScript(script) {
        const suspiciousSources = [
            'doubleclick.net',
            'googleadservices.com',
            // ... other domains
        ];

        if (script.src && suspiciousSources.some(d => script.src.includes(d))) {
            chrome.runtime.sendMessage({
                action: "suspiciousScript",
                src: script.src
            });
        }
    }
}

new CookieMonitor();