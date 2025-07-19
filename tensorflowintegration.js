// AI/ML Integration for Cookie Analysis using TensorFlow.js
// Note: This would typically load tensorflow.min.js from CDN

class AIModelManager {
    constructor() {
        this.model = null;
        this.isModelLoaded = false;
        this.modelVersion = '1.0.0';
        this.init();
    }

    async init() {
        try {
            await this.loadTensorFlow();
            await this.loadCookieAnalysisModel();
            console.log('AI Cookie Analysis Model loaded successfully');
        } catch (error) {
            console.error('Failed to initialize AI model:', error);
            // Fallback to rule-based analysis
            this.isModelLoaded = false;
        }
    }

    async loadTensorFlow() {
        // In a real implementation, TensorFlow.js would be loaded from CDN
        // For demo purposes, we'll simulate the TensorFlow environment
        if (typeof tf === 'undefined') {
            console.log('TensorFlow.js not available, using simulated environment');
            // Create mock TensorFlow object for demonstration
            window.tf = {
                sequential: () => ({ add: () => {}, predict: () => ({ dataSync: () => [0.5] }) }),
                layers: { dense: () => ({}), dropout: () => ({}) },
                model: () => ({ predict: () => ({ dataSync: () => [0.5] }) }),
                tensor2d: (data) => ({ dataSync: () => data.flat() }),
                ready: () => Promise.resolve()
            };
        }
        await tf.ready();
    }

    async loadCookieAnalysisModel() {
        // In production, this would load a pre-trained model
        // For demo, we'll create a simple model architecture
        this.model = this.createCookieAnalysisModel();
        this.isModelLoaded = true;
    }

    createCookieAnalysisModel() {
        // Simulate creating a neural network for cookie analysis
        // In reality, this would be a pre-trained model loaded from a file
        const model = tf.sequential();
        
        // Input layer - features extracted from cookies
        model.add(tf.layers.dense({
            units: 64,
            activation: 'relu',
            inputShape: [20] // 20 features extracted from each cookie
        }));
        
        // Hidden layers
        model.add(tf.layers.dropout({ rate: 0.3 }));
        model.add(tf.layers.dense({ units: 32, activation: 'relu' }));
        model.add(tf.layers.dropout({ rate: 0.2 }));
        model.add(tf.layers.dense({ units: 16, activation: 'relu' }));
        
        // Output layer - probability of being malicious
        model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));
        
        return model;
    }

    async analyzeCookieWithAI(cookie) {
        if (!this.isModelLoaded) {
            return this.fallbackAnalysis(cookie);
        }

        try {
            // Extract features from cookie
            const features = this.extractCookieFeatures(cookie);
            
            // Convert to tensor
            const inputTensor = tf.tensor2d([features]);
            
            // Make prediction
            const prediction = this.model.predict(inputTensor);
            const maliciousProbability = prediction.dataSync()[0];
            
            // Clean up tensors
            inputTensor.dispose();
            prediction.dispose();

            return {
                isMalicious: maliciousProbability > 0.7,
                isSuspicious: maliciousProbability > 0.4,
                confidence: maliciousProbability,
                method: 'ai',
                features: features
            };

        } catch (error) {
            console.error('AI analysis failed, falling back to rule-based:', error);
            return this.fallbackAnalysis(cookie);
        }
    }

    extractCookieFeatures(cookie) {
        // Extract 20 numerical features from cookie for ML model
        const features = new Array(20).fill(0);
        
        // Feature 1: Cookie name length
        features[0] = cookie.name ? cookie.name.length / 50 : 0;
        
        // Feature 2: Cookie value length
        features[1] = cookie.value ? cookie.value.length / 1000 : 0;
        
        // Feature 3: Domain depth (number of dots)
        features[2] = cookie.domain ? (cookie.domain.match(/\./g) || []).length / 5 : 0;
        
        // Feature 4: Is third-party cookie
        const currentDomain = window.location ? window.location.hostname : '';
        features[3] = cookie.domain && !currentDomain.endsWith(cookie.domain.replace(/^\./, '')) ? 1 : 0;
        
        // Feature 5: Has secure flag
        features[4] = cookie.secure ? 1 : 0;
        
        // Feature 6: Has httpOnly flag
        features[5] = cookie.httpOnly ? 1 : 0;
        
        // Feature 7: Expiration time (normalized)
        if (cookie.expirationDate) {
            const now = Date.now() / 1000;
            const timeToExpire = cookie.expirationDate - now;
            features[6] = Math.min(timeToExpire / (365 * 24 * 3600), 1); // Normalize to max 1 year
        }
        
        // Feature 8: Contains tracking patterns
        const trackingPatterns = ['_ga', '_gid', '_fbp', '_fbc', 'fr', '__utm'];
        features[7] = trackingPatterns.some(pattern => 
            cookie.name && cookie.name.includes(pattern)) ? 1 : 0;
        
        // Feature 9: Value entropy (randomness)
        features[8] = cookie.value ? this.calculateEntropy(cookie.value) / 8 : 0;
        
        // Feature 10: Contains base64-like data
        features[9] = cookie.value && this.looksLikeBase64(cookie.value) ? 1 : 0;
        
        // Feature 11: Name contains numbers
        features[10] = cookie.name && /\d/.test(cookie.name) ? 1 : 0;
        
        // Feature 12: Name contains special characters
        features[11] = cookie.name && /[^a-zA-Z0-9_-]/.test(cookie.name) ? 1 : 0;
        
        // Feature 13: Path specificity
        features[12] = cookie.path ? (cookie.path.split('/').length - 1) / 10 : 0;
        
        // Feature 14: SameSite attribute
        if (cookie.sameSite) {
            features[13] = cookie.sameSite.toLowerCase() === 'none' ? 1 : 
                          cookie.sameSite.toLowerCase() === 'lax' ? 0.5 : 0;
        }
        
        // Feature 15: Domain starts with dot (broad scope)
        features[14] = cookie.domain && cookie.domain.startsWith('.') ? 1 : 0;
        
        // Feature 16: Very long expiration (> 1 year)
        if (cookie.expirationDate) {
            const oneYearFromNow = Date.now() / 1000 + 365 * 24 * 3600;
            features[15] = cookie.expirationDate > oneYearFromNow ? 1 : 0;
        }
        
        // Feature 17: Common ad network domains
        const adDomains = ['doubleclick', 'googlesyndication', 'facebook', 'amazon-adsystem'];
        features[16] = adDomains.some(domain => 
            cookie.domain && cookie.domain.includes(domain)) ? 1 : 0;
        
        // Feature 18: Value contains URLs
        features[17] = cookie.value && /https?:\/\//.test(cookie.value) ? 1 : 0;
        
        // Feature 19: Name suggests user tracking
        const userTrackingNames = ['user', 'visitor', 'session', 'uid', 'id'];
        features[18] = userTrackingNames.some(name => 
            cookie.name && cookie.name.toLowerCase().includes(name)) ? 1 : 0;
        
        // Feature 20: Overall suspicion heuristic
        features[19] = this.calculateOverallSuspicion(cookie);
        
        return features;
    }

    calculateEntropy(str) {
        const freq = {};
        for (let char of str) {
            freq[char] = (freq[char] || 0) + 1;
        }

        let entropy = 0;
        for (let char in freq) {
            const p = freq[char] / str.length;
            entropy -= p * Math.log2(p);
        }

        return entropy;
    }

    looksLikeBase64(str) {
        if (str.length < 10) return false;
        const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
        return base64Regex.test(str);
    }

    calculateOverallSuspicion(cookie) {
        let suspicion = 0;
        
        // Multiple factors contributing to suspicion
        if (cookie.value && cookie.value.length > 200) suspicion += 0.2;
        if (!cookie.secure && cookie.domain && cookie.domain.includes('.')) suspicion += 0.2;
        if (cookie.domain && cookie.domain.startsWith('.')) suspicion += 0.1;
        if (cookie.name && cookie.name.length < 3) suspicion += 0.2;
        if (cookie.name && /^[a-f0-9]{8,}$/.test(cookie.name)) suspicion += 0.3;
        
        return Math.min(suspicion, 1);
    }

    fallbackAnalysis(cookie) {
        // Rule-based analysis as fallback when AI model is not available
        let suspiciousScore = 0;
        const reasons = [];

        // Known tracking cookies
        const trackingPatterns = ['_ga', '_gid', '_fbp', '_fbc', 'fr', '__utm'];
        if (trackingPatterns.some(pattern => cookie.name && cookie.name.includes(pattern))) {
            suspiciousScore += 0.8;
            reasons.push('Known tracking cookie');
        }

        // Long values often indicate tracking data
        if (cookie.value && cookie.value.length > 100) {
            suspiciousScore += 0.3;
            reasons.push('Unusually long value');
        }

        // Third-party cookies
        const currentDomain = window.location ? window.location.hostname : '';
        if (cookie.domain && !currentDomain.endsWith(cookie.domain.replace(/^\./, ''))) {
            suspiciousScore += 0.4;
            reasons.push('Third-party cookie');
        }

        // Insecure cookies
        if (!cookie.secure && cookie.domain && cookie.domain.includes('.')) {
            suspiciousScore += 0.2;
            reasons.push('Insecure third-party cookie');
        }

        return {
            isMalicious: suspiciousScore > 0.7,
            isSuspicious: suspiciousScore > 0.4,
            confidence: suspiciousScore,
            method: 'rule-based',
            reasons: reasons
        };
    }

    async batchAnalyzeCookies(cookies) {
        const results = [];
        
        for (const cookie of cookies) {
            const analysis = await this.analyzeCookieWithAI(cookie);
            results.push({
                cookie,
                analysis
            });
        }
        
        return results;
    }

    getModelStats() {
        return {
            isLoaded: this.isModelLoaded,
            version: this.modelVersion,
            method: this.isModelLoaded ? 'ai' : 'rule-based'
        };
    }
}

// Export for use in other parts of the extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AIModelManager;
} else {
    window.AIModelManager = AIModelManager;
}
