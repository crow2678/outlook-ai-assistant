// Enhanced storage with better error handling
  async storeStyleProfile(styleProfile) {
    try {
      // Validate profile before storing
      this.validateStyleProfile(styleProfile);
      
      const response = await this.withRetry(async () => {
        return await fetch('/api/users/style-profile', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${await this.getAuthToken()}`,
            'X-User-ID': this.userId
          },
          body: JSON.stringify({
            userId: this.userId,
            styleProfile: styleProfile,
            timestamp: new Date().toISOString()
          })
        });
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`Failed to store style profile: ${response.status} - ${errorData.message || response.statusText}`);
      }

      const result = await response.json();
      console.log('Style profile stored successfully:', result);
      return result;
      
    } catch (error) {
      console.error('Error storing style profile:', error);
      
      // Try to store locally as backup
      try {
        this.storeProfileLocally(styleProfile);
        console.log('Style profile stored locally as backup');
      } catch (localError) {
        console.error('Failed to store locally as well:', localError);
      }
      
      throw error;
    }
  }

  // Local storage backup
  storeProfileLocally(styleProfile) {
    try {
      const profileData = {
        profile: styleProfile,
        userId: this.userId,
        storedAt: new Date().toISOString(),
        version: styleProfile.metadata.version
      };
      
      localStorage.setItem(`styleProfile_${this.userId}`, JSON.stringify(profileData));
      
      // Also store in IndexedDB for larger capacity
      this.storeInIndexedDB(profileData);
      
    } catch (error) {
      console.error('Local storage failed:', error);
      throw error;
    }
  }

  // IndexedDB storage for better capacity
  async storeInIndexedDB(profileData) {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('OutlookAIAssistant', 1);
      
      request.onerror = () => reject(request.error);
      
      request.onsuccess = () => {
        const db = request.result;
        const transaction = db.transaction(['profiles'], 'readwrite');
        const store = transaction.objectStore('profiles');
        
        const putRequest = store.put(profileData, this.userId);
        putRequest.onsuccess = () => resolve();
        putRequest.onerror = () => reject(putRequest.error);
      };
      
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains('profiles')) {
          db.createObjectStore('profiles');
        }
      };
    });
  }

  // Enhanced auth token management
  async getAuthToken() {
    try {
      // Try to get fresh token
      let token = localStorage.getItem('authToken');
      
      if (!token) {
        // Try to get token from Office context
        if (typeof Office !==// src/core/StyleAnalyzer.js
class StyleAnalyzer {
  constructor(userId) {
    this.userId = userId;
    this.analysisCache = new Map();
    this.maxCacheSize = 100;
    this.isAnalyzing = false;
    this.analysisProgress = 0;
  }

  // Input validation
  validateEmailInput(emails) {
    if (!Array.isArray(emails)) {
      throw new Error('Emails must be provided as an array');
    }
    
    if (emails.length === 0) {
      throw new Error('At least one email is required for analysis');
    }
    
    if (emails.length < 5) {
      console.warn('Fewer than 5 emails provided. Analysis accuracy may be reduced.');
    }
    
    // Validate email structure
    emails.forEach((email, index) => {
      if (!email || typeof email !== 'object') {
        throw new Error(`Email at index ${index} is invalid`);
      }
      
      if (!email.body && !email.content) {
        throw new Error(`Email at index ${index} has no content`);
      }
      
      const content = email.body || email.content;
      if (typeof content !== 'string' || content.trim().length < 10) {
        throw new Error(`Email at index ${index} has insufficient content`);
      }
    });
    
    return true;
  }

  // Enhanced analysis with progress tracking
  async analyzeSampleEmails(emails, progressCallback = null) {
    try {
      // Validate input
      this.validateEmailInput(emails);
      
      // Check if already analyzing
      if (this.isAnalyzing) {
        throw new Error('Analysis already in progress');
      }
      
      this.isAnalyzing = true;
      this.analysisProgress = 0;
      
      console.log(`Analyzing ${emails.length} sample emails for user ${this.userId}`);
      
      // Generate cache key for this email set
      const emailHash = this.generateEmailHash(emails);
      const cachedAnalysis = this.getCachedAnalysis(emailHash);
      
      if (cachedAnalysis) {
        console.log('Using cached analysis');
        this.isAnalyzing = false;
        return cachedAnalysis;
      }
      
      // Progress tracking setup
      const totalSteps = 8; // Number of analysis methods
      let currentStep = 0;
      
      const updateProgress = () => {
        currentStep++;
        this.analysisProgress = (currentStep / totalSteps) * 100;
        if (progressCallback) {
          progressCallback(this.analysisProgress, `Step ${currentStep}/${totalSteps}`);
        }
      };
      
      // Perform analysis with progress updates
      const analysis = {
        emailCount: emails.length,
        analyzedAt: new Date()
      };
      
      analysis.toneProfile = await this.analyzeTone(emails);
      updateProgress();
      
      analysis.vocabularyStyle = this.analyzeVocabulary(emails);
      updateProgress();
      
      analysis.structurePatterns = this.analyzeStructure(emails);
      updateProgress();
      
      analysis.formalityLevel = this.analyzeFormalityLevel(emails);
      updateProgress();
      
      analysis.sentencePatterns = this.analyzeSentencePatterns(emails);
      updateProgress();
      
      analysis.greetingsClosings = this.analyzeGreetingsClosings(emails);
      updateProgress();
      
      analysis.commonPhrases = this.extractCommonPhrases(emails);
      updateProgress();
      
      analysis.writingTempo = this.analyzeWritingTempo(emails);
      updateProgress();

      const styleProfile = this.createStyleProfile(analysis);
      
      // Cache the analysis
      this.setCachedAnalysis(emailHash, styleProfile);
      
      // Store the profile
      await this.storeStyleProfile(styleProfile);
      
      this.isAnalyzing = false;
      this.analysisProgress = 100;
      
      if (progressCallback) {
        progressCallback(100, 'Analysis complete');
      }
      
      return styleProfile;
      
    } catch (error) {
      this.isAnalyzing = false;
      this.analysisProgress = 0;
      console.error('Error analyzing sample emails:', error);
      throw new Error(`Analysis failed: ${error.message}`);
    }
  }

  // Cache management
  generateEmailHash(emails) {
    const contentHash = emails.map(email => {
      const content = email.body || email.content || '';
      return content.substring(0, 100); // First 100 chars for hash
    }).join('|');
    
    // Simple hash function
    let hash = 0;
    for (let i = 0; i < contentHash.length; i++) {
      const char = contentHash.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString();
  }

  getCachedAnalysis(emailHash) {
    return this.analysisCache.get(emailHash);
  }

  setCachedAnalysis(emailHash, analysis) {
    // Manage cache size
    if (this.analysisCache.size >= this.maxCacheSize) {
      const firstKey = this.analysisCache.keys().next().value;
      this.analysisCache.delete(firstKey);
    }
    
    this.analysisCache.set(emailHash, {
      ...analysis,
      cachedAt: new Date()
    });
  }

  clearCache() {
    this.analysisCache.clear();
    console.log('Analysis cache cleared');
  }

  // Enhanced error handling for async operations
  async withRetry(operation, maxRetries = 3, delay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        if (attempt === maxRetries) {
          throw error;
        }
        
        console.warn(`Operation failed (attempt ${attempt}/${maxRetries}):`, error.message);
        await new Promise(resolve => setTimeout(resolve, delay * attempt));
      }
    }
  }

  // Enhanced tone analysis with better sentiment detection
  async analyzeTone(emails) {
    const toneMetrics = {
      formality: 0,
      warmth: 0,
      directness: 0,
      enthusiasm: 0,
      politeness: 0,
      confidence: 0,
      urgency: 0
    };

    const sentimentScores = [];

    emails.forEach(email => {
      const content = email.body || email.content || '';
      
      if (!content || content.trim().length === 0) {
        return; // Skip empty emails
      }
      
      // Enhanced formality analysis
      const formalWords = ['furthermore', 'however', 'therefore', 'regards', 'sincerely', 'respectfully', 'pursuant', 'accordingly', 'notwithstanding'];
      const informalWords = ['hey', 'yeah', 'totally', 'awesome', 'cool', 'thanks!', 'yep', 'nope', 'gonna', 'wanna'];
      
      const formalScore = this.countWordOccurrences(content, formalWords);
      const informalScore = this.countWordOccurrences(content, informalWords);
      toneMetrics.formality += (formalScore - informalScore);

      // Enhanced warmth analysis
      const warmWords = ['appreciate', 'thank', 'grateful', 'pleased', 'happy', 'excited', 'delighted', 'wonderful', 'amazing', 'love'];
      const coldWords = ['unfortunately', 'regret', 'disappointed', 'concerned', 'issue', 'problem'];
      
      const warmScore = this.countWordOccurrences(content, warmWords);
      const coldScore = this.countWordOccurrences(content, coldWords);
      toneMetrics.warmth += (warmScore - coldScore * 0.5);

      // Enhanced directness analysis
      const indirectPhrases = ['perhaps', 'maybe', 'might', 'could possibly', 'if you don\'t mind', 'when you get a chance'];
      const directPhrases = ['please', 'need', 'must', 'required', 'immediately', 'asap'];
      
      const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 0);
      const avgSentenceLength = sentences.length > 0 ? content.length / sentences.length : 0;
      const directnessFromLength = Math.max(0, 100 - avgSentenceLength) / 10; // Shorter = more direct
      
      const indirectScore = this.countWordOccurrences(content, indirectPhrases);
      const directScore = this.countWordOccurrences(content, directPhrases);
      
      toneMetrics.directness += directnessFromLength + (directScore - indirectScore);

      // Enhanced enthusiasm analysis
      const exclamationCount = (content.match(/!/g) || []).length;
      const enthusiasticWords = ['great', 'excellent', 'fantastic', 'amazing', 'brilliant', 'perfect', 'outstanding'];
      const enthusiasmScore = exclamationCount + this.countWordOccurrences(content, enthusiasticWords);
      toneMetrics.enthusiasm += enthusiasmScore;

      // Enhanced politeness analysis
      const politeWords = ['please', 'thank you', 'sorry', 'excuse me', 'would you mind', 'if you could', 'appreciate'];
      const rudeWords = ['wrong', 'stupid', 'ridiculous', 'obviously', 'clearly you'];
      
      const politeScore = this.countWordOccurrences(content, politeWords);
      const rudeScore = this.countWordOccurrences(content, rudeWords);
      toneMetrics.politeness += (politeScore - rudeScore);

      // Confidence analysis
      const confidentWords = ['will', 'definitely', 'certainly', 'absolutely', 'confident', 'sure', 'guarantee'];
      const uncertainWords = ['maybe', 'perhaps', 'might', 'possibly', 'unsure', 'think', 'believe'];
      
      const confidentScore = this.countWordOccurrences(content, confidentWords);
      const uncertainScore = this.countWordOccurrences(content, uncertainWords);
      toneMetrics.confidence += (confidentScore - uncertainScore);

      // Urgency analysis
      const urgentWords = ['urgent', 'asap', 'immediately', 'rush', 'deadline', 'critical', 'emergency'];
      const casualWords = ['whenever', 'eventually', 'sometime', 'no rush', 'when convenient'];
      
      const urgentScore = this.countWordOccurrences(content, urgentWords);
      const casualScore = this.countWordOccurrences(content, casualWords);
      toneMetrics.urgency += (urgentScore - casualScore);

      // Calculate overall sentiment for this email
      const positiveWords = ['good', 'great', 'excellent', 'happy', 'pleased', 'wonderful'];
      const negativeWords = ['bad', 'terrible', 'awful', 'disappointed', 'frustrated', 'annoyed'];
      
      const positiveScore = this.countWordOccurrences(content, positiveWords);
      const negativeScore = this.countWordOccurrences(content, negativeWords);
      sentimentScores.push(positiveScore - negativeScore);
    });

    // Normalize metrics to 0-10 scale
    Object.keys(toneMetrics).forEach(key => {
      const rawScore = toneMetrics[key] / emails.length;
      toneMetrics[key] = Math.max(0, Math.min(10, 5 + rawScore));
    });

    // Add overall sentiment
    const avgSentiment = sentimentScores.length > 0 
      ? sentimentScores.reduce((a, b) => a + b, 0) / sentimentScores.length 
      : 0;
    toneMetrics.overallSentiment = Math.max(0, Math.min(10, 5 + avgSentiment));

    return toneMetrics;
  }

  // Advanced vocabulary analysis with industry detection
  analyzeVocabulary(emails) {
    const vocabulary = {
      averageWordLength: 0,
      complexWords: 0,
      technicalTerms: 0,
      industryTerms: new Map(),
      commonWords: new Map(),
      uniqueWords: new Set(),
      readabilityScore: 0,
      jargonLevel: 0
    };

    let totalWords = 0;
    let totalWordLength = 0;
    let syllableCount = 0;
    let sentenceCount = 0;

    // Industry-specific term dictionaries
    const industryTerms = {
      technology: ['api', 'database', 'algorithm', 'implementation', 'optimization', 'framework', 'architecture', 'deployment', 'scalability', 'microservices'],
      business: ['revenue', 'stakeholder', 'roi', 'kpi', 'synergy', 'leverage', 'paradigm', 'deliverable', 'bandwidth', 'pivot'],
      finance: ['portfolio', 'asset', 'liability', 'equity', 'dividend', 'investment', 'capital', 'liquidity', 'volatility', 'hedge'],
      legal: ['contract', 'liability', 'clause', 'jurisdiction', 'compliance', 'statute', 'regulation', 'litigation', 'arbitration', 'indemnity'],
      marketing: ['conversion', 'engagement', 'funnel', 'segmentation', 'attribution', 'retention', 'acquisition', 'impression', 'ctr', 'persona'],
      healthcare: ['diagnosis', 'treatment', 'patient', 'clinical', 'therapeutic', 'pharmaceutical', 'procedure', 'symptoms', 'protocol', 'prognosis']
    };

    emails.forEach(email => {
      const content = email.body || email.content || '';
      if (!content) return;

      const words = content.toLowerCase().match(/\b\w+\b/g) || [];
      const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 0);
      sentenceCount += sentences.length;
      
      words.forEach(word => {
        totalWords++;
        totalWordLength += word.length;
        vocabulary.uniqueWords.add(word);
        
        // Count syllables (approximation)
        syllableCount += this.countSyllables(word);
        
        // Count occurrences
        vocabulary.commonWords.set(word, (vocabulary.commonWords.get(word) || 0) + 1);
        
        // Complex words (more than 6 characters or 3+ syllables)
        if (word.length > 6 || this.countSyllables(word) >= 3) {
          vocabulary.complexWords++;
        }
        
        // Check against industry terms
        Object.entries(industryTerms).forEach(([industry, terms]) => {
          if (terms.includes(word)) {
            vocabulary.technicalTerms++;
            const current = vocabulary.industryTerms.get(industry) || 0;
            vocabulary.industryTerms.set(industry, current + 1);
          }
        });
      });
    });

    if (totalWords > 0) {
      vocabulary.averageWordLength = totalWordLength / totalWords;
      vocabulary.complexWords = vocabulary.complexWords / totalWords;
      vocabulary.technicalTerms = vocabulary.technicalTerms / totalWords;
      
      // Calculate Flesch Reading Ease Score
      if (sentenceCount > 0) {
        const avgWordsPerSentence = totalWords / sentenceCount;
        const avgSyllablesPerWord = syllableCount / totalWords;
        vocabulary.readabilityScore = 206.835 - (1.015 * avgWordsPerSentence) - (84.6 * avgSyllablesPerWord);
        vocabulary.readabilityScore = Math.max(0, Math.min(100, vocabulary.readabilityScore));
      }
      
      // Calculate jargon level
      vocabulary.jargonLevel = Math.min(10, vocabulary.technicalTerms * 100);
    }

    // Get most significant industry
    vocabulary.primaryIndustry = this.getPrimaryIndustry(vocabulary.industryTerms);

    // Get most common meaningful words (excluding stop words)
    vocabulary.significantWords = this.getSignificantWords(vocabulary.commonWords);

    return vocabulary;
  }

  // Helper method to count syllables
  countSyllables(word) {
    word = word.toLowerCase();
    if (word.length <= 3) return 1;
    
    word = word.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, '');
    word = word.replace(/^y/, '');
    const matches = word.match(/[aeiouy]{1,2}/g);
    return matches ? matches.length : 1;
  }

  // Get primary industry based on term frequency
  getPrimaryIndustry(industryTerms) {
    if (industryTerms.size === 0) return 'general';
    
    let maxCount = 0;
    let primaryIndustry = 'general';
    
    industryTerms.forEach((count, industry) => {
      if (count > maxCount) {
        maxCount = count;
        primaryIndustry = industry;
      }
    });
    
    return primaryIndustry;
  }

  // Enhanced significant words extraction
  getSignificantWords(commonWords) {
    const stopWords = new Set([
      'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'up', 'about', 'into', 'through', 'during', 'before', 'after', 'above', 'below', 'between', 'among', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'cannot', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'her', 'its', 'our', 'their', 'mine', 'yours', 'hers', 'ours', 'theirs'
    ]);
    
    return Array.from(commonWords.entries())
      .filter(([word, count]) => 
        !stopWords.has(word) && 
        count > 1 && 
        word.length > 2 &&
        /^[a-z]+$/.test(word) // Only alphabetic words
      )
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([word, count]) => ({ word, count, frequency: count / Array.from(commonWords.values()).reduce((a, b) => a + b, 0) }));
  }

  // Advanced phrase extraction with context
  extractCommonPhrases(emails) {
    const phrases = new Map();
    const bigramPhrases = new Map();
    const trigramPhrases = new Map();
    const contextualPhrases = new Map();

    emails.forEach(email => {
      const content = email.body || email.content || '';
      if (!content) return;

      const words = content.toLowerCase().match(/\b\w+\b/g) || [];
      
      // Extract bigrams (2-word phrases)
      for (let i = 0; i < words.length - 1; i++) {
        const bigram = `${words[i]} ${words[i + 1]}`;
        if (this.isValidPhrase(bigram)) {
          bigramPhrases.set(bigram, (bigramPhrases.get(bigram) || 0) + 1);
        }
      }
      
      // Extract trigrams (3-word phrases)
      for (let i = 0; i < words.length - 2; i++) {
        const trigram = `${words[i]} ${words[i + 1]} ${words[i + 2]}`;
        if (this.isValidPhrase(trigram)) {
          trigramPhrases.set(trigram, (trigramPhrases.get(trigram) || 0) + 1);
        }
      }

      // Extract contextual phrases (common email patterns)
      const contextPatterns = [
        /please let me know/gi,
        /thank you for/gi,
        /i would like to/gi,
        /looking forward to/gi,
        /please find attached/gi,
        /as discussed/gi,
        /follow up on/gi,
        /reach out to/gi
      ];

      contextPatterns.forEach(pattern => {
        const matches = content.match(pattern);
        if (matches) {
          matches.forEach(match => {
            const phrase = match.toLowerCase();
            contextualPhrases.set(phrase, (contextualPhrases.get(phrase) || 0) + 1);
          });
        }
      });
    });

    return {
      bigrams: this.getTopPhrases(bigramPhrases, 10),
      trigrams: this.getTopPhrases(trigramPhrases, 10),
      contextual: this.getTopPhrases(contextualPhrases, 15),
      allPhrases: this.getTopPhrases(new Map([...bigramPhrases, ...trigramPhrases, ...contextualPhrases]), 25)
    };
  }

  // Validate if a phrase is meaningful
  isValidPhrase(phrase) {
    const words = phrase.split(' ');
    const stopWords = new Set(['the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by']);
    
    // Phrase must have at least one non-stop word
    const hasContentWord = words.some(word => !stopWords.has(word) && word.length > 2);
    
    // Phrase must be of reasonable length
    const reasonableLength = phrase.length >= 6 && phrase.length <= 50;
    
    // Must contain only alphabetic characters and spaces
    const validCharacters = /^[a-z\s]+$/.test(phrase);
    
    return hasContentWord && reasonableLength && validCharacters;
  }

  // Get top phrases sorted by frequency
  getTopPhrases(phrasesMap, limit) {
    return Array.from(phrasesMap.entries())
      .filter(([phrase, count]) => count > 1)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([phrase, count]) => ({ phrase, count }));
  }

  analyzeStructure(emails) {
    const structure = {
      averageParagraphs: 0,
      averageSentencesPerParagraph: 0,
      averageWordsPerSentence: 0,
      usesLists: false,
      usesNumbering: false,
      paragraphLengthVariation: 0
    };

    let totalParagraphs = 0;
    let totalSentences = 0;
    let totalWords = 0;
    const paragraphLengths = [];

    emails.forEach(email => {
      const content = email.body || email.content || '';
      
      // Count paragraphs (split by double newline or <p> tags)
      const paragraphs = content.split(/\n\s*\n|<\/p>\s*<p>/).filter(p => p.trim().length > 0);
      totalParagraphs += paragraphs.length;

      paragraphs.forEach(paragraph => {
        const sentences = paragraph.split(/[.!?]+/).filter(s => s.trim().length > 0);
        totalSentences += sentences.length;
        paragraphLengths.push(sentences.length);

        sentences.forEach(sentence => {
          const words = sentence.match(/\b\w+\b/g) || [];
          totalWords += words.length;
        });
      });

      // Check for lists and numbering
      if (content.includes('•') || content.includes('-') || /^\d+\./m.test(content)) {
        structure.usesLists = true;
      }
      
      if (/^\d+\.\s/m.test(content)) {
        structure.usesNumbering = true;
      }
    });

    if (emails.length > 0) {
      structure.averageParagraphs = totalParagraphs / emails.length;
      structure.averageSentencesPerParagraph = totalSentences / totalParagraphs || 0;
      structure.averageWordsPerSentence = totalWords / totalSentences || 0;
      
      // Calculate paragraph length variation (standard deviation)
      const avgParagraphLength = paragraphLengths.reduce((a, b) => a + b, 0) / paragraphLengths.length || 0;
      const variance = paragraphLengths.reduce((acc, length) => 
        acc + Math.pow(length - avgParagraphLength, 2), 0) / paragraphLengths.length || 0;
      structure.paragraphLengthVariation = Math.sqrt(variance);
    }

    return structure;
  }

  analyzeFormalityLevel(emails) {
    let formalityScore = 0;
    
    emails.forEach(email => {
      const content = email.body || email.content || '';
      
      // Formal indicators
      const formalIndicators = [
        'Dear Sir/Madam', 'To Whom It May Concern', 'I am writing to',
        'Please find attached', 'I would like to', 'Furthermore', 'However',
        'In conclusion', 'Yours sincerely', 'Best regards', 'Kind regards'
      ];
      
      // Informal indicators  
      const informalIndicators = [
        'Hey', 'Hi there', 'What\'s up', 'Thanks!', 'Cool', 'Awesome',
        'Yeah', 'Nope', 'Got it', 'Sounds good', 'No worries', 'Cheers'
      ];
      
      formalIndicators.forEach(indicator => {
        if (content.toLowerCase().includes(indicator.toLowerCase())) {
          formalityScore += 1;
        }
      });
      
      informalIndicators.forEach(indicator => {
        if (content.toLowerCase().includes(indicator.toLowerCase())) {
          formalityScore -= 1;
        }
      });
    });
    
    // Normalize to 0-10 scale
    return Math.max(0, Math.min(10, 5 + (formalityScore / emails.length)));
  }

  analyzeSentencePatterns(emails) {
    const patterns = {
      averageLength: 0,
      lengthVariation: 0,
      complexity: 0,
      questionFrequency: 0,
      exclamationFrequency: 0
    };

    const sentenceLengths = [];
    let totalSentences = 0;
    let questions = 0;
    let exclamations = 0;
    let complexSentences = 0;

    emails.forEach(email => {
      const content = email.body || email.content || '';
      const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 0);
      
      sentences.forEach(sentence => {
        const words = sentence.match(/\b\w+\b/g) || [];
        sentenceLengths.push(words.length);
        totalSentences++;
        
        if (sentence.includes('?')) questions++;
        if (sentence.includes('!')) exclamations++;
        
        // Complex sentence indicators (conjunctions, clauses)
        const complexityIndicators = ['although', 'however', 'moreover', 'furthermore', 'nevertheless', 'because', 'since', 'while', 'whereas'];
        if (complexityIndicators.some(indicator => sentence.toLowerCase().includes(indicator))) {
          complexSentences++;
        }
      });
    });

    if (sentenceLengths.length > 0) {
      patterns.averageLength = sentenceLengths.reduce((a, b) => a + b, 0) / sentenceLengths.length;
      
      const variance = sentenceLengths.reduce((acc, length) => 
        acc + Math.pow(length - patterns.averageLength, 2), 0) / sentenceLengths.length;
      patterns.lengthVariation = Math.sqrt(variance);
      
      patterns.complexity = complexSentences / totalSentences;
      patterns.questionFrequency = questions / totalSentences;
      patterns.exclamationFrequency = exclamations / totalSentences;
    }

    return patterns;
  }

  analyzeGreetingsClosings(emails) {
    const greetings = new Map();
    const closings = new Map();

    emails.forEach(email => {
      const content = email.body || email.content || '';
      const lines = content.split('\n').map(line => line.trim());
      
      // Analyze first few lines for greetings
      const firstLines = lines.slice(0, 3).join(' ').toLowerCase();
      const greetingPatterns = ['dear', 'hello', 'hi', 'hey', 'good morning', 'good afternoon'];
      
      greetingPatterns.forEach(pattern => {
        if (firstLines.includes(pattern)) {
          greetings.set(pattern, (greetings.get(pattern) || 0) + 1);
        }
      });

      // Analyze last few lines for closings
      const lastLines = lines.slice(-3).join(' ').toLowerCase();
      const closingPatterns = ['best regards', 'sincerely', 'thanks', 'best', 'cheers', 'talk soon'];
      
      closingPatterns.forEach(pattern => {
        if (lastLines.includes(pattern)) {
          closings.set(pattern, (closings.get(pattern) || 0) + 1);
        }
      });
    });

    return {
      preferredGreetings: Array.from(greetings.entries()).sort((a, b) => b[1] - a[1]),
      preferredClosings: Array.from(closings.entries()).sort((a, b) => b[1] - a[1])
    };
  }

  extractCommonPhrases(emails) {
    const phrases = new Map();
    const phraseLength = 3; // 3-word phrases

    emails.forEach(email => {
      const content = email.body || email.content || '';
      const words = content.toLowerCase().match(/\b\w+\b/g) || [];
      
      for (let i = 0; i <= words.length - phraseLength; i++) {
        const phrase = words.slice(i, i + phraseLength).join(' ');
        if (phrase.length > 10) { // Only meaningful phrases
          phrases.set(phrase, (phrases.get(phrase) || 0) + 1);
        }
      }
    });

    return Array.from(phrases.entries())
      .filter(([phrase, count]) => count > 1)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([phrase, count]) => ({ phrase, count }));
  }

  analyzeWritingTempo(emails) {
    // Analyze writing patterns that indicate tempo/urgency
    let urgencyScore = 0;
    let detailLevel = 0;

    emails.forEach(email => {
      const content = email.body || email.content || '';
      
      // Urgency indicators
      const urgentWords = ['asap', 'urgent', 'immediately', 'quickly', 'rush', 'deadline'];
      urgencyScore += this.countWordOccurrences(content, urgentWords);
      
      // Detail level (longer emails = more detailed)
      const wordCount = (content.match(/\b\w+\b/g) || []).length;
      detailLevel += wordCount;
    });

    return {
      urgencyTendency: urgencyScore / emails.length,
      averageDetailLevel: detailLevel / emails.length,
      writingStyle: detailLevel / emails.length > 100 ? 'detailed' : 'concise'
    };
  }

  // Enhanced style profile creation with validation
  createStyleProfile(analysis) {
    // Validate analysis data
    this.validateAnalysisData(analysis);

    const profile = {
      tone: {
        formality: this.normalizeScore(analysis.toneProfile.formality),
        warmth: this.normalizeScore(analysis.toneProfile.warmth),
        directness: this.normalizeScore(analysis.toneProfile.directness),
        enthusiasm: this.normalizeScore(analysis.toneProfile.enthusiasm),
        politeness: this.normalizeScore(analysis.toneProfile.politeness),
        confidence: this.normalizeScore(analysis.toneProfile.confidence),
        urgency: this.normalizeScore(analysis.toneProfile.urgency),
        overallSentiment: this.normalizeScore(analysis.toneProfile.overallSentiment)
      },
      vocabulary: {
        complexity: this.normalizeScore(analysis.vocabularyStyle.complexWords * 10),
        technicalLevel: this.normalizeScore(analysis.vocabularyStyle.technicalTerms * 100),
        jargonLevel: this.normalizeScore(analysis.vocabularyStyle.jargonLevel),
        readabilityScore: analysis.vocabularyStyle.readabilityScore,
        averageWordLength: analysis.vocabularyStyle.averageWordLength,
        primaryIndustry: analysis.vocabularyStyle.primaryIndustry,
        significantWords: analysis.vocabularyStyle.significantWords
      },
      structure: {
        paragraphStyle: analysis.structurePatterns.averageParagraphs,
        sentenceLength: analysis.sentencePatterns.averageLength,
        sentenceVariation: analysis.sentencePatterns.lengthVariation,
        usesLists: analysis.structurePatterns.usesLists,
        usesNumbering: analysis.structurePatterns.usesNumbering,
        complexity: this.normalizeScore(analysis.sentencePatterns.complexity * 10),
        structureConsistency: this.calculateStructureConsistency(analysis.structurePatterns)
      },
      communication: {
        greetingStyle: analysis.greetingsClosings.preferredGreetings[0]?.[0] || 'hello',
        closingStyle: analysis.greetingsClosings.preferredClosings[0]?.[0] || 'best regards',
        questionFrequency: analysis.sentencePatterns.questionFrequency,
        exclamationFrequency: analysis.sentencePatterns.exclamationFrequency,
        formalityLevel: this.categorizeFormalityLevel(analysis.formalityLevel)
      },
      patterns: {
        commonPhrases: analysis.commonPhrases.allPhrases?.map(p => p.phrase) || [],
        contextualPhrases: analysis.commonPhrases.contextual?.map(p => p.phrase) || [],
        writingTempo: analysis.writingTempo.writingStyle,
        detailLevel: this.categorizeDetailLevel(analysis.writingTempo.averageDetailLevel),
        urgencyTendency: this.normalizeScore(analysis.writingTempo.urgencyTendency * 10),
        preferredStructures: this.identifyPreferredStructures(analysis)
      },
      insights: {
        communicationStyle: this.generateCommunicationStyleInsight(analysis),
        strengths: this.identifyWritingStrengths(analysis),
        suggestions: this.generateImprovementSuggestions(analysis),
        personalityTraits: this.inferPersonalityTraits(analysis)
      },
      metadata: {
        analyzedEmails: analysis.emailCount || 0,
        createdAt: analysis.analyzedAt || new Date(),
        version: '2.0',
        analysisQuality: this.assessAnalysisQuality(analysis),
        confidence: this.calculateAnalysisConfidence(analysis)
      }
    };

    return profile;
  }

  // Utility methods for profile creation
  normalizeScore(score, min = 0, max = 10) {
    return Math.max(min, Math.min(max, score));
  }

  categorizeFormalityLevel(score) {
    if (score < 3) return 'very_informal';
    if (score < 5) return 'informal';
    if (score < 7) return 'moderate';
    if (score < 9) return 'formal';
    return 'very_formal';
  }

  categorizeDetailLevel(averageWordCount) {
    if (averageWordCount < 50) return 'very_concise';
    if (averageWordCount < 100) return 'concise';
    if (averageWordCount < 200) return 'moderate';
    if (averageWordCount < 300) return 'detailed';
    return 'very_detailed';
  }

  calculateStructureConsistency(structurePatterns) {
    // Calculate how consistent the user's structure patterns are
    const variations = [
      structurePatterns.paragraphLengthVariation || 0,
      structurePatterns.averageSentencesPerParagraph || 0
    ];
    
    const avgVariation = variations.reduce((a, b) => a + b, 0) / variations.length;
    return Math.max(0, 10 - avgVariation); // Lower variation = higher consistency
  }

  identifyPreferredStructures(analysis) {
    const structures = [];
    
    if (analysis.structurePatterns.usesLists) structures.push('bullet_points');
    if (analysis.structurePatterns.usesNumbering) structures.push('numbered_lists');
    if (analysis.structurePatterns.averageParagraphs > 3) structures.push('multi_paragraph');
    if (analysis.sentencePatterns.averageLength < 15) structures.push('short_sentences');
    if (analysis.sentencePatterns.complexity > 0.3) structures.push('complex_sentences');
    
    return structures.length > 0 ? structures : ['standard'];
  }

  generateCommunicationStyleInsight(analysis) {
    const tone = analysis.toneProfile;
    const vocab = analysis.vocabularyStyle;
    
    if (tone.formality > 7 && tone.politeness > 7) {
      return 'Professional and courteous communicator';
    } else if (tone.warmth > 7 && tone.enthusiasm > 6) {
      return 'Warm and engaging communicator';
    } else if (tone.directness > 7 && vocab.readabilityScore > 60) {
      return 'Clear and direct communicator';
    } else if (vocab.technicalLevel > 5) {
      return 'Technical and detail-oriented communicator';
    } else {
      return 'Balanced and adaptable communicator';
    }
  }

  identifyWritingStrengths(analysis) {
    const strengths = [];
    const tone = analysis.toneProfile;
    const vocab = analysis.vocabularyStyle;
    const structure = analysis.structurePatterns;
    
    if (tone.politeness > 7) strengths.push('Very polite and respectful');
    if (vocab.readabilityScore > 70) strengths.push('Clear and easy to understand');
    if (tone.warmth > 7) strengths.push('Warm and personable');
    if (structure.usesLists) strengths.push('Good use of structure and organization');
    if (vocab.technicalLevel > 5) strengths.push('Strong technical communication');
    if (tone.confidence > 7) strengths.push('Confident and assertive');
    
    return strengths.length > 0 ? strengths : ['Consistent communication style'];
  }

  generateImprovementSuggestions(analysis) {
    const suggestions = [];
    const tone = analysis.toneProfile;
    const vocab = analysis.vocabularyStyle;
    const structure = analysis.sentencePatterns;
    
    if (vocab.readabilityScore < 50) {
      suggestions.push('Consider using simpler words and shorter sentences for better clarity');
    }
    if (tone.warmth < 4) {
      suggestions.push('Adding more personal touches could make emails more engaging');
    }
    if (structure.lengthVariation < 2) {
      suggestions.push('Varying sentence length could improve flow and readability');
    }
    if (tone.politeness < 5) {
      suggestions.push('Adding more courteous language could improve professional relationships');
    }
    if (!analysis.structurePatterns.usesLists && analysis.structurePatterns.averageParagraphs > 4) {
      suggestions.push('Using bullet points or lists could improve readability for complex information');
    }
    
    return suggestions.length > 0 ? suggestions : ['Continue developing your strong communication style'];
  }

  inferPersonalityTraits(analysis) {
    const traits = [];
    const tone = analysis.toneProfile;
    
    if (tone.enthusiasm > 7) traits.push('enthusiastic');
    if (tone.directness > 7) traits.push('straightforward');
    if (tone.warmth > 7) traits.push('empathetic');
    if (tone.confidence > 7) traits.push('confident');
    if (tone.politeness > 8) traits.push('diplomatic');
    if (analysis.vocabularyStyle.technicalLevel > 6) traits.push('analytical');
    
    return traits;
  }

  assessAnalysisQuality(analysis) {
    let qualityScore = 0;
    
    // More emails = better quality
    const emailCount = analysis.emailCount || 0;
    if (emailCount >= 15) qualityScore += 30;
    else if (emailCount >= 10) qualityScore += 20;
    else if (emailCount >= 5) qualityScore += 10;
    
    // Variety in content = better quality
    if (analysis.vocabularyStyle.uniqueWords.size > 100) qualityScore += 25;
    else if (analysis.vocabularyStyle.uniqueWords.size > 50) qualityScore += 15;
    
    // Structure variety = better quality
    if (analysis.structurePatterns.paragraphLengthVariation > 1) qualityScore += 20;
    
    // Content length = better quality
    if (analysis.writingTempo.averageDetailLevel > 100) qualityScore += 25;
    
    if (qualityScore >= 80) return 'excellent';
    if (qualityScore >= 60) return 'good';
    if (qualityScore >= 40) return 'fair';
    return 'limited';
  }

  calculateAnalysisConfidence(analysis) {
    const emailCount = analysis.emailCount || 0;
    const uniqueWords = analysis.vocabularyStyle.uniqueWords.size;
    
    // Base confidence on amount of data
    let confidence = Math.min(100, (emailCount * 5) + (uniqueWords / 10));
    
    // Reduce confidence for limited data
    if (emailCount < 5) confidence *= 0.6;
    if (uniqueWords < 50) confidence *= 0.8;
    
    return Math.round(confidence);
  }

  // Validation methods
  validateAnalysisData(analysis) {
    const requiredFields = ['toneProfile', 'vocabularyStyle', 'structurePatterns', 'sentencePatterns'];
    
    requiredFields.forEach(field => {
      if (!analysis[field]) {
        throw new Error(`Missing required analysis field: ${field}`);
      }
    });
    
    if (!analysis.emailCount || analysis.emailCount < 1) {
      throw new Error('Invalid email count in analysis');
    }
    
    return true;
  }

  validateStyleProfile(profile) {
    const requiredSections = ['tone', 'vocabulary', 'structure', 'communication', 'patterns', 'metadata'];
    
    requiredSections.forEach(section => {
      if (!profile[section]) {
        throw new Error(`Missing required profile section: ${section}`);
      }
    });
    
    // Validate score ranges
    Object.values(profile.tone).forEach(score => {
      if (typeof score === 'number' && (score < 0 || score > 10)) {
        throw new Error('Tone scores must be between 0 and 10');
      }
    });
    
    return true;
  }

  // Enhanced auth token management
  async getAuthToken() {
    try {
      // Try to get fresh token
      let token = localStorage.getItem('authToken');
      
      if (!token) {
        // Try to get token from Office context
        if (typeof Office !== 'undefined' && Office.context?.auth) {
          token = await this.getOfficeToken();
        } else {
          // Development fallback
          token = 'dev-token-' + this.userId;
        }
      }
      
      // Validate token if it exists
      if (token && token !== 'dev-token-' + this.userId) {
        const isValid = await this.validateToken(token);
        if (!isValid) {
          token = await this.refreshToken();
        }
      }
      
      return token;
      
    } catch (error) {
      console.warn('Token management error:', error);
      return 'fallback-token-' + Date.now();
    }
  }

  async getOfficeToken() {
    return new Promise((resolve, reject) => {
      Office.context.auth.getAccessTokenAsync((result) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
          resolve(result.value);
        } else {
          reject(new Error('Failed to get Office token'));
        }
      });
    });
  }

  async validateToken(token) {
    try {
      const response = await fetch('/api/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async refreshToken() {
    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('authToken', data.token);
        return data.token;
      }
      
      throw new Error('Token refresh failed');
    } catch (error) {
      console.error('Token refresh error:', error);
      return 'refresh-failed-' + Date.now();
    }
  }

  // Utility and cleanup methods
  getAnalysisProgress() {
    return {
      isAnalyzing: this.isAnalyzing,
      progress: this.analysisProgress,
      userId: this.userId
    };
  }

  // Reset analyzer state
  reset() {
    this.isAnalyzing = false;
    this.analysisProgress = 0;
    this.clearCache();
    console.log('StyleAnalyzer reset completed');
  }

  // Export analysis for debugging
  exportAnalysisData() {
    return {
      userId: this.userId,
      cacheSize: this.analysisCache.size,
      isAnalyzing: this.isAnalyzing,
      progress: this.analysisProgress,
      timestamp: new Date().toISOString()
    };
  }

  // Load profile from storage
  async loadStoredProfile() {
    try {
      // Try API first
      const response = await fetch(`/api/users/${this.userId}/profile`);
      if (response.ok) {
        return await response.json();
      }
      
      // Fallback to local storage
      const localProfile = localStorage.getItem(`styleProfile_${this.userId}`);
      if (localProfile) {
        const data = JSON.parse(localProfile);
        console.log('Loaded profile from local storage');
        return data.profile;
      }
      
      // Fallback to IndexedDB
      return await this.loadFromIndexedDB();
      
    } catch (error) {
      console.error('Error loading stored profile:', error);
      return null;
    }
  }

  async loadFromIndexedDB() {
    return new Promise((resolve) => {
      const request = indexedDB.open('OutlookAIAssistant', 1);
      
      request.onsuccess = () => {
        const db = request.result;
        const transaction = db.transaction(['profiles'], 'readonly');
        const store = transaction.objectStore('profiles');
        
        const getRequest = store.get(this.userId);
        getRequest.onsuccess = () => {
          resolve(getRequest.result?.profile || null);
        };
        getRequest.onerror = () => resolve(null);
      };
      
      request.onerror = () => resolve(null);
    });
  }

  // Performance monitoring
  measurePerformance(operation, startTime) {
    const endTime = performance.now();
    const duration = endTime - startTime;
    
    console.log(`StyleAnalyzer.${operation} took ${duration.toFixed(2)}ms`);
    
    // Log slow operations
    if (duration > 1000) {
      console.warn(`Slow operation detected: ${operation} took ${duration.toFixed(2)}ms`);
    }
    
    return duration;
  }

  // Health check for the analyzer
  healthCheck() {
    const health = {
      status: 'healthy',
      checks: {
        initialized: !!this.userId,
        notAnalyzing: !this.isAnalyzing,
        cacheSize: this.analysisCache.size,
        maxCacheSize: this.maxCacheSize
      },
      timestamp: new Date().toISOString()
    };
    
    // Check for issues
    if (!health.checks.initialized) {
      health.status = 'unhealthy';
      health.issues = ['Not initialized with userId'];
    }
    
    if (health.checks.cacheSize > health.checks.maxCacheSize * 0.9) {
      health.status = 'warning';
      health.issues = health.issues || [];
      health.issues.push('Cache nearly full');
    }
    
    return health;
  }

  // Debug utilities
  debugInfo() {
    return {
      userId: this.userId,
      isAnalyzing: this.isAnalyzing,
      progress: this.analysisProgress,
      cacheSize: this.analysisCache.size,
      cacheKeys: Array.from(this.analysisCache.keys()),
      maxCacheSize: this.maxCacheSize,
      version: '2.0'
    };
  }

  // Cleanup method for component unmounting
  dispose() {
    this.clearCache();
    this.isAnalyzing = false;
    this.analysisProgress = 0;
    this.userId = null;
    console.log('StyleAnalyzer disposed');
  }

  // Helper method for word occurrence counting (enhanced)
  countWordOccurrences(text, words) {
    if (!text || !Array.isArray(words)) return 0;
    
    const lowerText = text.toLowerCase();
    return words.reduce((count, word) => {
      if (typeof word !== 'string') return count;
      
      const regex = new RegExp(`\\b${word.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\  async storeStyleProfile(styleProfile) {
    try {
      const response = await fetch('/api/users/style-profile', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${await this.getAuthToken()}`
        },
        body: JSON.stringify({
          userId: this.userId,
          styleProfile: styleProfile
        })
      });

      if (!response.ok) {
        throw new Error('Failed to store style profile');
      }

      console.log('Style profile stored successfully');
      return true;
    } catch (error) {
      console.error('Error storing style profile:', error);
      throw error;
    }
  }

  countWordOccurrences(text, words) {
    const lowerText = text.toLowerCase();
    return words.reduce((count, word) => {
      const regex = new RegExp(`\\b${word.toLowerCase()}\\b`, 'g');
      const matches = lowerText.match(regex);
      return count + (matches ? matches.length : 0);
    }, 0);
  }

  async getAuthToken() {
    return localStorage.getItem('authToken') || 'dev-token';
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { StyleAnalyzer };
} else {
  window.StyleAnalyzer = StyleAnalyzer;
}')}\\b`, 'g');
      const matches = lowerText.match(regex);
      return count + (matches ? matches.length : 0);
    }, 0);
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { StyleAnalyzer };
} else {
  window.StyleAnalyzer = StyleAnalyzer;
}