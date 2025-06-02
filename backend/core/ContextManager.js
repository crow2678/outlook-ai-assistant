// src/core/ContextManager.js
class ContextManager {
  constructor(userId) {
    this.userId = userId;
    this.contextCache = new Map();
    this.recipientCache = new Map();
    this.isGathering = false;
    this.maxCacheSize = 50;
    this.cacheExpiry = 5 * 60 * 1000; // 5 minutes
  }

  // Main context gathering method
  async gatherContext() {
    if (this.isGathering) {
      console.warn('Context gathering already in progress');
      return this.getLastContext();
    }

    try {
      this.isGathering = true;
      const startTime = performance.now();
      
      console.log('Gathering email context...');
      
      // Check cache first
      const cacheKey = await this.generateContextCacheKey();
      const cachedContext = this.getCachedContext(cacheKey);
      
      if (cachedContext) {
        console.log('Using cached context');
        this.isGathering = false;
        return cachedContext;
      }

      // Gather all context components
      const context = {
        timestamp: new Date(),
        userId: this.userId,
        email: await this.getCurrentEmailContext(),
        recipient: await this.getRecipientContext(),
        thread: await this.getThreadContext(),
        temporal: this.getTemporalContext(),
        environment: this.getEnvironmentContext(),
        user: await this.getUserContext()
      };

      // Enrich context with relationships and patterns
      context.enriched = await this.enrichContext(context);
      
      // Cache the context
      this.setCachedContext(cacheKey, context);
      
      const duration = performance.now() - startTime;
      console.log(`Context gathering completed in ${duration.toFixed(2)}ms`);
      
      this.isGathering = false;
      return context;
      
    } catch (error) {
      this.isGathering = false;
      console.error('Error gathering context:', error);
      
      // Return minimal context as fallback
      return this.getMinimalContext();
    }
  }

  // Get current email context from Outlook
  async getCurrentEmailContext() {
    try {
      if (typeof Office === 'undefined' || !Office.context?.mailbox?.item) {
        return this.getMockEmailContext(); // For development
      }

      const item = Office.context.mailbox.item;
      const emailContext = {
        id: item.itemId,
        subject: '',
        body: '',
        isReply: false,
        isForward: false,
        hasAttachments: false,
        importance: 'normal',
        sensitivity: 'normal'
      };

      // Get subject
      emailContext.subject = await this.getEmailSubject(item);
      
      // Get body content
      emailContext.body = await this.getEmailBody(item);
      
      // Determine email type
      emailContext.emailType = this.detectEmailType(emailContext.subject, emailContext.body);
      
      // Check if reply or forward
      emailContext.isReply = this.isReplyEmail(emailContext.subject);
      emailContext.isForward = this.isForwardEmail(emailContext.subject);
      
      // Get attachments info
      emailContext.hasAttachments = item.attachments && item.attachments.length > 0;
      
      // Get importance and sensitivity
      emailContext.importance = item.notificationMessages?.importance || 'normal';
      emailContext.sensitivity = item.sensitivity || 'normal';
      
      // Analyze content characteristics
      emailContext.analysis = this.analyzeEmailContent(emailContext.body);
      
      return emailContext;
      
    } catch (error) {
      console.error('Error getting current email context:', error);
      return this.getMockEmailContext();
    }
  }

  // Helper methods for email context
  async getEmailSubject(item) {
    return new Promise((resolve) => {
      if (item.subject) {
        resolve(item.subject);
      } else {
        item.subject.getAsync((result) => {
          resolve(result.status === Office.AsyncResultStatus.Succeeded ? result.value : '');
        });
      }
    });
  }

  async getEmailBody(item) {
    return new Promise((resolve) => {
      item.body.getAsync(Office.CoercionType.Text, (result) => {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
          resolve(result.value || '');
        } else {
          resolve('');
        }
      });
    });
  }

  // Detect email type based on subject and content
  detectEmailType(subject, body) {
    const lowerSubject = subject.toLowerCase();
    const lowerBody = body.toLowerCase();
    
    // Meeting-related
    if (lowerSubject.includes('meeting') || lowerSubject.includes('call') || 
        lowerBody.includes('meeting') || lowerBody.includes('schedule')) {
      return 'meeting_request';
    }
    
    // Follow-up
    if (lowerSubject.includes('follow up') || lowerSubject.includes('following up') ||
        lowerBody.includes('follow up') || lowerBody.includes('following up')) {
      return 'follow_up';
    }
    
    // Introduction
    if (lowerSubject.includes('introduction') || lowerSubject.includes('intro') ||
        lowerBody.includes('introduce') || lowerBody.includes('pleased to meet')) {
      return 'introduction';
    }
    
    // Request
    if (lowerSubject.includes('request') || lowerBody.includes('could you') || 
        lowerBody.includes('would you') || lowerBody.includes('please')) {
      return 'request';
    }
    
    // Status update
    if (lowerSubject.includes('update') || lowerSubject.includes('status') ||
        lowerBody.includes('update') || lowerBody.includes('progress')) {
      return 'status_update';
    }
    
    // Apology
    if (lowerSubject.includes('sorry') || lowerSubject.includes('apology') ||
        lowerBody.includes('sorry') || lowerBody.includes('apologize')) {
      return 'apology';
    }
    
    // Thank you
    if (lowerSubject.includes('thank') || lowerBody.includes('thank you') ||
        lowerBody.includes('grateful') || lowerBody.includes('appreciate')) {
      return 'gratitude';
    }
    
    return 'general';
  }

  // Check if email is a reply
  isReplyEmail(subject) {
    const replyPrefixes = ['re:', 'reply:', 'response:'];
    const lowerSubject = subject.toLowerCase();
    return replyPrefixes.some(prefix => lowerSubject.startsWith(prefix));
  }

  // Check if email is a forward
  isForwardEmail(subject) {
    const forwardPrefixes = ['fwd:', 'fw:', 'forward:', 'forwarded:'];
    const lowerSubject = subject.toLowerCase();
    return forwardPrefixes.some(prefix => lowerSubject.startsWith(prefix));
  }

  // Analyze email content characteristics
  analyzeEmailContent(body) {
    if (!body) return {};
    
    const words = body.match(/\b\w+\b/g) || [];
    const sentences = body.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const paragraphs = body.split(/\n\s*\n/).filter(p => p.trim().length > 0);
    
    return {
      wordCount: words.length,
      sentenceCount: sentences.length,
      paragraphCount: paragraphs.length,
      averageWordsPerSentence: sentences.length > 0 ? words.length / sentences.length : 0,
      hasQuestions: body.includes('?'),
      hasExclamations: body.includes('!'),
      hasUrls: /https?:\/\//.test(body),
      hasPhoneNumbers: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/.test(body),
      hasEmails: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(body),
      sentiment: this.quickSentimentAnalysis(body)
    };
  }

  // Quick sentiment analysis
  quickSentimentAnalysis(text) {
    const positiveWords = ['good', 'great', 'excellent', 'happy', 'pleased', 'wonderful', 'amazing', 'fantastic', 'perfect', 'love'];
    const negativeWords = ['bad', 'terrible', 'awful', 'disappointed', 'frustrated', 'annoyed', 'angry', 'upset', 'concerned', 'worried'];
    
    const lowerText = text.toLowerCase();
    let positiveScore = 0;
    let negativeScore = 0;
    
    positiveWords.forEach(word => {
      const matches = lowerText.match(new RegExp(`\\b${word}\\b`, 'g'));
      positiveScore += matches ? matches.length : 0;
    });
    
    negativeWords.forEach(word => {
      const matches = lowerText.match(new RegExp(`\\b${word}\\b`, 'g'));
      negativeScore += matches ? matches.length : 0;
    });
    
    if (positiveScore > negativeScore) return 'positive';
    if (negativeScore > positiveScore) return 'negative';
    return 'neutral';
  }

  // Get recipient context and relationship analysis
  async getRecipientContext() {
    try {
      if (typeof Office === 'undefined' || !Office.context?.mailbox?.item) {
        return this.getMockRecipientContext(); // For development
      }

      const item = Office.context.mailbox.item;
      const recipients = {
        to: [],
        cc: [],
        bcc: [],
        total: 0
      };

      // Get TO recipients
      if (item.to && item.to.length > 0) {
        recipients.to = await this.processRecipients(item.to);
      }
      
      // Get CC recipients
      if (item.cc && item.cc.length > 0) {
        recipients.cc = await this.processRecipients(item.cc);
      }
      
      // Get BCC recipients (if available)
      if (item.bcc && item.bcc.length > 0) {
        recipients.bcc = await this.processRecipients(item.bcc);
      }
      
      recipients.total = recipients.to.length + recipients.cc.length + recipients.bcc.length;
      
      // Analyze recipient relationships
      const analysis = await this.analyzeRecipientRelationships(recipients);
      
      return {
        recipients,
        analysis,
        primary: recipients.to.length > 0 ? recipients.to[0] : null,
        isGroupEmail: recipients.total > 1,
        hasExternalRecipients: analysis.hasExternal,
        dominantRelationship: analysis.dominantRelationship
      };
      
    } catch (error) {
      console.error('Error getting recipient context:', error);
      return this.getMockRecipientContext();
    }
  }

  // Process and enrich recipient information
  async processRecipients(recipientList) {
    const processed = [];
    
    for (const recipient of recipientList) {
      const enrichedRecipient = {
        email: recipient.emailAddress,
        name: recipient.displayName || recipient.emailAddress,
        type: recipient.recipientType || 'to'
      };
      
      // Check cache first
      const cachedInfo = this.getCachedRecipient(enrichedRecipient.email);
      if (cachedInfo) {
        processed.push({ ...enrichedRecipient, ...cachedInfo });
        continue;
      }
      
      // Analyze recipient
      const analysis = await this.analyzeRecipient(enrichedRecipient);
      const finalRecipient = { ...enrichedRecipient, ...analysis };
      
      // Cache the analysis
      this.setCachedRecipient(enrichedRecipient.email, analysis);
      
      processed.push(finalRecipient);
    }
    
    return processed;
  }

  // Analyze individual recipient
  async analyzeRecipient(recipient) {
    const analysis = {
      isInternal: this.isInternalEmail(recipient.email),
      domain: this.extractDomain(recipient.email),
      relationship: 'unknown',
      communicationHistory: null,
      preferredTone: 'professional'
    };
    
    // Determine relationship level
    analysis.relationship = this.determineRelationship(recipient.email, analysis.isInternal);
    
    // Get communication history if available
    analysis.communicationHistory = await this.getCommunicationHistory(recipient.email);
    
    // Determine preferred communication tone
    analysis.preferredTone = this.determinePreferredTone(analysis);
    
    return analysis;
  }

  // Check if email is internal to organization
  isInternalEmail(email) {
    if (!email) return false;
    
    // Get user's domain from their email
    const userDomain = this.getUserDomain();
    const recipientDomain = this.extractDomain(email);
    
    return userDomain && recipientDomain && userDomain === recipientDomain;
  }

  // Extract domain from email
  extractDomain(email) {
    if (!email || !email.includes('@')) return null;
    return email.split('@')[1].toLowerCase();
  }

  // Get user's domain
  getUserDomain() {
    try {
      if (typeof Office !== 'undefined' && Office.context?.mailbox?.userProfile?.emailAddress) {
        return this.extractDomain(Office.context.mailbox.userProfile.emailAddress);
      }
      
      // Fallback to stored user info
      const storedUser = localStorage.getItem('userProfile');
      if (storedUser) {
        const userProfile = JSON.parse(storedUser);
        return this.extractDomain(userProfile.email);
      }
      
      return null;
    } catch (error) {
      console.error('Error getting user domain:', error);
      return null;
    }
  }

  // Determine relationship level
  determineRelationship(email, isInternal) {
    // Internal relationships
    if (isInternal) {
      // Check against known patterns
      if (email.includes('ceo') || email.includes('president')) return 'executive';
      if (email.includes('manager') || email.includes('director')) return 'management';
      if (email.includes('hr') || email.includes('admin')) return 'support';
      return 'colleague';
    }
    
    // External relationships
    const domain = this.extractDomain(email);
    if (domain) {
      // Check against known customer/vendor domains
      if (this.isKnownCustomerDomain(domain)) return 'customer';
      if (this.isKnownVendorDomain(domain)) return 'vendor';
    }
    
    return 'external';
  }

  // Mock/fallback methods
  getMockEmailContext() {
    return {
      id: 'mock-email-id',
      subject: 'Sample Email Subject',
      body: 'This is a sample email body for development purposes.',
      emailType: 'general',
      isReply: false,
      isForward: false,
      hasAttachments: false,
      importance: 'normal',
      sensitivity: 'normal',
      analysis: {
        wordCount: 10,
        sentenceCount: 1,
        paragraphCount: 1,
        sentiment: 'neutral'
      }
    };
  }

  // Get thread context and conversation history
  async getThreadContext() {
    try {
      if (typeof Office === 'undefined' || !Office.context?.mailbox?.item) {
        return this.getMockThreadContext(); // For development
      }

      const item = Office.context.mailbox.item;
      const threadContext = {
        conversationId: item.conversationId,
        isNewConversation: true,
        threadLength: 1,
        previousEmails: [],
        threadSummary: '',
        toneProgression: [],
        participants: new Set(),
        threadType: 'single'
      };

      // Get conversation history if available
      if (item.conversationId) {
        const conversationHistory = await this.getConversationHistory(item.conversationId);
        threadContext.previousEmails = conversationHistory.emails || [];
        threadContext.threadLength = conversationHistory.emails?.length + 1 || 1;
        threadContext.isNewConversation = threadContext.threadLength === 1;
        
        // Analyze thread patterns
        if (threadContext.previousEmails.length > 0) {
          threadContext.threadSummary = this.generateThreadSummary(threadContext.previousEmails);
          threadContext.toneProgression = this.analyzeToneProgression(threadContext.previousEmails);
          threadContext.participants = this.extractThreadParticipants(threadContext.previousEmails);
          threadContext.threadType = this.determineThreadType(threadContext.previousEmails);
          threadContext.urgencyTrend = this.analyzeUrgencyTrend(threadContext.previousEmails);
          threadContext.responsePattern = this.analyzeResponsePattern(threadContext.previousEmails);
        }
      }

      return threadContext;
      
    } catch (error) {
      console.error('Error getting thread context:', error);
      return this.getMockThreadContext();
    }
  }

  // Get conversation history using Graph API or Exchange
  async getConversationHistory(conversationId) {
    try {
      // Try to get conversation from Exchange/Graph API
      const response = await this.fetchConversationHistory(conversationId);
      if (response && response.emails) {
        return response;
      }
      
      // Fallback to cached history
      const cached = this.getCachedConversation(conversationId);
      if (cached) {
        return cached;
      }
      
      return { emails: [] };
      
    } catch (error) {
      console.error('Error fetching conversation history:', error);
      return { emails: [] };
    }
  }

  async fetchConversationHistory(conversationId) {
    try {
      const token = await this.getAuthToken();
      const response = await fetch(`/api/conversations/${conversationId}/history`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        return await response.json();
      }
      
      return null;
    } catch (error) {
      console.warn('Could not fetch conversation history:', error);
      return null;
    }
  }

  // Generate summary of thread conversation
  generateThreadSummary(emails) {
    if (!emails || emails.length === 0) return '';
    
    const topics = new Set();
    const keyPoints = [];
    let overallTone = 'neutral';
    
    emails.forEach((email, index) => {
      // Extract key topics from subject
      if (email.subject) {
        const cleanSubject = email.subject.replace(/^(re:|fwd?:|fw:)\s*/i, '').trim();
        if (cleanSubject.length > 0) {
          topics.add(cleanSubject);
        }
      }
      
      // Extract key phrases from content
      if (email.body) {
        const keyPhrases = this.extractKeyPhrases(email.body);
        keyPoints.push(...keyPhrases);
      }
      
      // Track tone changes
      if (email.sentiment) {
        overallTone = this.combineTones(overallTone, email.sentiment);
      }
    });
    
    const summary = {
      mainTopics: Array.from(topics).slice(0, 3),
      keyPoints: this.consolidateKeyPoints(keyPoints),
      emailCount: emails.length,
      overallTone: overallTone,
      timeSpan: this.calculateTimeSpan(emails),
      lastActivity: emails[emails.length - 1]?.timestamp || new Date()
    };
    
    return summary;
  }

  // Extract key phrases from email content
  extractKeyPhrases(content) {
    if (!content) return [];
    
    const keyPhrasePatterns = [
      /(?:need to|must|should|have to|required to)\s+([^.!?]{10,50})/gi,
      /(?:please|could you|would you)\s+([^.!?]{10,50})/gi,
      /(?:deadline|due date|by)\s+([^.!?]{5,30})/gi,
      /(?:meeting|call|discussion)\s+([^.!?]{5,40})/gi,
      /(?:decision|conclusion|result)\s+([^.!?]{5,40})/gi
    ];
    
    const phrases = [];
    keyPhrasePatterns.forEach(pattern => {
      const matches = content.match(pattern);
      if (matches) {
        phrases.push(...matches.map(match => match.trim().substring(0, 50)));
      }
    });
    
    return phrases.slice(0, 5); // Limit to top 5 phrases
  }

  // Analyze tone progression through the thread
  analyzeToneProgression(emails) {
    const progression = [];
    
    emails.forEach((email, index) => {
      const tone = {
        index: index,
        timestamp: email.timestamp,
        sender: email.from,
        sentiment: email.sentiment || this.quickSentimentAnalysis(email.body || ''),
        formality: this.assessFormality(email.body || ''),
        urgency: this.assessUrgency(email.body || '', email.subject || ''),
        politeness: this.assessPoliteness(email.body || '')
      };
      
      progression.push(tone);
    });
    
    return {
      progression: progression,
      trendAnalysis: this.analyzeToneTrends(progression),
      recommendations: this.generateToneRecommendations(progression)
    };
  }

  // Assess formality level of content
  assessFormality(content) {
    const formalIndicators = ['furthermore', 'however', 'therefore', 'regards', 'sincerely', 'respectfully', 'pursuant', 'accordingly'];
    const informalIndicators = ['hey', 'yeah', 'totally', 'awesome', 'cool', 'thanks!', 'yep', 'gonna'];
    
    const formalCount = this.countWords(content, formalIndicators);
    const informalCount = this.countWords(content, informalIndicators);
    
    if (formalCount > informalCount) return 'formal';
    if (informalCount > formalCount) return 'informal';
    return 'neutral';
  }

  // Assess urgency level
  assessUrgency(content, subject) {
    const urgentIndicators = ['urgent', 'asap', 'immediately', 'rush', 'deadline', 'critical', 'emergency', 'time-sensitive'];
    const casualIndicators = ['whenever', 'eventually', 'sometime', 'no rush', 'when convenient'];
    
    const combinedText = (subject + ' ' + content).toLowerCase();
    const urgentCount = this.countWords(combinedText, urgentIndicators);
    const casualCount = this.countWords(combinedText, casualIndicators);
    
    if (urgentCount > 0) return 'high';
    if (casualCount > 0) return 'low';
    return 'medium';
  }

  // Assess politeness level
  assessPoliteness(content) {
    const politeIndicators = ['please', 'thank you', 'sorry', 'excuse me', 'would you mind', 'if you could', 'appreciate'];
    const rudeIndicators = ['wrong', 'stupid', 'ridiculous', 'obviously', 'clearly you'];
    
    const politeCount = this.countWords(content, politeIndicators);
    const rudeCount = this.countWords(content, rudeIndicators);
    
    if (politeCount > rudeCount && politeCount > 0) return 'high';
    if (rudeCount > 0) return 'low';
    return 'medium';
  }

  // Analyze trends in tone progression
  analyzeToneTrends(progression) {
    if (progression.length < 2) return { trend: 'insufficient_data' };
    
    const trends = {
      sentiment: this.calculateTrend(progression.map(p => this.sentimentToNumber(p.sentiment))),
      formality: this.calculateTrend(progression.map(p => this.formalityToNumber(p.formality))),
      urgency: this.calculateTrend(progression.map(p => this.urgencyToNumber(p.urgency))),
      politeness: this.calculateTrend(progression.map(p => this.politenessToNumber(p.politeness)))
    };
    
    return {
      overall: this.determineOverallTrend(trends),
      details: trends,
      recommendations: this.generateTrendRecommendations(trends)
    };
  }

  // Calculate trend direction (increasing, decreasing, stable)
  calculateTrend(values) {
    if (values.length < 2) return 'stable';
    
    let increasing = 0;
    let decreasing = 0;
    
    for (let i = 1; i < values.length; i++) {
      if (values[i] > values[i-1]) increasing++;
      else if (values[i] < values[i-1]) decreasing++;
    }
    
    if (increasing > decreasing) return 'increasing';
    if (decreasing > increasing) return 'decreasing';
    return 'stable';
  }

  // Get temporal context (time, day, urgency patterns)
  getTemporalContext() {
    const now = new Date();
    const context = {
      timestamp: now,
      timeOfDay: this.getTimeOfDay(now),
      dayOfWeek: this.getDayOfWeek(now),
      isBusinessHours: this.isBusinessHours(now),
      isWeekend: this.isWeekend(now),
      timezone: this.getTimezone(),
      seasonality: this.getSeasonality(now),
      urgencyContext: this.getUrgencyContext(now)
    };
    
    return context;
  }

  getTimeOfDay(date) {
    const hour = date.getHours();
    if (hour < 6) return 'late_night';
    if (hour < 12) return 'morning';
    if (hour < 17) return 'afternoon';
    if (hour < 21) return 'evening';
    return 'night';
  }

  getDayOfWeek(date) {
    const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
    return days[date.getDay()];
  }

  isBusinessHours(date) {
    const hour = date.getHours();
    const day = date.getDay();
    return day >= 1 && day <= 5 && hour >= 9 && hour <= 17;
  }

  isWeekend(date) {
    const day = date.getDay();
    return day === 0 || day === 6; // Sunday or Saturday
  }

  getTimezone() {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch (error) {
      return 'UTC';
    }
  }

  getSeasonality(date) {
    const month = date.getMonth();
    if (month >= 11 || month <= 1) return 'winter';
    if (month >= 2 && month <= 4) return 'spring';
    if (month >= 5 && month <= 7) return 'summer';
    return 'fall';
  }

  getUrgencyContext(date) {
    const context = {
      isAfterHours: !this.isBusinessHours(date),
      isWeekend: this.isWeekend(date),
      suggestedResponseTime: 'standard'
    };
    
    // Adjust expected response time based on temporal context
    if (context.isWeekend) {
      context.suggestedResponseTime = 'relaxed';
    } else if (context.isAfterHours) {
      context.suggestedResponseTime = 'next_business_day';
    } else {
      const hour = date.getHours();
      if (hour >= 9 && hour <= 11) {
        context.suggestedResponseTime = 'quick'; // Morning rush
      }
    }
    
    return context;
  }

  // Get environment context (device, platform, etc.)
  getEnvironmentContext() {
    const context = {
      platform: this.detectPlatform(),
      device: this.detectDevice(),
      connection: this.getConnectionInfo(),
      capabilities: this.getCapabilities()
    };
    
    return context;
  }

  detectPlatform() {
    if (typeof Office !== 'undefined') {
      if (Office.context?.platform) {
        return Office.context.platform === Office.PlatformType.PC ? 'desktop' : 'web';
      }
    }
    
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes('electron')) return 'desktop';
    if (userAgent.includes('mobile')) return 'mobile';
    return 'web';
  }

  detectDevice() {
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes('mobile') || userAgent.includes('android') || userAgent.includes('iphone')) {
      return 'mobile';
    }
    if (userAgent.includes('tablet') || userAgent.includes('ipad')) {
      return 'tablet';
    }
    return 'desktop';
  }

  getConnectionInfo() {
    if ('connection' in navigator) {
      return {
        type: navigator.connection.effectiveType || 'unknown',
        speed: navigator.connection.downlink || 'unknown'
      };
    }
    return { type: 'unknown', speed: 'unknown' };
  }

  getCapabilities() {
    return {
      offlineCapable: 'serviceWorker' in navigator,
      notificationSupported: 'Notification' in window,
      speechSupported: 'speechSynthesis' in window,
      cameraSupported: 'mediaDevices' in navigator
    };
  }