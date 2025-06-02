// src/core/LearningEngine.js
class LearningEngine {
  constructor(userId) {
    this.userId = userId;
    this.learningData = new Map();
    this.feedbackHistory = [];
    this.patterns = new Map();
    this.adaptations = new Map();
    this.isProcessing = false;
    this.learningRate = 0.1; // How quickly to adapt (0.0 to 1.0)
    this.confidenceThreshold = 0.7; // Minimum confidence for suggestions
    this.maxFeedbackHistory = 1000; // Maximum feedback items to keep in memory
  }

  // Initialize learning engine with user's historical data
  async initialize() {
    try {
      console.log(`Initializing LearningEngine for user ${this.userId}`);
      
      // Load existing learning data
      await this.loadLearningData();
      
      // Load feedback history
      await this.loadFeedbackHistory();
      
      // Initialize pattern recognition
      await this.initializePatterns();
      
      // Calculate initial adaptations
      await this.calculateAdaptations();
      
      console.log('LearningEngine initialized successfully');
      return true;
      
    } catch (error) {
      console.error('Error initializing LearningEngine:', error);
      throw error;
    }
  }

  // Record user interaction with AI suggestion
  async recordInteraction(interaction) {
    try {
      if (this.isProcessing) {
        console.warn('LearningEngine is busy processing, queuing interaction');
        return this.queueInteraction(interaction);
      }

      const enrichedInteraction = {
        ...interaction,
        id: this.generateInteractionId(),
        timestamp: new Date(),
        userId: this.userId,
        processed: false
      };

      // Store interaction
      this.feedbackHistory.push(enrichedInteraction);
      
      // Maintain history size limit
      if (this.feedbackHistory.length > this.maxFeedbackHistory) {
        this.feedbackHistory.shift();
      }

      // Process interaction asynchronously
      this.processInteractionAsync(enrichedInteraction);
      
      return enrichedInteraction.id;
      
    } catch (error) {
      console.error('Error recording interaction:', error);
      throw error;
    }
  }

  // Record user feedback on AI suggestion
  async recordUserFeedback(suggestionId, action, modifiedText = null, rating = null) {
    try {
      const feedback = {
        suggestionId,
        userId: this.userId,
        action, // 'accept', 'modify', 'reject'
        modifiedText,
        rating, // 1-5 scale
        timestamp: new Date(),
        processed: false
      };

      // Find the original interaction
      const originalInteraction = this.findInteraction(suggestionId);
      if (originalInteraction) {
        feedback.context = originalInteraction.context;
        feedback.suggestion = originalInteraction.suggestion;
      }

      // Store feedback
      this.feedbackHistory.push(feedback);
      
      // Process feedback for learning
      await this.processFeedback(feedback);
      
      // Update learning patterns
      await this.updateLearningPatterns(feedback);
      
      return feedback;
      
    } catch (error) {
      console.error('Error recording user feedback:', error);
      throw error;
    }
  }

  // Process feedback to extract learning insights
  async processFeedback(feedback) {
    try {
      const { action, context, suggestion, modifiedText, rating } = feedback;
      
      // Analyze acceptance patterns
      if (action === 'accept') {
        await this.reinforceSuccessfulPattern(context, suggestion);
      } else if (action === 'reject') {
        await this.recordFailurePattern(context, suggestion);
      } else if (action === 'modify' && modifiedText) {
        await this.analyzeModification(context, suggestion, modifiedText);
      }

      // Process rating if provided
      if (rating !== null) {
        await this.processRating(context, suggestion, rating);
      }

      // Update confidence scores
      await this.updateConfidenceScores(feedback);
      
      feedback.processed = true;
      
    } catch (error) {
      console.error('Error processing feedback:', error);
    }
  }

  // Reinforce patterns that led to successful suggestions
  async reinforceSuccessfulPattern(context, suggestion) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      // Increase success count
      pattern.successCount = (pattern.successCount || 0) + 1;
      pattern.totalAttempts = (pattern.totalAttempts || 0) + 1;
      
      // Update success characteristics
      if (!pattern.successfulCharacteristics) {
        pattern.successfulCharacteristics = {};
      }
      
      // Analyze what made this suggestion successful
      const characteristics = this.extractSuggestionCharacteristics(suggestion);
      Object.keys(characteristics).forEach(key => {
        if (!pattern.successfulCharacteristics[key]) {
          pattern.successfulCharacteristics[key] = [];
        }
        pattern.successfulCharacteristics[key].push(characteristics[key]);
      });
      
      // Update confidence
      pattern.confidence = pattern.successCount / pattern.totalAttempts;
      pattern.lastUpdated = new Date();
      
      this.patterns.set(patternKey, pattern);
      
      console.log(`Reinforced pattern ${patternKey} (success rate: ${(pattern.confidence * 100).toFixed(1)}%)`);
      
    } catch (error) {
      console.error('Error reinforcing successful pattern:', error);
    }
  }

  // Record patterns that led to unsuccessful suggestions
  async recordFailurePattern(context, suggestion) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      // Increase failure count
      pattern.failureCount = (pattern.failureCount || 0) + 1;
      pattern.totalAttempts = (pattern.totalAttempts || 0) + 1;
      
      // Update failure characteristics
      if (!pattern.failureCharacteristics) {
        pattern.failureCharacteristics = {};
      }
      
      // Analyze what made this suggestion fail
      const characteristics = this.extractSuggestionCharacteristics(suggestion);
      Object.keys(characteristics).forEach(key => {
        if (!pattern.failureCharacteristics[key]) {
          pattern.failureCharacteristics[key] = [];
        }
        pattern.failureCharacteristics[key].push(characteristics[key]);
      });
      
      // Update confidence
      pattern.confidence = (pattern.successCount || 0) / pattern.totalAttempts;
      pattern.lastUpdated = new Date();
      
      this.patterns.set(patternKey, pattern);
      
      console.log(`Recorded failure pattern ${patternKey} (success rate: ${(pattern.confidence * 100).toFixed(1)}%)`);
      
    } catch (error) {
      console.error('Error recording failure pattern:', error);
    }
  }

  // Analyze user modifications to understand preferences
  async analyzeModification(context, originalSuggestion, modifiedText) {
    try {
      const modification = {
        context,
        originalSuggestion,
        modifiedText,
        timestamp: new Date()
      };
      
      // Analyze the differences
      const analysis = this.analyzeDifferences(originalSuggestion, modifiedText);
      modification.analysis = analysis;
      
      // Extract learning insights from modifications
      const insights = this.extractModificationInsights(analysis, context);
      
      // Update learning patterns based on insights
      await this.updatePatternsFromInsights(insights, context);
      
      // Store for future reference
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      if (!pattern.modifications) {
        pattern.modifications = [];
      }
      pattern.modifications.push(modification);
      
      // Keep only recent modifications
      if (pattern.modifications.length > 10) {
        pattern.modifications = pattern.modifications.slice(-10);
      }
      
      this.patterns.set(patternKey, pattern);
      
      console.log(`Analyzed modification for pattern ${patternKey}`);
      
    } catch (error) {
      console.error('Error analyzing modification:', error);
    }
  }

  // Process user ratings to understand quality preferences
  async processRating(context, suggestion, rating) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      if (!pattern.ratings) {
        pattern.ratings = [];
      }
      
      pattern.ratings.push({
        rating,
        suggestion,
        timestamp: new Date()
      });
      
      // Keep only recent ratings
      if (pattern.ratings.length > 20) {
        pattern.ratings = pattern.ratings.slice(-20);
      }
      
      // Calculate average rating
      pattern.averageRating = pattern.ratings.reduce((sum, r) => sum + r.rating, 0) / pattern.ratings.length;
      
      // Adjust learning based on rating
      if (rating >= 4) {
        // High rating - reinforce this pattern
        await this.reinforceSuccessfulPattern(context, suggestion);
      } else if (rating <= 2) {
        // Low rating - learn to avoid this pattern
        await this.recordFailurePattern(context, suggestion);
      }
      
      this.patterns.set(patternKey, pattern);
      
    } catch (error) {
      console.error('Error processing rating:', error);
    }
  }

  // Update confidence scores based on recent feedback
  async updateConfidenceScores(feedback) {
    try {
      const { action, context, rating } = feedback;
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey);
      
      if (!pattern) return;
      
      // Calculate confidence adjustment
      let adjustment = 0;
      
      if (action === 'accept') {
        adjustment = this.learningRate * 0.1; // Positive adjustment
      } else if (action === 'reject') {
        adjustment = -this.learningRate * 0.2; // Negative adjustment
      } else if (action === 'modify') {
        adjustment = this.learningRate * 0.05; // Small positive (user engaged)
      }
      
      // Factor in rating if available
      if (rating !== null) {
        const ratingAdjustment = ((rating - 3) / 2) * this.learningRate * 0.15;
        adjustment += ratingAdjustment;
      }
      
      // Apply adjustment
      pattern.confidence = Math.max(0, Math.min(1, pattern.confidence + adjustment));
      pattern.lastConfidenceUpdate = new Date();
      
      this.patterns.set(patternKey, pattern);
      
    } catch (error) {
      console.error('Error updating confidence scores:', error);
    }
  }

  // Generate suggestions based on learned patterns
  async generateLearningInsights(context) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey);
      
      if (!pattern || pattern.confidence < this.confidenceThreshold) {
        return this.getDefaultInsights(context);
      }
      
      const insights = {
        confidence: pattern.confidence,
        recommendations: [],
        warnings: [],
        adaptations: {},
        patternData: pattern
      };
      
      // Generate recommendations based on successful patterns
      if (pattern.successfulCharacteristics) {
        insights.recommendations = this.generateRecommendationsFromPattern(pattern.successfulCharacteristics);
      }
      
      // Generate warnings based on failure patterns
      if (pattern.failureCharacteristics) {
        insights.warnings = this.generateWarningsFromPattern(pattern.failureCharacteristics);
      }
      
      // Generate adaptations
      insights.adaptations = this.generateAdaptations(pattern, context);
      
      return insights;
      
    } catch (error) {
      console.error('Error generating learning insights:', error);
      return this.getDefaultInsights(context);
    }
  }

  // Get personalized preferences based on learning
  getPersonalizedPreferences(context) {
    try {
      const preferences = {
        tone: this.getLearnedTonePreference(context),
        structure: this.getLearnedStructurePreference(context),
        vocabulary: this.getLearnedVocabularyPreference(context),
        length: this.getLearnedLengthPreference(context),
        formality: this.getLearnedFormalityPreference(context)
      };
      
      return preferences;
      
    } catch (error) {
      console.error('Error getting personalized preferences:', error);
      return this.getDefaultPreferences();
    }
  }

  // Utility methods
  generateInteractionId() {
    return `int_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  generatePatternKey(context) {
    // Create a unique key based on context characteristics
    const keyComponents = [
      context.recipient?.relationship || 'unknown',
      context.emailType || 'general',
      context.temporal?.timeOfDay || 'unknown',
      context.thread?.threadLength > 1 ? 'thread' : 'new'
    ];
    
    return keyComponents.join('_');
  }

  createNewPattern(patternKey) {
    return {
      key: patternKey,
      successCount: 0,
      failureCount: 0,
      totalAttempts: 0,
      confidence: 0.5, // Start neutral
      createdAt: new Date(),
      lastUpdated: new Date(),
      successfulCharacteristics: {},
      failureCharacteristics: {},
      modifications: [],
      ratings: []
    };
  }

  extractSuggestionCharacteristics(suggestion) {
    if (typeof suggestion !== 'string') {
      suggestion = suggestion.text || suggestion.content || '';
    }
    
    const characteristics = {
      length: suggestion.length,
      wordCount: (suggestion.match(/\b\w+\b/g) || []).length,
      sentenceCount: (suggestion.match(/[.!?]+/g) || []).length,
      hasQuestions: suggestion.includes('?'),
      hasExclamations: suggestion.includes('!'),
      formalWords: this.countFormalWords(suggestion),
      informalWords: this.countInformalWords(suggestion),
      politeWords: this.countPoliteWords(suggestion),
      urgentWords: this.countUrgentWords(suggestion)
    };
    
    return characteristics;
  }

  countFormalWords(text) {
    const formalWords = ['furthermore', 'however', 'therefore', 'regards', 'sincerely', 'respectfully'];
    return this.countWordsInText(text, formalWords);
  }

  countInformalWords(text) {
    const informalWords = ['hey', 'yeah', 'totally', 'awesome', 'cool', 'thanks!'];
    return this.countWordsInText(text, informalWords);
  }

  countPoliteWords(text) {
    const politeWords = ['please', 'thank you', 'sorry', 'excuse me', 'would you mind'];
    return this.countWordsInText(text, politeWords);
  }

  countUrgentWords(text) {
    const urgentWords = ['urgent', 'asap', 'immediately', 'deadline', 'critical'];
    return this.countWordsInText(text, urgentWords);
  }

  countWordsInText(text, words) {
    const lowerText = text.toLowerCase();
    return words.reduce((count, word) => {
      const regex = new RegExp(`\\b${word.toLowerCase()}\\b`, 'g');
      const matches = lowerText.match(regex);
      return count + (matches ? matches.length : 0);
    }, 0);
  }

  findInteraction(suggestionId) {
    return this.feedbackHistory.find(item => 
      item.id === suggestionId || item.suggestionId === suggestionId
    );
  }

  async queueInteraction(interaction) {
    // Simple queue implementation - in production, might use Redis or similar
    if (!this.interactionQueue) {
      this.interactionQueue = [];
    }
    this.interactionQueue.push(interaction);
    
    // Process queue when not busy
    setTimeout(() => {
      if (!this.isProcessing && this.interactionQueue.length > 0) {
        const queued = this.interactionQueue.shift();
        this.recordInteraction(queued);
      }
    }, 100);
  }

  async processInteractionAsync(interaction) {
    // Process interaction in background to avoid blocking
    setTimeout(async () => {
      try {
        this.isProcessing = true;
        
        // Analyze interaction patterns
        await this.analyzeInteractionPatterns(interaction);
        
        // Update learning data
        await this.updateLearningData(interaction);
        
        interaction.processed = true;
        
      } catch (error) {
        console.error('Error processing interaction async:', error);
      } finally {
        this.isProcessing = false;
      }
    }, 0);
  }

  async analyzeInteractionPatterns(interaction) {
    try {
      const context = interaction.context;
      if (!context) return;
      
      // Track context patterns
      const contextKey = this.generatePatternKey(context);
      
      // Update interaction frequency for this context
      const contextPattern = this.patterns.get(contextKey) || this.createNewPattern(contextKey);
      contextPattern.interactionCount = (contextPattern.interactionCount || 0) + 1;
      contextPattern.lastInteraction = new Date();
      
      this.patterns.set(contextKey, contextPattern);
      
    } catch (error) {
      console.error('Error analyzing interaction patterns:', error);
    }
  }

  async updateLearningData(interaction) {
    try {
      const learningKey = `${this.userId}_learning_data`;
      
      // Update learning statistics
      const currentData = this.learningData.get(learningKey) || {
        totalInteractions: 0,
        lastUpdated: new Date(),
        patternCount: 0
      };
      
      currentData.totalInteractions += 1;
      currentData.lastUpdated = new Date();
      currentData.patternCount = this.patterns.size;
      
      this.learningData.set(learningKey, currentData);
      
    } catch (error) {
      console.error('Error updating learning data:', error);
    }
  }
}
// Advanced learning algorithms and trend analysis
  analyzeDifferences(originalText, modifiedText) {
    try {
      const analysis = {
        lengthChange: modifiedText.length - originalText.length,
        wordCountChange: this.getWordCount(modifiedText) - this.getWordCount(originalText),
        toneChanges: this.analyzeToneChanges(originalText, modifiedText),
        structureChanges: this.analyzeStructureChanges(originalText, modifiedText),
        vocabularyChanges: this.analyzeVocabularyChanges(originalText, modifiedText),
        addedPhrases: this.findAddedPhrases(originalText, modifiedText),
        removedPhrases: this.findRemovedPhrases(originalText, modifiedText)
      };
      
      return analysis;
      
    } catch (error) {
      console.error('Error analyzing differences:', error);
      return {};
    }
  }

  analyzeToneChanges(original, modified) {
    const originalTone = this.analyzeTone(original);
    const modifiedTone = this.analyzeTone(modified);
    
    return {
      formalityChange: modifiedTone.formality - originalTone.formality,
      politenessChange: modifiedTone.politeness - originalTone.politeness,
      warmthChange: modifiedTone.warmth - originalTone.warmth,
      directnessChange: modifiedTone.directness - originalTone.directness
    };
  }

  analyzeStructureChanges(original, modified) {
    return {
      paragraphCountChange: this.getParagraphCount(modified) - this.getParagraphCount(original),
      sentenceCountChange: this.getSentenceCount(modified) - this.getSentenceCount(original),
      addedLists: this.hasLists(modified) && !this.hasLists(original),
      removedLists: !this.hasLists(modified) && this.hasLists(original),
      addedQuestions: this.getQuestionCount(modified) - this.getQuestionCount(original)
    };
  }

  analyzeVocabularyChanges(original, modified) {
    const originalWords = new Set(this.getWords(original));
    const modifiedWords = new Set(this.getWords(modified));
    
    const addedWords = [...modifiedWords].filter(word => !originalWords.has(word));
    const removedWords = [...originalWords].filter(word => !modifiedWords.has(word));
    
    return {
      addedWords,
      removedWords,
      complexityChange: this.getComplexityScore(modified) - this.getComplexityScore(original),
      formalWordsAdded: addedWords.filter(word => this.isFormalWord(word)).length,
      informalWordsAdded: addedWords.filter(word => this.isInformalWord(word)).length
    };
  }

  extractModificationInsights(analysis, context) {
    const insights = {
      preferredLength: null,
      preferredTone: {},
      preferredStructure: {},
      preferredVocabulary: {},
      confidence: 0.7
    };
    
    // Analyze length preferences
    if (Math.abs(analysis.lengthChange) > 20) {
      insights.preferredLength = analysis.lengthChange > 0 ? 'longer' : 'shorter';
    }
    
    // Analyze tone preferences
    if (analysis.toneChanges) {
      if (Math.abs(analysis.toneChanges.formalityChange) > 0.2) {
        insights.preferredTone.formality = analysis.toneChanges.formalityChange > 0 ? 'more_formal' : 'less_formal';
      }
      if (Math.abs(analysis.toneChanges.politenessChange) > 0.2) {
        insights.preferredTone.politeness = analysis.toneChanges.politenessChange > 0 ? 'more_polite' : 'less_polite';
      }
      if (Math.abs(analysis.toneChanges.warmthChange) > 0.2) {
        insights.preferredTone.warmth = analysis.toneChanges.warmthChange > 0 ? 'warmer' : 'cooler';
      }
    }
    
    // Analyze structure preferences
    if (analysis.structureChanges) {
      if (analysis.structureChanges.addedLists) {
        insights.preferredStructure.useLists = true;
      }
      if (analysis.structureChanges.addedQuestions > 0) {
        insights.preferredStructure.useQuestions = true;
      }
    }
    
    // Analyze vocabulary preferences
    if (analysis.vocabularyChanges) {
      if (analysis.vocabularyChanges.formalWordsAdded > analysis.vocabularyChanges.informalWordsAdded) {
        insights.preferredVocabulary.style = 'formal';
      } else if (analysis.vocabularyChanges.informalWordsAdded > analysis.vocabularyChanges.formalWordsAdded) {
        insights.preferredVocabulary.style = 'informal';
      }
    }
    
    return insights;
  }

  async updatePatternsFromInsights(insights, context) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      // Update pattern with insights
      if (!pattern.learnedPreferences) {
        pattern.learnedPreferences = {};
      }
      
      // Merge new insights with existing preferences
      if (insights.preferredLength) {
        pattern.learnedPreferences.length = insights.preferredLength;
      }
      
      if (Object.keys(insights.preferredTone).length > 0) {
        pattern.learnedPreferences.tone = {
          ...pattern.learnedPreferences.tone,
          ...insights.preferredTone
        };
      }
      
      if (Object.keys(insights.preferredStructure).length > 0) {
        pattern.learnedPreferences.structure = {
          ...pattern.learnedPreferences.structure,
          ...insights.preferredStructure
        };
      }
      
      if (Object.keys(insights.preferredVocabulary).length > 0) {
        pattern.learnedPreferences.vocabulary = {
          ...pattern.learnedPreferences.vocabulary,
          ...insights.preferredVocabulary
        };
      }
      
      pattern.lastLearningUpdate = new Date();
      this.patterns.set(patternKey, pattern);
      
    } catch (error) {
      console.error('Error updating patterns from insights:', error);
    }
  }

  generateRecommendationsFromPattern(successCharacteristics) {
    const recommendations = [];
    
    // Analyze successful characteristics
    Object.keys(successCharacteristics).forEach(characteristic => {
      const values = successCharacteristics[characteristic];
      if (values.length === 0) return;
      
      switch (characteristic) {
        case 'length':
          const avgLength = values.reduce((a, b) => a + b, 0) / values.length;
          if (avgLength > 200) {
            recommendations.push('Use detailed explanations - your longer emails tend to be well-received');
          } else if (avgLength < 100) {
            recommendations.push('Keep it concise - your brief emails get better responses');
          }
          break;
          
        case 'formalWords':
          const avgFormal = values.reduce((a, b) => a + b, 0) / values.length;
          if (avgFormal > 2) {
            recommendations.push('Maintain formal language - it works well in this context');
          }
          break;
          
        case 'politeWords':
          const avgPolite = values.reduce((a, b) => a + b, 0) / values.length;
          if (avgPolite > 1) {
            recommendations.push('Continue using courteous language - it improves acceptance');
          }
          break;
          
        case 'hasQuestions':
          if (values.filter(v => v).length > values.length * 0.7) {
            recommendations.push('Including questions encourages engagement');
          }
          break;
      }
    });
    
    return recommendations;
  }

  generateWarningsFromPattern(failureCharacteristics) {
    const warnings = [];
    
    Object.keys(failureCharacteristics).forEach(characteristic => {
      const values = failureCharacteristics[characteristic];
      if (values.length === 0) return;
      
      switch (characteristic) {
        case 'urgentWords':
          const avgUrgent = values.reduce((a, b) => a + b, 0) / values.length;
          if (avgUrgent > 1) {
            warnings.push('Avoid overusing urgent language in this context');
          }
          break;
          
        case 'length':
          const avgLength = values.reduce((a, b) => a + b, 0) / values.length;
          if (avgLength > 300) {
            warnings.push('Very long emails may not be well-received here');
          } else if (avgLength < 50) {
            warnings.push('Very brief emails might seem abrupt in this context');
          }
          break;
          
        case 'informalWords':
          const avgInformal = values.reduce((a, b) => a + b, 0) / values.length;
          if (avgInformal > 2) {
            warnings.push('Overly casual language may not be appropriate here');
          }
          break;
      }
    });
    
    return warnings;
  }

  generateAdaptations(pattern, context) {
    const adaptations = {};
    
    if (pattern.learnedPreferences) {
      const prefs = pattern.learnedPreferences;
      
      // Length adaptations
      if (prefs.length === 'longer') {
        adaptations.targetLength = 'expand_content';
      } else if (prefs.length === 'shorter') {
        adaptations.targetLength = 'condense_content';
      }
      
      // Tone adaptations
      if (prefs.tone) {
        if (prefs.tone.formality === 'more_formal') {
          adaptations.toneAdjustment = 'increase_formality';
        } else if (prefs.tone.formality === 'less_formal') {
          adaptations.toneAdjustment = 'decrease_formality';
        }
        
        if (prefs.tone.warmth === 'warmer') {
          adaptations.warmthAdjustment = 'add_warmth';
        } else if (prefs.tone.warmth === 'cooler') {
          adaptations.warmthAdjustment = 'reduce_warmth';
        }
      }
      
      // Structure adaptations
      if (prefs.structure) {
        if (prefs.structure.useLists) {
          adaptations.structureHint = 'consider_bullet_points';
        }
        if (prefs.structure.useQuestions) {
          adaptations.engagementHint = 'include_questions';
        }
      }
    }
    
    return adaptations;
  }

  // Continuous learning and adaptation methods
  async evolveLearningPatterns() {
    try {
      console.log('Evolving learning patterns...');
      
      // Analyze pattern evolution over time
      for (const [patternKey, pattern] of this.patterns.entries()) {
        if (this.shouldEvolvePattern(pattern)) {
          await this.evolvePattern(pattern);
        }
      }
      
      // Consolidate similar patterns
      await this.consolidateSimilarPatterns();
      
      // Remove outdated patterns
      await this.cleanupOutdatedPatterns();
      
      console.log('Pattern evolution completed');
      
    } catch (error) {
      console.error('Error evolving learning patterns:', error);
    }
  }

  shouldEvolvePattern(pattern) {
    const daysSinceUpdate = (Date.now() - pattern.lastUpdated.getTime()) / (1000 * 60 * 60 * 24);
    const hasEnoughData = pattern.totalAttempts >= 10;
    const needsEvolution = daysSinceUpdate > 7; // Evolve weekly
    
    return hasEnoughData && needsEvolution;
  }

  async evolvePattern(pattern) {
    try {
      // Analyze trend in success rate
      const recentFeedback = this.getRecentFeedbackForPattern(pattern, 30); // Last 30 days
      const recentSuccessRate = this.calculateSuccessRate(recentFeedback);
      
      // Compare with overall success rate
      const overallSuccessRate = pattern.confidence;
      const trend = recentSuccessRate - overallSuccessRate;
      
      // Adjust confidence based on trend
      if (Math.abs(trend) > 0.1) {
        const adjustment = trend * 0.5; // Moderate adjustment
        pattern.confidence = Math.max(0, Math.min(1, pattern.confidence + adjustment));
        
        console.log(`Evolved pattern ${pattern.key}: confidence ${overallSuccessRate.toFixed(2)} → ${pattern.confidence.toFixed(2)}`);
      }
      
      // Update evolution timestamp
      pattern.lastEvolution = new Date();
      
    } catch (error) {
      console.error('Error evolving pattern:', error);
    }
  }

  async consolidateSimilarPatterns() {
    try {
      const patternArray = Array.from(this.patterns.values());
      const consolidations = [];
      
      // Find similar patterns
      for (let i = 0; i < patternArray.length; i++) {
        for (let j = i + 1; j < patternArray.length; j++) {
          const similarity = this.calculatePatternSimilarity(patternArray[i], patternArray[j]);
          
          if (similarity > 0.8 && this.shouldConsolidate(patternArray[i], patternArray[j])) {
            consolidations.push({
              pattern1: patternArray[i],
              pattern2: patternArray[j],
              similarity
            });
          }
        }
      }
      
      // Perform consolidations
      for (const consolidation of consolidations) {
        await this.mergePatterns(consolidation.pattern1, consolidation.pattern2);
      }
      
      if (consolidations.length > 0) {
        console.log(`Consolidated ${consolidations.length} similar patterns`);
      }
      
    } catch (error) {
      console.error('Error consolidating patterns:', error);
    }
  }

  calculatePatternSimilarity(pattern1, pattern2) {
    // Simple similarity calculation based on context overlap
    const context1 = pattern1.key.split('_');
    const context2 = pattern2.key.split('_');
    
    let matches = 0;
    const maxLength = Math.max(context1.length, context2.length);
    
    for (let i = 0; i < Math.min(context1.length, context2.length); i++) {
      if (context1[i] === context2[i]) {
        matches++;
      }
    }
    
    return matches / maxLength;
  }

  shouldConsolidate(pattern1, pattern2) {
    // Don't consolidate if one pattern has significantly more data
    const dataRatio = Math.max(pattern1.totalAttempts, pattern2.totalAttempts) / 
                     Math.min(pattern1.totalAttempts, pattern2.totalAttempts);
    
    return dataRatio < 3; // Only consolidate if data amounts are similar
  }

  async mergePatterns(pattern1, pattern2) {
    try {
      // Keep the pattern with more data as primary
      const primary = pattern1.totalAttempts >= pattern2.totalAttempts ? pattern1 : pattern2;
      const secondary = pattern1.totalAttempts >= pattern2.totalAttempts ? pattern2 : pattern1;
      
      // Merge data
      primary.successCount += secondary.successCount;
      primary.failureCount += secondary.failureCount;
      primary.totalAttempts += secondary.totalAttempts;
      primary.confidence = primary.successCount / primary.totalAttempts;
      
      // Merge characteristics
      this.mergeCharacteristics(primary.successfulCharacteristics, secondary.successfulCharacteristics);
      this.mergeCharacteristics(primary.failureCharacteristics, secondary.failureCharacteristics);
      
      // Merge other data
      if (secondary.modifications) {
        primary.modifications = (primary.modifications || []).concat(secondary.modifications);
      }
      
      if (secondary.ratings) {
        primary.ratings = (primary.ratings || []).concat(secondary.ratings);
        primary.averageRating = primary.ratings.reduce((sum, r) => sum + r.rating, 0) / primary.ratings.length;
      }
      
      // Remove secondary pattern
      this.patterns.delete(secondary.key);
      
      // Update primary pattern
      primary.lastMerge = new Date();
      this.patterns.set(primary.key, primary);
      
    } catch (error) {
      console.error('Error merging patterns:', error);
    }
  }

  mergeCharacteristics(primary, secondary) {
    Object.keys(secondary).forEach(key => {
      if (!primary[key]) {
        primary[key] = [];
      }
      primary[key] = primary[key].concat(secondary[key]);
      
      // Keep only recent values
      if (primary[key].length > 50) {
        primary[key] = primary[key].slice(-50);
      }
    });
  }

  async cleanupOutdatedPatterns() {
    try {
      const cutoffDate = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days ago
      const patternsToRemove = [];
      
      for (const [key, pattern] of this.patterns.entries()) {
        if (pattern.lastUpdated < cutoffDate && pattern.totalAttempts < 5) {
          patternsToRemove.push(key);
        }
      }
      
      patternsToRemove.forEach(key => {
        this.patterns.delete(key);
      });
      
      if (patternsToRemove.length > 0) {
        console.log(`Cleaned up ${patternsToRemove.length} outdated patterns`);
      }
      
    } catch (error) {
      console.error('Error cleaning up patterns:', error);
    }
  }

  // Data persistence methods
  async loadLearningData() {
    try {
      const response = await fetch(`/api/users/${this.userId}/learning-data`, {
        headers: {
          'Authorization': `Bearer ${await this.getAuthToken()}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        this.learningData = new Map(Object.entries(data.learningData || {}));
        console.log('Learning data loaded successfully');
      }
      
    } catch (error) {
      console.warn('Could not load learning data:', error);
      // Continue with empty learning data
    }
  }

  async loadFeedbackHistory() {
    try {
      const response = await fetch(`/api/users/${this.userId}/feedback-history`, {
        headers: {
          'Authorization': `Bearer ${await this.getAuthToken()}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        this.feedbackHistory = data.feedbackHistory || [];
        console.log(`Loaded ${this.feedbackHistory.length} feedback items`);
      }
      
    } catch (error) {
      console.warn('Could not load feedback history:', error);
      // Continue with empty history
    }
  }

  async initializePatterns() {
    try {
      const response = await fetch(`/api/users/${this.userId}/learning-patterns`, {
        headers: {
          'Authorization': `Bearer ${await this.getAuthToken()}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        this.patterns = new Map();
        
        if (data.patterns) {
          Object.entries(data.patterns).forEach(([key, pattern]) => {
            // Convert date strings back to Date objects
            pattern.createdAt = new Date(pattern.createdAt);
            pattern.lastUpdated = new Date(pattern.lastUpdated);
            if (pattern.lastEvolution) pattern.lastEvolution = new Date(pattern.lastEvolution);
            
            this.patterns.set(key, pattern);
          });
        }
        
        console.log(`Loaded ${this.patterns.size} learning patterns`);
      }
      
    } catch (error) {
      console.warn('Could not load learning patterns:', error);
      // Continue with empty patterns
    }
  }

  async calculateAdaptations() {
    try {
      // Calculate initial adaptations based on loaded patterns
      for (const [key, pattern] of this.patterns.entries()) {
        if (pattern.confidence > this.confidenceThreshold) {
          const context = this.parsePatternKey(key);
          const adaptations = this.generateAdaptations(pattern, context);
          this.adaptations.set(key, adaptations);
        }
      }
      
      console.log(`Calculated ${this.adaptations.size} adaptations`);
      
    } catch (error) {
      console.error('Error calculating adaptations:', error);
    }
  }

  async saveLearningData() {
    try {
      const dataToSave = {
        learningData: Object.fromEntries(this.learningData),
        patterns: Object.fromEntries(this.patterns),
        feedbackHistory: this.feedbackHistory.slice(-this.maxFeedbackHistory), // Only save recent feedback
        lastSaved: new Date()
      };
      
      const response = await fetch(`/api/users/${this.userId}/learning-data`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${await this.getAuthToken()}`
        },
        body: JSON.stringify(dataToSave)
      });
      
      if (response.ok) {
        console.log('Learning data saved successfully');
        return true;
      } else {
        console.error('Failed to save learning data:', response.statusText);
        return false;
      }
      
    } catch (error) {
      console.error('Error saving learning data:', error);
      return false;
    }
  }

  // Utility methods for Part 2
  getRecentFeedbackForPattern(pattern, days) {
    const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    return this.feedbackHistory.filter(feedback => 
      feedback.timestamp > cutoffDate && 
      this.generatePatternKey(feedback.context) === pattern.key
    );
  }

  calculateSuccessRate(feedbackList) {
    if (feedbackList.length === 0) return 0.5;
    
    const successes = feedbackList.filter(f => f.action === 'accept' || (f.rating && f.rating >= 4)).length;
    return successes / feedbackList.length;
  }

  parsePatternKey(key) {
    const parts = key.split('_');
    return {
      recipient: { relationship: parts[0] },
      emailType: parts[1],
      temporal: { timeOfDay: parts[2] },
      thread: { threadLength: parts[3] === 'thread' ? 2 : 1 }
    };
  }

  // Learned preference methods
  getLearnedTonePreference(context) {
    const patternKey = this.generatePatternKey(context);
    const pattern = this.patterns.get(patternKey);
    
    if (pattern?.learnedPreferences?.tone) {
      return pattern.learnedPreferences.tone;
    }
    
    return this.getDefaultTone(context);
  }

  getLearnedStructurePreference(context) {
    const patternKey = this.generatePatternKey(context);
    const pattern = this.patterns.get(patternKey);
    
    if (pattern?.learnedPreferences?.structure) {
      return pattern.learnedPreferences.structure;
    }
    
    return this.getDefaultStructure(context);
  }

  getLearnedVocabularyPreference(context) {
    const patternKey = this.generatePatternKey(context);
    const pattern = this.patterns.get(patternKey);
    
    if (pattern?.learnedPreferences?.vocabulary) {
      return pattern.learnedPreferences.vocabulary;
    }
    
    return this.getDefaultVocabulary(context);
  }

  getLearnedLengthPreference(context) {
    const patternKey = this.generatePatternKey(context);
    const pattern = this.patterns.get(patternKey);
    
    if (pattern?.learnedPreferences?.length) {
      return pattern.learnedPreferences.length;
    }
    
    return 'medium';
  }

  getLearnedFormalityPreference(context) {
    const patternKey = this.generatePatternKey(context);
    const pattern = this.patterns.get(patternKey);
    
    if (pattern?.learnedPreferences?.tone?.formality) {
      return pattern.learnedPreferences.tone.formality;
    }
    
    return this.getDefaultFormality(context);
  }

  // Helper methods for tone analysis
  analyzeTone(text) {
    return {
      formality: this.calculateFormality(text),
      politeness: this.calculatePoliteness(text),
      warmth: this.calculateWarmth(text),
      directness: this.calculateDirectness(text)
    };
  }

  calculateFormality(text) {
    const formalWords = this.countFormalWords(text);
    const informalWords = this.countInformalWords(text);
    const totalWords = this.getWordCount(text);
    
    if (totalWords === 0) return 0.5;
    
    const formalRatio = formalWords / totalWords;
    const informalRatio = informalWords / totalWords;
    
    return Math.max(0, Math.min(1, 0.5 + (formalRatio - informalRatio) * 2));
  }

  calculatePoliteness(text) {
    const politeWords = this.countPoliteWords(text);
    const totalWords = this.getWordCount(text);
    
    if (totalWords === 0) return 0.5;
    
    return Math.min(1, politeWords / totalWords * 10);
  }

  calculateWarmth(text) {
    const warmWords = ['appreciate', 'thank', 'grateful', 'pleased', 'happy', 'excited', 'wonderful'];
    const warmCount = this.countWordsInText(text, warmWords);
    const totalWords = this.getWordCount(text);
    
    if (totalWords === 0) return 0.5;
    
    return Math.min(1, warmCount / totalWords * 20);
  }

  calculateDirectness(text) {
    const sentences = this.getSentenceCount(text);
    const words = this.getWordCount(text);
    
    if (sentences === 0) return 0.5;
    
    const avgSentenceLength = words / sentences;
    return Math.max(0, Math.min(1, 1 - (avgSentenceLength - 10) / 20));
  }

  // Text analysis helper methods
  getWordCount(text) {
    return (text.match(/\b\w+\b/g) || []).length;
  }

  getSentenceCount(text) {
    return (text.match(/[.!?]+/g) || []).length;
  }

  getParagraphCount(text) {
    return text.split(/\n\s*\n/).filter(p => p.trim().length > 0).length;
  }

  hasLists(text) {
    return /^[\s]*[-•*]\s+/m.test(text) || /^\d+\.\s+/m.test(text);
  }

  getQuestionCount(text) {
    return (text.match(/\?/g) || []).length;
  }

  getWords(text) {
    return (text.match(/\b\w+\b/g) || []).map(word => word.toLowerCase());
  }

  getComplexityScore(text) {
    const words = this.getWords(text);
    const complexWords = words.filter(word => word.length > 6);
    return words.length > 0 ? complexWords.length / words.length : 0;
  }

  isFormalWord(word) {
    const formalWords = ['furthermore', 'however', 'therefore', 'accordingly', 'consequently', 'nevertheless'];
    return formalWords.includes(word.toLowerCase());
  }

  isInformalWord(word) {
    const informalWords = ['hey', 'yeah', 'totally', 'awesome', 'cool', 'gonna', 'wanna'];
    return informalWords.includes(word.toLowerCase());
  }

  findAddedPhrases(original, modified) {
    // Simple implementation - could be more sophisticated
    const originalWords = new Set(this.getWords(original));
    const modifiedWords = this.getWords(modified);
    
    const addedWords = modifiedWords.filter(word => !originalWords.has(word));
    return this.extractPhrases(addedWords.join(' '));
  }

  findRemovedPhrases(original, modified) {
    const modifiedWords = new Set(this.getWords(modified));
    const originalWords = this.getWords(original);
    
    const removedWords = originalWords.filter(word => !modifiedWords.has(word));
    return this.extractPhrases(removedWords.join(' '));
  }

  extractPhrases(text) {
    // Simple phrase extraction - split by common delimiters
    return text.split(/[,;.]/).map(phrase => phrase.trim()).filter(phrase => phrase.length > 5);
  }

  // Default preference methods
  getDefaultTone(context) {
    if (context.recipient?.relationship === 'executive') {
      return { formality: 'more_formal', politeness: 'more_polite' };
    } else if (context.recipient?.relationship === 'colleague') {
      return { formality: 'neutral', politeness: 'polite' };
    }
    return { formality: 'neutral', politeness: 'polite' };
  }

  getDefaultStructure(context) {
    if (context.emailType === 'meeting_request') {
      return { useLists: true, useQuestions: false };
    }
    return { useLists: false, useQuestions: false };
  }

  getDefaultVocabulary(context) {
    if (context.recipient?.relationship === 'external') {
      return { style: 'formal' };
    }
    return { style: 'neutral' };
  }

  getDefaultFormality(context) {
    if (context.recipient?.relationship === 'executive') {
      return 'formal';
    } else if (context.recipient?.relationship === 'colleague') {
      return 'moderate';
    }
    return 'moderate';
  }

  getDefaultInsights(context) {
    return {
      confidence: 0.// src/core/LearningEngine.js
class LearningEngine {
  constructor(userId) {
    this.userId = userId;
    this.learningData = new Map();
    this.feedbackHistory = [];
    this.patterns = new Map();
    this.adaptations = new Map();
    this.isProcessing = false;
    this.learningRate = 0.1; // How quickly to adapt (0.0 to 1.0)
    this.confidenceThreshold = 0.7; // Minimum confidence for suggestions
    this.maxFeedbackHistory = 1000; // Maximum feedback items to keep in memory
  }

  // Initialize learning engine with user's historical data
  async initialize() {
    try {
      console.log(`Initializing LearningEngine for user ${this.userId}`);
      
      // Load existing learning data
      await this.loadLearningData();
      
      // Load feedback history
      await this.loadFeedbackHistory();
      
      // Initialize pattern recognition
      await this.initializePatterns();
      
      // Calculate initial adaptations
      await this.calculateAdaptations();
      
      console.log('LearningEngine initialized successfully');
      return true;
      
    } catch (error) {
      console.error('Error initializing LearningEngine:', error);
      throw error;
    }
  }

  // Record user interaction with AI suggestion
  async recordInteraction(interaction) {
    try {
      if (this.isProcessing) {
        console.warn('LearningEngine is busy processing, queuing interaction');
        return this.queueInteraction(interaction);
      }

      const enrichedInteraction = {
        ...interaction,
        id: this.generateInteractionId(),
        timestamp: new Date(),
        userId: this.userId,
        processed: false
      };

      // Store interaction
      this.feedbackHistory.push(enrichedInteraction);
      
      // Maintain history size limit
      if (this.feedbackHistory.length > this.maxFeedbackHistory) {
        this.feedbackHistory.shift();
      }

      // Process interaction asynchronously
      this.processInteractionAsync(enrichedInteraction);
      
      return enrichedInteraction.id;
      
    } catch (error) {
      console.error('Error recording interaction:', error);
      throw error;
    }
  }

  // Record user feedback on AI suggestion
  async recordUserFeedback(suggestionId, action, modifiedText = null, rating = null) {
    try {
      const feedback = {
        suggestionId,
        userId: this.userId,
        action, // 'accept', 'modify', 'reject'
        modifiedText,
        rating, // 1-5 scale
        timestamp: new Date(),
        processed: false
      };

      // Find the original interaction
      const originalInteraction = this.findInteraction(suggestionId);
      if (originalInteraction) {
        feedback.context = originalInteraction.context;
        feedback.suggestion = originalInteraction.suggestion;
      }

      // Store feedback
      this.feedbackHistory.push(feedback);
      
      // Process feedback for learning
      await this.processFeedback(feedback);
      
      // Update learning patterns
      await this.updateLearningPatterns(feedback);
      
      return feedback;
      
    } catch (error) {
      console.error('Error recording user feedback:', error);
      throw error;
    }
  }

  // Process feedback to extract learning insights
  async processFeedback(feedback) {
    try {
      const { action, context, suggestion, modifiedText, rating } = feedback;
      
      // Analyze acceptance patterns
      if (action === 'accept') {
        await this.reinforceSuccessfulPattern(context, suggestion);
      } else if (action === 'reject') {
        await this.recordFailurePattern(context, suggestion);
      } else if (action === 'modify' && modifiedText) {
        await this.analyzeModification(context, suggestion, modifiedText);
      }

      // Process rating if provided
      if (rating !== null) {
        await this.processRating(context, suggestion, rating);
      }

      // Update confidence scores
      await this.updateConfidenceScores(feedback);
      
      feedback.processed = true;
      
    } catch (error) {
      console.error('Error processing feedback:', error);
    }
  }

  // Reinforce patterns that led to successful suggestions
  async reinforceSuccessfulPattern(context, suggestion) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      // Increase success count
      pattern.successCount = (pattern.successCount || 0) + 1;
      pattern.totalAttempts = (pattern.totalAttempts || 0) + 1;
      
      // Update success characteristics
      if (!pattern.successfulCharacteristics) {
        pattern.successfulCharacteristics = {};
      }
      
      // Analyze what made this suggestion successful
      const characteristics = this.extractSuggestionCharacteristics(suggestion);
      Object.keys(characteristics).forEach(key => {
        if (!pattern.successfulCharacteristics[key]) {
          pattern.successfulCharacteristics[key] = [];
        }
        pattern.successfulCharacteristics[key].push(characteristics[key]);
      });
      
      // Update confidence
      pattern.confidence = pattern.successCount / pattern.totalAttempts;
      pattern.lastUpdated = new Date();
      
      this.patterns.set(patternKey, pattern);
      
      console.log(`Reinforced pattern ${patternKey} (success rate: ${(pattern.confidence * 100).toFixed(1)}%)`);
      
    } catch (error) {
      console.error('Error reinforcing successful pattern:', error);
    }
  }

  // Record patterns that led to unsuccessful suggestions
  async recordFailurePattern(context, suggestion) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      // Increase failure count
      pattern.failureCount = (pattern.failureCount || 0) + 1;
      pattern.totalAttempts = (pattern.totalAttempts || 0) + 1;
      
      // Update failure characteristics
      if (!pattern.failureCharacteristics) {
        pattern.failureCharacteristics = {};
      }
      
      // Analyze what made this suggestion fail
      const characteristics = this.extractSuggestionCharacteristics(suggestion);
      Object.keys(characteristics).forEach(key => {
        if (!pattern.failureCharacteristics[key]) {
          pattern.failureCharacteristics[key] = [];
        }
        pattern.failureCharacteristics[key].push(characteristics[key]);
      });
      
      // Update confidence
      pattern.confidence = (pattern.successCount || 0) / pattern.totalAttempts;
      pattern.lastUpdated = new Date();
      
      this.patterns.set(patternKey, pattern);
      
      console.log(`Recorded failure pattern ${patternKey} (success rate: ${(pattern.confidence * 100).toFixed(1)}%)`);
      
    } catch (error) {
      console.error('Error recording failure pattern:', error);
    }
  }

  // Analyze user modifications to understand preferences
  async analyzeModification(context, originalSuggestion, modifiedText) {
    try {
      const modification = {
        context,
        originalSuggestion,
        modifiedText,
        timestamp: new Date()
      };
      
      // Analyze the differences
      const analysis = this.analyzeDifferences(originalSuggestion, modifiedText);
      modification.analysis = analysis;
      
      // Extract learning insights from modifications
      const insights = this.extractModificationInsights(analysis, context);
      
      // Update learning patterns based on insights
      await this.updatePatternsFromInsights(insights, context);
      
      // Store for future reference
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      if (!pattern.modifications) {
        pattern.modifications = [];
      }
      pattern.modifications.push(modification);
      
      // Keep only recent modifications
      if (pattern.modifications.length > 10) {
        pattern.modifications = pattern.modifications.slice(-10);
      }
      
      this.patterns.set(patternKey, pattern);
      
      console.log(`Analyzed modification for pattern ${patternKey}`);
      
    } catch (error) {
      console.error('Error analyzing modification:', error);
    }
  }

  // Process user ratings to understand quality preferences
  async processRating(context, suggestion, rating) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey) || this.createNewPattern(patternKey);
      
      if (!pattern.ratings) {
        pattern.ratings = [];
      }
      
      pattern.ratings.push({
        rating,
        suggestion,
        timestamp: new Date()
      });
      
      // Keep only recent ratings
      if (pattern.ratings.length > 20) {
        pattern.ratings = pattern.ratings.slice(-20);
      }
      
      // Calculate average rating
      pattern.averageRating = pattern.ratings.reduce((sum, r) => sum + r.rating, 0) / pattern.ratings.length;
      
      // Adjust learning based on rating
      if (rating >= 4) {
        // High rating - reinforce this pattern
        await this.reinforceSuccessfulPattern(context, suggestion);
      } else if (rating <= 2) {
        // Low rating - learn to avoid this pattern
        await this.recordFailurePattern(context, suggestion);
      }
      
      this.patterns.set(patternKey, pattern);
      
    } catch (error) {
      console.error('Error processing rating:', error);
    }
  }

  // Update confidence scores based on recent feedback
  async updateConfidenceScores(feedback) {
    try {
      const { action, context, rating } = feedback;
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey);
      
      if (!pattern) return;
      
      // Calculate confidence adjustment
      let adjustment = 0;
      
      if (action === 'accept') {
        adjustment = this.learningRate * 0.1; // Positive adjustment
      } else if (action === 'reject') {
        adjustment = -this.learningRate * 0.2; // Negative adjustment
      } else if (action === 'modify') {
        adjustment = this.learningRate * 0.05; // Small positive (user engaged)
      }
      
      // Factor in rating if available
      if (rating !== null) {
        const ratingAdjustment = ((rating - 3) / 2) * this.learningRate * 0.15;
        adjustment += ratingAdjustment;
      }
      
      // Apply adjustment
      pattern.confidence = Math.max(0, Math.min(1, pattern.confidence + adjustment));
      pattern.lastConfidenceUpdate = new Date();
      
      this.patterns.set(patternKey, pattern);
      
    } catch (error) {
      console.error('Error updating confidence scores:', error);
    }
  }

  // Generate suggestions based on learned patterns
  async generateLearningInsights(context) {
    try {
      const patternKey = this.generatePatternKey(context);
      const pattern = this.patterns.get(patternKey);
      
      if (!pattern || pattern.confidence < this.confidenceThreshold) {
        return this.getDefaultInsights(context);
      }
      
      const insights = {
        confidence: pattern.confidence,
        recommendations: [],
        warnings: [],
        adaptations: {},
        patternData: pattern
      };
      
      // Generate recommendations based on successful patterns
      if (pattern.successfulCharacteristics) {
        insights.recommendations = this.generateRecommendationsFromPattern(pattern.successfulCharacteristics);
      }
      
      // Generate warnings based on failure patterns
      if (pattern.failureCharacteristics) {
        insights.warnings = this.generateWarningsFromPattern(pattern.failureCharacteristics);
      }
      
      // Generate adaptations
      insights.adaptations = this.generateAdaptations(pattern, context);
      
      return insights;
      
    } catch (error) {
      console.error('Error generating learning insights:', error);
      return this.getDefaultInsights(context);
    }
  }

  // Get personalized preferences based on learning
  getPersonalizedPreferences(context) {
    try {
      const preferences = {
        tone: this.getLearnedTonePreference(context),
        structure: this.getLearnedStructurePreference(context),
        vocabulary: this.getLearnedVocabularyPreference(context),
        length: this.getLearnedLengthPreference(context),
        formality: this.getLearnedFormalityPreference(context)
      };
      
      return preferences;
      
    } catch (error) {
      console.error('Error getting personalized preferences:', error);
      return this.getDefaultPreferences();
    }
  }

  // Utility methods
  generateInteractionId() {
    return `int_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  generatePatternKey(context) {
    // Create a unique key based on context characteristics
    const keyComponents = [
      context.recipient?.relationship || 'unknown',
      context.emailType || 'general',
      context.temporal?.timeOfDay || 'unknown',
      context.thread?.threadLength > 1 ? 'thread' : 'new'
    ];
    
    return keyComponents.join('_');
  }

  createNewPattern(patternKey) {
    return {
      key: patternKey,
      successCount: 0,
      failureCount: 0,
      totalAttempts: 0,
      confidence: 0.5, // Start neutral
      createdAt: new Date(),
      lastUpdated: new Date(),
      successfulCharacteristics: {},
      failureCharacteristics: {},
      modifications: [],
      ratings: []
    };
  }

  extractSuggestionCharacteristics(suggestion) {
    if (typeof suggestion !== 'string') {
      suggestion = suggestion.text || suggestion.content || '';
    }
    
    const characteristics = {
      length: suggestion.length,
      wordCount: (suggestion.match(/\b\w+\b/g) || []).length,
      sentenceCount: (suggestion.match(/[.!?]+/g) || []).length,
      hasQuestions: suggestion.includes('?'),
      hasExclamations: suggestion.includes('!'),
      formalWords: this.countFormalWords(suggestion),
      informalWords: this.countInformalWords(suggestion),
      politeWords: this.countPoliteWords(suggestion),
      urgentWords: this.countUrgentWords(suggestion)
    };
    
    return characteristics;
  }

  countFormalWords(text) {
    const formalWords = ['furthermore', 'however', 'therefore', 'regards', 'sincerely', 'respectfully'];
    return this.countWordsInText(text, formalWords);
  }

  countInformalWords(text) {
    const informalWords = ['hey', 'yeah', 'totally', 'awesome', 'cool', 'thanks!'];
    return this.countWordsInText(text, informalWords);
  }

  countPoliteWords(text) {
    const politeWords = ['please', 'thank you', 'sorry', 'excuse me', 'would you mind'];
    return this.countWordsInText(text, politeWords);
  }

  countUrgentWords(text) {
    const urgentWords = ['urgent', 'asap', 'immediately', 'deadline', 'critical'];
    return this.countWordsInText(text, urgentWords);
  }

  countWordsInText(text, words) {
    const lowerText = text.toLowerCase();
    return words.reduce((count, word) => {
      const regex = new RegExp(`\\b${word.toLowerCase()}\\b`, 'g');
      const matches = lowerText.match(regex);
      return count + (matches ? matches.length : 0);
    }, 0);
  }

  findInteraction(suggestionId) {
    return this.feedbackHistory.find(item => 
      item.id === suggestionId || item.suggestionId === suggestionId
    );
  }

  async queueInteraction(interaction) {
    // Simple queue implementation - in production, might use Redis or similar
    if (!this.interactionQueue) {
      this.interactionQueue = [];
    }
    this.interactionQueue.push(interaction);
    
    // Process queue when not busy
    setTimeout(() => {
      if (!this.isProcessing && this.interactionQueue.length > 0) {
        const queued = this.interactionQueue.shift();
        this.recordInteraction(queued);
      }
    }, 100);
  }

  async processInteractionAsync(interaction) {
    // Process interaction in background to avoid blocking
    setTimeout(async () => {
      try {
        this.isProcessing = true;
        
        // Analyze interaction patterns
        await this.analyzeInteractionPatterns(interaction);
        
        // Update learning data
        await this.updateLearningData(interaction);
        
        interaction.processed = true;
        
      } catch (error) {
        console.error('Error processing interaction async:', error);
      } finally {
        this.isProcessing = false;
      }
    }, 0);
  }

  async analyzeInteractionPatterns(interaction) {
    try {
      const context = interaction.context;
      if (!context) return;
      
      // Track context patterns
      const contextKey = this.generatePatternKey(context);
      
      // Update interaction frequency for this context
      const contextPattern = this.patterns.get(contextKey) || this.createNewPattern(contextKey);
      contextPattern.interactionCount = (contextPattern.interactionCount || 0) + 1;
      contextPattern.lastInteraction = new Date();
      
      this.patterns.set(contextKey, contextPattern);
      
    } catch (error) {
      console.error('Error analyzing interaction patterns:', error);
    }
  }

  getDefaultInsights(context) {
    return {
      confidence: 0.5,
      recommendations: ['Use professional tone', 'Keep content clear and concise'],
      warnings: [],
      adaptations: {},
      patternData: null
    };
  }

  getDefaultPreferences() {
    return {
      tone: { formality: 'moderate', politeness: 'polite' },
      structure: { useLists: false, useQuestions: false },
      vocabulary: { style: 'neutral' },
      length: 'medium',
      formality: 'moderate'
    };
  }

  async getAuthToken() {
    return localStorage.getItem('authToken') || 'dev-token';
  }

  // Analytics and debugging methods
  getLearningStats() {
    const stats = {
      totalPatterns: this.patterns.size,
      totalFeedback: this.feedbackHistory.length,
      avgConfidence: 0,
      patternsByContext: {},
      feedbackByAction: { accept: 0, modify: 0, reject: 0 },
      learningTrends: {}
    };

    // Calculate average confidence
    let totalConfidence = 0;
    let patternCount = 0;
    
    for (const pattern of this.patterns.values()) {
      totalConfidence += pattern.confidence;
      patternCount++;
      
      // Group by context
      const contextType = pattern.key.split('_')[0];
      stats.patternsByContext[contextType] = (stats.patternsByContext[contextType] || 0) + 1;
    }
    
    stats.avgConfidence = patternCount > 0 ? totalConfidence / patternCount : 0;

    // Analyze feedback actions
    this.feedbackHistory.forEach(feedback => {
      if (feedback.action && stats.feedbackByAction.hasOwnProperty(feedback.action)) {
        stats.feedbackByAction[feedback.action]++;
      }
    });

    // Calculate learning trends (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentFeedback = this.feedbackHistory.filter(f => f.timestamp > thirtyDaysAgo);
    
    stats.learningTrends = {
      recentFeedbackCount: recentFeedback.length,
      recentAcceptanceRate: recentFeedback.length > 0 ? 
        recentFeedback.filter(f => f.action === 'accept').length / recentFeedback.length : 0,
      improvementTrend: this.calculateImprovementTrend(recentFeedback)
    };

    return stats;
  }

  calculateImprovementTrend(recentFeedback) {
    if (recentFeedback.length < 10) return 'insufficient_data';
    
    // Split into two halves and compare acceptance rates
    const midPoint = Math.floor(recentFeedback.length / 2);
    const firstHalf = recentFeedback.slice(0, midPoint);
    const secondHalf = recentFeedback.slice(midPoint);
    
    const firstHalfAcceptance = firstHalf.filter(f => f.action === 'accept').length / firstHalf.length;
    const secondHalfAcceptance = secondHalf.filter(f => f.action === 'accept').length / secondHalf.length;
    
    const improvement = secondHalfAcceptance - firstHalfAcceptance;
    
    if (improvement > 0.1) return 'improving';
    if (improvement < -0.1) return 'declining';
    return 'stable';
  }

  getPatternDetails(patternKey) {
    const pattern = this.patterns.get(patternKey);
    if (!pattern) return null;
    
    return {
      key: pattern.key,
      confidence: pattern.confidence,
      successCount: pattern.successCount,
      failureCount: pattern.failureCount,
      totalAttempts: pattern.totalAttempts,
      successRate: pattern.totalAttempts > 0 ? pattern.successCount / pattern.totalAttempts : 0,
      averageRating: pattern.averageRating || null,
      learnedPreferences: pattern.learnedPreferences || {},
      lastUpdated: pattern.lastUpdated,
      recentModifications: pattern.modifications?.slice(-5) || [],
      recentRatings: pattern.ratings?.slice(-10) || []
    };
  }

  exportLearningData() {
    return {
      userId: this.userId,
      exportDate: new Date(),
      patterns: Object.fromEntries(this.patterns),
      learningData: Object.fromEntries(this.learningData),
      feedbackHistory: this.feedbackHistory,
      stats: this.getLearningStats(),
      configuration: {
        learningRate: this.learningRate,
        confidenceThreshold: this.confidenceThreshold,
        maxFeedbackHistory: this.maxFeedbackHistory
      }
    };
  }

  importLearningData(data) {
    try {
      if (data.patterns) {
        this.patterns = new Map(Object.entries(data.patterns));
        
        // Convert date strings back to Date objects
        for (const pattern of this.patterns.values()) {
          pattern.createdAt = new Date(pattern.createdAt);
          pattern.lastUpdated = new Date(pattern.lastUpdated);
          if (pattern.lastEvolution) pattern.lastEvolution = new Date(pattern.lastEvolution);
          if (pattern.lastMerge) pattern.lastMerge = new Date(pattern.lastMerge);
        }
      }
      
      if (data.learningData) {
        this.learningData = new Map(Object.entries(data.learningData));
      }
      
      if (data.feedbackHistory) {
        this.feedbackHistory = data.feedbackHistory.map(feedback => ({
          ...feedback,
          timestamp: new Date(feedback.timestamp)
        }));
      }
      
      if (data.configuration) {
        this.learningRate = data.configuration.learningRate || this.learningRate;
        this.confidenceThreshold = data.configuration.confidenceThreshold || this.confidenceThreshold;
        this.maxFeedbackHistory = data.configuration.maxFeedbackHistory || this.maxFeedbackHistory;
      }
      
      console.log('Learning data imported successfully');
      return true;
      
    } catch (error) {
      console.error('Error importing learning data:', error);
      return false;
    }
  }

  // Performance and maintenance methods
  async performMaintenance() {
    try {
      console.log('Starting LearningEngine maintenance...');
      
      // Evolve patterns
      await this.evolveLearningPatterns();
      
      // Save current state
      await this.saveLearningData();
      
      // Clean up memory
      this.cleanupMemory();
      
      console.log('LearningEngine maintenance completed');
      
    } catch (error) {
      console.error('Error during maintenance:', error);
    }
  }

  cleanupMemory() {
    try {
      // Limit feedback history size
      if (this.feedbackHistory.length > this.maxFeedbackHistory) {
        this.feedbackHistory = this.feedbackHistory.slice(-this.maxFeedbackHistory);
      }
      
      // Clean up pattern modifications and ratings
      for (const pattern of this.patterns.values()) {
        if (pattern.modifications && pattern.modifications.length > 20) {
          pattern.modifications = pattern.modifications.slice(-20);
        }
        
        if (pattern.ratings && pattern.ratings.length > 50) {
          pattern.ratings = pattern.ratings.slice(-50);
        }
      }
      
      console.log('Memory cleanup completed');
      
    } catch (error) {
      console.error('Error during memory cleanup:', error);
    }
  }

  getHealthStatus() {
    const health = {
      status: 'healthy',
      issues: [],
      metrics: {
        patternCount: this.patterns.size,
        feedbackCount: this.feedbackHistory.length,
        avgConfidence: 0,
        isProcessing: this.isProcessing
      }
    };

    // Calculate average confidence
    let totalConfidence = 0;
    let patternCount = 0;
    
    for (const pattern of this.patterns.values()) {
      totalConfidence += pattern.confidence;
      patternCount++;
    }
    
    health.metrics.avgConfidence = patternCount > 0 ? totalConfidence / patternCount : 0;

    // Check for issues
    if (this.patterns.size === 0) {
      health.issues.push('No learning patterns available');
      health.status = 'warning';
    }
    
    if (health.metrics.avgConfidence < 0.3) {
      health.issues.push('Low average confidence in patterns');
      health.status = 'warning';
    }
    
    if (this.feedbackHistory.length < 10) {
      health.issues.push('Insufficient feedback data for reliable learning');
      health.status = 'warning';
    }
    
    if (this.isProcessing) {
      health.issues.push('Currently processing interactions');
    }

    return health;
  }

  // Configuration methods
  updateConfiguration(config) {
    if (config.learningRate !== undefined) {
      this.learningRate = Math.max(0, Math.min(1, config.learningRate));
    }
    
    if (config.confidenceThreshold !== undefined) {
      this.confidenceThreshold = Math.max(0, Math.min(1, config.confidenceThreshold));
    }
    
    if (config.maxFeedbackHistory !== undefined) {
      this.maxFeedbackHistory = Math.max(100, config.maxFeedbackHistory);
    }
    
    console.log('LearningEngine configuration updated', {
      learningRate: this.learningRate,
      confidenceThreshold: this.confidenceThreshold,
      maxFeedbackHistory: this.maxFeedbackHistory
    });
  }

  getConfiguration() {
    return {
      learningRate: this.learningRate,
      confidenceThreshold: this.confidenceThreshold,
      maxFeedbackHistory: this.maxFeedbackHistory,
      userId: this.userId
    };
  }

  // Reset and cleanup methods
  reset() {
    this.patterns.clear();
    this.learningData.clear();
    this.feedbackHistory = [];
    this.adaptations.clear();
    this.isProcessing = false;
    
    console.log('LearningEngine reset completed');
  }

  dispose() {
    try {
      // Save current state before disposing
      this.saveLearningData().catch(error => {
        console.error('Error saving data during dispose:', error);
      });
      
      // Clear all data
      this.reset();
      
      // Clear any pending timeouts or intervals
      if (this.maintenanceInterval) {
        clearInterval(this.maintenanceInterval);
      }
      
      console.log('LearningEngine disposed');
      
    } catch (error) {
      console.error('Error disposing LearningEngine:', error);
    }
  }

  // Automatic maintenance scheduling
  startAutoMaintenance(intervalMinutes = 60) {
    if (this.maintenanceInterval) {
      clearInterval(this.maintenanceInterval);
    }
    
    this.maintenanceInterval = setInterval(() => {
      this.performMaintenance().catch(error => {
        console.error('Auto-maintenance error:', error);
      });
    }, intervalMinutes * 60 * 1000);
    
    console.log(`Auto-maintenance scheduled every ${intervalMinutes} minutes`);
  }

  stopAutoMaintenance() {
    if (this.maintenanceInterval) {
      clearInterval(this.maintenanceInterval);
      this.maintenanceInterval = null;
      console.log('Auto-maintenance stopped');
    }
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LearningEngine };
} else {
  window.LearningEngine = LearningEngine;
}