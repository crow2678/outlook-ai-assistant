// src/core/AIEngine.js
class AIEngine {
  constructor() {
    this.initialized = false;
    this.userId = null;
    this.userProfile = null;
    this.styleAnalyzer = null;
    this.contextManager = null;
    this.learningEngine = null;
    this.pluginManager = null;
  }

  async initialize(userId) {
    try {
      this.userId = userId;
      
      // Initialize core components
      const { StyleAnalyzer } = await import('./StyleAnalyzer.js');
      const { ContextManager } = await import('./ContextManager.js');
      const { LearningEngine } = await import('./LearningEngine.js');
      const { PluginManager } = await import('./PluginManager.js');
      
      this.styleAnalyzer = new StyleAnalyzer(userId);
      this.contextManager = new ContextManager(userId);
      this.learningEngine = new LearningEngine(userId);
      this.pluginManager = new PluginManager();

      // Load user profile
      await this.loadUserProfile();
      
      // Initialize plugins
      await this.pluginManager.loadPlugins();
      
      this.initialized = true;
      console.log('AI Engine initialized successfully');
      
    } catch (error) {
      console.error('Failed to initialize AI Engine:', error);
      throw error;
    }
  }

  async loadUserProfile() {
    try {
      const response = await fetch(`/api/users/${this.userId}/profile`);
      if (response.ok) {
        this.userProfile = await response.json();
      } else {
        // New user - will need onboarding
        this.userProfile = null;
      }
    } catch (error) {
      console.error('Error loading user profile:', error);
      this.userProfile = null;
    }
  }

  async generateSuggestion(trigger, options = {}) {
    if (!this.initialized) {
      throw new Error('AI Engine not initialized');
    }

    try {
      // Gather context
      const context = await this.contextManager.gatherContext();
      
      // Get current email content
      const currentContent = await this.getCurrentEmailContent();
      
      // Apply plugins to context
      const enhancedContext = await this.pluginManager.executeHook('beforeSuggestion', {
        context,
        currentContent,
        trigger,
        options
      });

      // Generate suggestion based on user's style
      const suggestion = await this.generatePersonalizedSuggestion(
        enhancedContext.context,
        enhancedContext.currentContent,
        trigger
      );

      // Apply plugins to suggestion
      const finalSuggestion = await this.pluginManager.executeHook('afterSuggestion', {
        suggestion,
        context: enhancedContext.context,
        trigger
      });

      // Record interaction for learning
      this.learningEngine.recordInteraction({
        context: enhancedContext.context,
        suggestion: finalSuggestion.suggestion,
        trigger,
        timestamp: new Date()
      });

      return finalSuggestion.suggestion;

    } catch (error) {
      console.error('Error generating suggestion:', error);
      throw error;
    }
  }

  async generatePersonalizedSuggestion(context, currentContent, trigger) {
    const styleProfile = this.userProfile?.styleProfile || this.getDefaultStyle();
    
    // Build personalized prompt
    const prompt = this.buildPrompt(styleProfile, context, trigger);
    
    // Call AI service
    const response = await fetch('/api/ai/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${await this.getAuthToken()}`
      },
      body: JSON.stringify({
        prompt,
        content: currentContent,
        context,
        userId: this.userId
      })
    });

    if (!response.ok) {
      throw new Error('Failed to generate AI suggestion');
    }

    return await response.json();
  }

  buildPrompt(styleProfile, context, trigger) {
    let basePrompt = `You are helping someone write an email. Here's their writing style:
    - Tone: ${styleProfile.tone || 'professional'}
    - Formality: ${styleProfile.formality || 'moderate'}
    - Sentence length preference: ${styleProfile.sentenceLength || 'varied'}
    - Common phrases: ${styleProfile.commonPhrases?.join(', ') || 'none specified'}
    
    Context:
    - Recipient relationship: ${context.recipient?.relationship || 'unknown'}
    - Email type: ${context.emailType || 'general'}
    - Time of day: ${context.timeOfDay}
    - Thread context: ${context.threadSummary || 'new email'}
    `;

    // Customize prompt based on trigger type
    switch (trigger) {
      case 'improve':
        basePrompt += '\n\nImprove the following email while maintaining the user\'s authentic voice:';
        break;
      case 'formal':
        basePrompt += '\n\nMake the following email more formal while keeping the user\'s style:';
        break;
      case 'casual':
        basePrompt += '\n\nMake the following email more casual while keeping the user\'s style:';
        break;
      case 'shorter':
        basePrompt += '\n\nMake the following email more concise while keeping the user\'s style:';
        break;
      default:
        basePrompt += '\n\nHelp improve the following email:';
    }

    return basePrompt;
  }

  async getCurrentEmailContent() {
    return new Promise((resolve, reject) => {
      if (typeof Office !== 'undefined' && Office.context.mailbox.item) {
        Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => {
          if (result.status === Office.AsyncResultStatus.Succeeded) {
            resolve(result.value);
          } else {
            reject(new Error('Failed to get email content'));
          }
        });
      } else {
        // Fallback for development/testing
        resolve('Sample email content');
      }
    });
  }

  async getAuthToken() {
    // Implementation for getting user auth token
    return localStorage.getItem('authToken') || 'dev-token';
  }

  getDefaultStyle() {
    return {
      tone: 'professional',
      formality: 'moderate',
      sentenceLength: 'varied',
      commonPhrases: []
    };
  }

  // Learning feedback methods
  async recordUserFeedback(suggestionId, action, modifiedText = null) {
    await this.learningEngine.recordUserFeedback(suggestionId, action, modifiedText);
  }

  // Plugin management
  async registerPlugin(plugin) {
    await this.pluginManager.registerPlugin(plugin);
  }

  // Health check
  isHealthy() {
    return this.initialized && this.styleAnalyzer && this.contextManager && this.learningEngine;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AIEngine;
} else {
  window.AIEngine = AIEngine;
}