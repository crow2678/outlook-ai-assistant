// src/core/AIService.js
class AIService {
  constructor() {
    this.openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  }

  async generateSuggestion(styleProfile, context, currentText) {
    const prompt = this.buildPersonalizedPrompt(styleProfile, context);
    
    const response = await this.openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        { role: "system", content: prompt },
        { role: "user", content: `Improve this email: ${currentText}` }
      ]
    });

    return response.choices[0].message.content;
  }

  buildPersonalizedPrompt(styleProfile, context) {
    return `You are helping someone write an email. Here's their writing style:
    - Tone: ${styleProfile.tone}
    - Formality: ${styleProfile.formality}
    - Typical phrases: ${styleProfile.commonPhrases.join(', ')}
    
    Context:
    - Recipient: ${context.recipient.relationship}
    - Email type: ${context.emailType}
    - Thread history: ${context.threadSummary}
    
    Maintain their authentic voice while improving clarity and effectiveness.`;
  }
}