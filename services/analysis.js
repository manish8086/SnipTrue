const fetch = require('node-fetch');

class AnalysisService {
    constructor(apiKey) {
        if (!apiKey) {
            throw new Error('Hugging Face API key is required');
        }
        this.apiKey = apiKey;
        this.API_URL = 'https://api-inference.huggingface.co/models';
        console.log('AnalysisService initialized with API key:', this.apiKey);
    }

    async analyzeText(text) {
        try {
            if (!text || text.trim().length === 0) {
                throw new Error('No text provided for analysis');
            }

            console.log('Starting text analysis...');
            
            // Truncate text if too long (Hugging Face has a token limit)
            const truncatedText = text.slice(0, 1000);
            
            // Use a single model for faster analysis
            console.log('Sending request to Hugging Face API...');
            const response = await fetch(
                `${this.API_URL}/facebook/bart-large-mnli`,
                {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.apiKey}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        inputs: truncatedText,
                        parameters: {
                            candidate_labels: ['credible', 'biased', 'accurate', 'misleading']
                        }
                    })
                }
            );

            if (!response.ok) {
                const errorData = await response.json();
                console.error('Hugging Face API error:', {
                    status: response.status,
                    statusText: response.statusText,
                    error: errorData
                });
                throw new Error(errorData.error || `API request failed with status ${response.status}`);
            }

            const result = await response.json();
            console.log('Raw API response:', result);

            if (!result || !result.scores || !result.labels) {
                throw new Error('Invalid response format from API');
            }

            // Calculate scores based on the model's predictions (as decimals between 0 and 1)
            const credibilityScore = result.scores[result.labels.indexOf('credible')];
            const biasScore = result.scores[result.labels.indexOf('biased')];
            const accuracyScore = result.scores[result.labels.indexOf('accurate')];

            // Calculate objectivity as inverse of bias
            const objectivityScore = 1 - biasScore;

            // Generate summary based on scores (using percentages for readability)
            const credibilityPercent = Math.round(credibilityScore * 100);
            const objectivityPercent = Math.round(objectivityScore * 100);

            // Generate summary based on scores
            const summary = `Analysis shows ${
                credibilityPercent > 70 ? "high credibility" : 
                credibilityPercent > 40 ? "moderate credibility" : "low credibility"
            } with ${
                objectivityPercent > 70 ? "strong objectivity" : 
                objectivityPercent > 40 ? "moderate objectivity" : "low objectivity"
            }. The content appears to be ${
                credibilityPercent > 70 ? "highly reliable" : 
                credibilityPercent > 40 ? "moderately reliable" : "potentially inaccurate"
            }.`;

            // Generate warnings
            const warnings = [];
            if (credibilityScore < 0.5) {
                warnings.push('This content shows signs of low credibility.');
            }
            if (objectivityScore < 0.5) {
                warnings.push('Low objectivity detected in the content.');
            }
            if (credibilityScore < 0.4) {
                warnings.push('The reliability of this content may need verification.');
            }

            const analysis = {
                credibility: credibilityScore,
                objectivity: objectivityScore,
                summary,
                warnings
            };

            console.log('Analysis completed successfully:', analysis);
            return analysis;
        } catch (error) {
            console.error('Analysis failed:', error);
            throw new Error(`Analysis failed: ${error.message}`);
        }
    }
}

module.exports = AnalysisService; 