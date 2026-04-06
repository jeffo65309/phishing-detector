# SHAP Explainer with URL and Metadata
# Uses pipeline for model loading (simpler and more reliable)

from transformers import pipeline
import shap
import re
import numpy as np
from src.components.url_checker import URLChecker
from src.components.metadata_checker import MetadataChecker

class ShapExplainer:
    
    def __init__(self):
        print("      [ShapExplainer] Loading model...")
        
        # Create pipeline for text classification
        self.pipe = pipeline(
            "text-classification", 
            model="aamoshdahal/email-phishing-distilbert-finetuned",
            truncation=True,
            max_length=512
        )
        
        # Create SHAP explainer
        self.explainer = shap.Explainer(self.pipe)
        
        # Add URL and metadata checkers
        self.urlChecker = URLChecker()
        self.metadataChecker = MetadataChecker()
        
        # Persuasion map for translating words to principles
        self.persuasionMap = {
            "urgent": "scarcity", "immediately": "scarcity", "deadline": "scarcity",
            "expires": "scarcity", "limited": "scarcity", "last": "scarcity",
            "today": "scarcity", "now": "scarcity", "soon": "scarcity",
            "verify": "authority", "confirm": "authority", "security": "authority",
            "team": "authority", "admin": "authority", "support": "authority",
            "account": "phishing_context", "password": "phishing_context",
            "click": "phishing_action", "link": "phishing_action"
        }
        
        print("      [ShapExplainer] Ready!")
    
    def mapWord(self, word):
        """Map a word to its persuasion principle"""
        clean = re.sub(r'[^\w\s]', '', word).lower()
        if clean in self.persuasionMap:
            return self.persuasionMap[clean]
        for key, value in self.persuasionMap.items():
            if key in clean:
                return value
        return "unknown"
    
    def explainEmail(self, email_text, email_headers=None):
        """Run SHAP and return explanation with URL and metadata scores"""
        
        print("      [ShapExplainer] Running SHAP (this takes 30-60 seconds)...")
        
        # STEP 1: Get text score from pipeline
        result = self.pipe(email_text)
        textScore = int(result[0]['score'] * 100)
        
        # STEP 2: Get URL score
        urlResult = self.urlChecker.analyseEmail(email_text)
        urlScore = urlResult['score']
        
        # STEP 3: Get metadata score (if headers provided)
        if email_headers:
            metaResult = self.metadataChecker.analyseEmail(email_headers)
            metaScore = metaResult['score']
            spoofed = metaResult['spoofed']
        else:
            metaScore = 0
            spoofed = False
        
        # STEP 4: Get SHAP values
        shap_values = self.explainer([email_text])
        
        # STEP 5: Extract word importance from SHAP
        rawWords = []
        if hasattr(shap_values, 'data') and len(shap_values.data) > 0:
            tokens = shap_values.data[0]
            if hasattr(shap_values, 'values') and len(shap_values.values) > 0:
                values = shap_values.values[0]
                
                # Handle value shape (for binary classification)
                if len(values.shape) > 1:
                    # Take the column with highest absolute values (phishing class)
                    col_means = np.abs(values).mean(axis=0)
                    best_col = np.argmax(col_means)
                    values = values[:, best_col]
                
                # Combine tokens into words
                for i, token in enumerate(tokens):
                    if i < len(values):
                        weight = float(values[i])
                        # Filter out punctuation and special tokens
                        if token and not token.startswith('[') and len(token) > 1 and token not in ['.', ',', ':', ';', '!', '?']:
                            rawWords.append((token, weight))
        
        # Sort by absolute weight and take top 20
        rawWords.sort(key=lambda x: abs(x[1]), reverse=True)
        rawWords = rawWords[:20]
        
        # STEP 6: Map to persuasion principles
        mappedWords = []
        persuasionBreakdown = {}
        unmappedWords = []
        
        for word, weight in rawWords:
            principle = self.mapWord(word)
            mappedWords.append({
                "word": word,
                "weight": weight,
                "principle": principle
            })
            
            if principle == "unknown":
                unmappedWords.append(word)
            else:
                if principle not in persuasionBreakdown:
                    persuasionBreakdown[principle] = []
                persuasionBreakdown[principle].append({"word": word, "weight": weight})
        
        # STEP 7: Build summary
        summaryParts = []
        
        # First, show mapped persuasion words
        for principle, words in persuasionBreakdown.items():
            if principle != "unknown" and principle != "phishing_context":
                wordList = [w["word"] for w in words[:3]]
                summaryParts.append(f"{principle} ({', '.join(wordList)})")
        
        # Then, show important words not in map
        if unmappedWords:
            summaryParts.append(f"other words ({', '.join(unmappedWords[:5])})")
        
        # Add URL issues to summary
        if urlResult['has_urls'] and urlResult['issues']:
            for issue in urlResult['issues'][:2]:
                summaryParts.append(issue)
        
        if summaryParts:
            summary = f"Email uses: {', '.join(summaryParts)}"
        else:
            summary = "No clear patterns detected"
        
        # STEP 8: Return everything
        return {
            "textScore": textScore,
            "urlScore": urlScore,
            "metaScore": metaScore,
            "spoofed": spoofed,
            "rawWords": rawWords,
            "mappedWords": mappedWords,
            "persuasionBreakdown": persuasionBreakdown,
            "unmappedWords": unmappedWords,
            "summary": summary,
            "urls": urlResult,
            "time": "shap"
        }


# Quick test when run directly
if __name__ == "__main__":
    print("=" * 60)
    print("TESTING SHAP EXPLAINER")
    print("=" * 60)
    
    explainer = ShapExplainer()
    
    test_email = """URGENT: Your PayPal account has been limited.
Please verify your account immediately by clicking here:
http://paypal-security-verify.com/login"""
    
    result = explainer.explainEmail(test_email)
    
    print(f"\nText score: {result['textScore']}%")
    print(f"URL score: {result['urlScore']}%")
    print(f"Meta score: {result['metaScore']}%")
    print(f"Spoofed: {result['spoofed']}")
    print(f"\nSummary: {result['summary']}")
    print("\nTop 10 words:")
    for word, weight in result['rawWords'][:10]:
        print(f"   {word}: {weight:.4f}")