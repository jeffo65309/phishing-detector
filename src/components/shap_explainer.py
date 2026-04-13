# SHAP Explainer - Improved Version
# Uses pipeline for model loading and produces cleaner output

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
        
        # Create SHAP explainer with a text masker
        self.masker = shap.maskers.Text(tokenizer=self.pipe.tokenizer)
        self.explainer = shap.Explainer(self.pipe, self.masker)
        
        # Add URL and metadata checkers
        self.urlChecker = URLChecker()
        self.metadataChecker = MetadataChecker()
        
        # Persuasion map
        self.persuasionMap = {
            "urgent": "scarcity", "immediately": "scarcity", "deadline": "scarcity",
            "verify": "authority", "confirm": "authority", "security": "authority",
            "team": "authority", "admin": "authority", "support": "authority",
            "account": "phishing_context", "password": "phishing_context",
            "click": "phishing_action", "link": "phishing_action",
            "suspended": "scarcity", "limited": "scarcity", "locked": "scarcity"
        }
        
        print("      [ShapExplainer] Ready!")
    
    def mapWord(self, word):
        clean = re.sub(r'[^\w\s]', '', word).lower()
        if clean in self.persuasionMap:
            return self.persuasionMap[clean]
        for key, value in self.persuasionMap.items():
            if key in clean:
                return value
        return "unknown"
    
    def explainEmail(self, email_text, email_headers=None):
        """Run SHAP and return explanation"""
        
        print("      [ShapExplainer] Running SHAP (this takes 30-60 seconds)...")
        
        # Get text score
        result = self.pipe(email_text)
        textScore = int(result[0]['score'] * 100)
        
        # Get URL score
        urlResult = self.urlChecker.analyseEmail(email_text)
        urlScore = urlResult['score']
        
        # Get metadata score
        if email_headers:
            metaResult = self.metadataChecker.analyseEmail(email_headers)
            metaScore = metaResult['score']
            spoofed = metaResult['spoofed']
        else:
            metaScore = 0
            spoofed = False
        
        # Get SHAP values
        shap_values = self.explainer([email_text])
        
        # Extract word importance
        rawWords = []
        if hasattr(shap_values, 'data') and len(shap_values.data) > 0:
            tokens = shap_values.data[0]
            if hasattr(shap_values, 'values') and len(shap_values.values) > 0:
                values = shap_values.values[0]
                
                # For binary classification, take the second column (phishing)
                if len(values.shape) > 1 and values.shape[1] > 1:
                    values = values[:, 1]
                
                # Group tokens into words
                current_word = ""
                current_weight = 0.0
                for i, token in enumerate(tokens):
                    if token.startswith('##'):
                        current_word += token[2:]
                        if i < len(values):
                            current_weight += float(values[i])
                    else:
                        if current_word:
                            # Clean up the word
                            clean_word = re.sub(r'[^\w\s]', '', current_word)
                            if clean_word and len(clean_word) > 1:
                                rawWords.append((clean_word, current_weight))
                        current_word = token
                        current_weight = float(values[i]) if i < len(values) else 0.0
                
                # Add last word
                if current_word:
                    clean_word = re.sub(r'[^\w\s]', '', current_word)
                    if clean_word and len(clean_word) > 1:
                        rawWords.append((clean_word, current_weight))
        
        # Remove duplicates and sort by absolute weight
        seen = set()
        unique_words = []
        for word, weight in rawWords:
            if word.lower() not in seen:
                seen.add(word.lower())
                unique_words.append((word, weight))
        
        unique_words.sort(key=lambda x: abs(x[1]), reverse=True)
        topWords = unique_words[:15]
        
        # Map to persuasion principles
        mappedWords = []
        persuasionBreakdown = {}
        unmappedWords = []
        
        for word, weight in topWords:
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
        
        # Build summary
        summaryParts = []
        for principle, words in persuasionBreakdown.items():
            if principle != "unknown" and principle != "phishing_context":
                wordList = [w["word"] for w in words[:3]]
                summaryParts.append(f"{principle} ({', '.join(wordList)})")
        
        if unmappedWords:
            summaryParts.append(f"other words ({', '.join(unmappedWords[:5])})")
        
        if urlResult['has_urls'] and urlResult['issues']:
            for issue in urlResult['issues'][:2]:
                summaryParts.append(issue)
        
        if summaryParts:
            summary = f"Email uses: {', '.join(summaryParts)}"
        else:
            summary = "No clear patterns detected"
        
        # Scale weights to be more readable (multiply by 1000)
        scaledWords = [(word, round(weight * 1000, 2)) for word, weight in topWords]
        
        return {
            "textScore": textScore,
            "urlScore": urlScore,
            "metaScore": metaScore,
            "spoofed": spoofed,
            "rawWords": scaledWords,
            "mappedWords": mappedWords,
            "persuasionBreakdown": persuasionBreakdown,
            "unmappedWords": unmappedWords,
            "summary": summary,
            "urls": urlResult,
            "time": "shap"
        }