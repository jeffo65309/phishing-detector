# SHAP/FAST Explainer - Dual Mode with Proper Word Grouping
# Change the SELECTED_MODEL line below to switch between models
from dotenv import load_dotenv
load_dotenv()  # This loads .env file
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch
import re
from src.components.url_checker import URLChecker
from src.components.metadata_checker import MetadataChecker

# ============================================================
# CHANGE THIS ONE LINE TO SWITCH MODELS
# ============================================================
# "model1" = aamoshdahal (uses SHAP - slower, 30-60 seconds)
# "model3" = rahulkothuri (uses Fast Explainer - faster, 5-10 seconds)

SELECTED_MODEL = "model3"   # Change to "model1" or "model3"

# ============================================================

class ShapExplainer:
    
    def __init__(self):
        print("      [ShapExplainer] Loading model...")
        
        if SELECTED_MODEL == "model1":
            # MODEL 1 - Uses SHAP pipeline
            print("      [ShapExplainer] Using Model 1 with SHAP (30-60 seconds)")
            self.model_name = "aamoshdahal/email-phishing-distilbert-finetuned"
            self.use_shap = True
            
            # Load pipeline for SHAP
            self.pipe = pipeline(
                "text-classification", 
                model=self.model_name,
                truncation=True,
                max_length=512
            )
            
            self.tokenizer = self.pipe.tokenizer
            self.model = self.pipe.model
            
        else:
            # MODEL 3 - Uses transformers-interpret
            print("      [ShapExplainer] Using Model 3 with Fast Explainer (5-10 seconds)")
            self.model_name = "rahulkothuri/phishing-email-disilBERT"
            self.use_shap = False
            
            # Load model directly for transformers-interpret
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
        
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
            "suspended": "scarcity", "limited": "scarcity", "locked": "scarcity",
            "closes": "scarcity", "expires": "scarcity"
        }
        
        # Import SHAP only if using Model 1
        if self.use_shap:
            import shap
            self.shap = shap
            self.masker = shap.maskers.Text(tokenizer=self.tokenizer)
            self.explainer = shap.Explainer(self.pipe, self.masker)
        
        print("      [ShapExplainer] Ready!")
    
    def mapWord(self, word):
        clean = re.sub(r'[^\w\s]', '', word).lower()
        if clean in self.persuasionMap:
            return self.persuasionMap[clean]
        for key, value in self.persuasionMap.items():
            if key in clean:
                return value
        return "unknown"
    
    def group_tokens_into_words(self, tokens, weights):
        """Group subword tokens back into full words"""
        words = []
        current_word = ""
        current_weight = 0.0
        
        for i, token in enumerate(tokens):
            # Skip special tokens
            if token in ['[CLS]', '[SEP]', '[PAD]', '[UNK]', '[MASK]']:
                continue
            
            # Skip punctuation tokens that are just single characters
            if token in [',', '.', ';', ':', '!', '?', '(', ')', '[', ']', '{', '}']:
                continue
            
            # Handle subword tokens (start with ##)
            if token.startswith('##'):
                current_word += token[2:]
                if i < len(weights):
                    current_weight += weights[i]
            else:
                # Save previous word
                if current_word and len(current_word) > 1:
                    words.append((current_word, current_weight))
                # Start new word
                current_word = token
                current_weight = weights[i] if i < len(weights) else 0.0
        
        # Save last word
        if current_word and len(current_word) > 1:
            words.append((current_word, current_weight))
        
        return words
    
    def get_text_score_model1(self, email_text):
        """Get text score using pipeline (Model 1)"""
        result = self.pipe(email_text)
        if isinstance(result, list):
            result = result[0]
        return int(result['score'] * 100)
    
    def get_text_score_model3(self, email_text):
        """Get text score using direct model (Model 3)"""
        inputs = self.tokenizer(
            email_text, 
            return_tensors="pt", 
            truncation=True, 
            padding=True, 
            max_length=512
        )
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        return int(probs[0][1].item() * 100)
    
    def explain_with_shap(self, email_text):
        """Run SHAP explanation for Model 1"""
        print("      [ShapExplainer] Running SHAP (this takes 30-60 seconds)...")
        
        # Get SHAP values
        shap_values = self.explainer([email_text])
        
        # Extract word importance
        rawWords = []
        if hasattr(shap_values, 'data') and len(shap_values.data) > 0:
            tokens = shap_values.data[0]
            if hasattr(shap_values, 'values') and len(shap_values.values) > 0:
                values = shap_values.values[0]
                
                if len(values.shape) > 1 and values.shape[1] > 1:
                    values = values[:, 1]
                
                current_word = ""
                current_weight = 0.0
                for i, token in enumerate(tokens):
                    if token is None:
                        continue
                    if token.startswith('##'):
                        current_word += token[2:]
                        if i < len(values) and values[i] is not None:
                            current_weight += float(values[i])
                    else:
                        if current_word:
                            clean_word = re.sub(r'[^\w\s]', '', current_word)
                            if clean_word and len(clean_word) > 1:
                                rawWords.append((clean_word, current_weight))
                        current_word = token
                        current_weight = float(values[i]) if i < len(values) and values[i] is not None else 0.0
                
                if current_word:
                    clean_word = re.sub(r'[^\w\s]', '', current_word)
                    if clean_word and len(clean_word) > 1:
                        rawWords.append((clean_word, current_weight))
        
        # Remove duplicates and sort
        seen = set()
        unique_words = []
        for word, weight in rawWords:
            if word.lower() not in seen:
                seen.add(word.lower())
                unique_words.append((word, weight))
        
        unique_words.sort(key=lambda x: abs(x[1]), reverse=True)
        topWords = unique_words[:15]
        
        return topWords
    
    def explain_with_fast(self, email_text):
        """Run fast explanation for Model 3 with proper word grouping"""
        print("      [ShapExplainer] Running fast analysis (5-10 seconds)...")
        
        from transformers_interpret import SequenceClassificationExplainer
        
        explainer = SequenceClassificationExplainer(self.model, self.tokenizer)
        word_attributions = explainer(email_text)
        
        # word_attributions is list of (token, weight)
        # Extract tokens and weights separately
        tokens = [item[0] for item in word_attributions]
        weights = [item[1] for item in word_attributions]
        
        # Group tokens into full words
        grouped_words = self.group_tokens_into_words(tokens, weights)
        
        # Remove duplicates and sort by absolute weight
        seen = set()
        unique_words = []
        for word, weight in grouped_words:
            if word.lower() not in seen:
                seen.add(word.lower())
                unique_words.append((word, weight))
        
        unique_words.sort(key=lambda x: abs(x[1]), reverse=True)
        topWords = unique_words[:15]
        
        return topWords
    
    def explainEmail(self, email_text, email_headers=None):
        """Run explanation based on selected model"""
        
        # Get text score based on model
        if self.use_shap:
            textScore = self.get_text_score_model1(email_text)
        else:
            textScore = self.get_text_score_model3(email_text)
        
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
        
        # Run explanation based on model
        if self.use_shap:
            topWords = self.explain_with_shap(email_text)
        else:
            topWords = self.explain_with_fast(email_text)
        
        # Map to persuasion principles
        persuasionBreakdown = {}
        unmappedWords = []
        
        for word, weight in topWords:
            principle = self.mapWord(word)
            if principle == "unknown":
                unmappedWords.append(word)
            else:
                if principle not in persuasionBreakdown:
                    persuasionBreakdown[principle] = []
                persuasionBreakdown[principle].append({"word": word, "weight": round(weight, 4)})
        
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
        
        return {
            "textScore": textScore,
            "urlScore": urlScore,
            "metaScore": metaScore,
            "spoofed": spoofed,
            "rawWords": topWords,
            "persuasionBreakdown": persuasionBreakdown,
            "unmappedWords": unmappedWords,
            "summary": summary,
            "urls": urlResult,
            "time": "shap" if self.use_shap else "fast"
        }