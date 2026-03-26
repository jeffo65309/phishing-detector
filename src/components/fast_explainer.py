# Fast Explainer
# Uses transformers-interpret to show which words influenced the model
# Much faster than LIME - runs in 1-2 seconds
# It doesn't catch every single word but it's good enough for quick explanations

from src.components.url_checker import URLChecker
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers_interpret import SequenceClassificationExplainer
import torch
import re


class FastExplainer:
    
    def __init__(self, silent=False):
        self.silent = silent
        if not self.silent:
            # Load the model when I create this
            # This runs once when the explainer is created
            print("      [FastExplainer] Loading model...")
        
        # This is the same DistilBERT model from my literature review
        # It's already trained to detect phishing emails
        self.modelId = "aamoshdahal/email-phishing-distilbert-finetuned"
        self.tokenizer = AutoTokenizer.from_pretrained(self.modelId)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.modelId)
        
        # Persuasion map - links words to persuasion principles
        # I got these from Tooher and Lallie (2025) in my literature review
        # This map is only for translating words into human-readable principles
        # The actual detection comes from the AI model, not this map
        self.persuasionMap = {
            # Authority - pretending to be important
            "admin": "authority", "security": "authority", "team": "authority",
            "manager": "authority", "ceo": "authority", "director": "authority",
            "support": "authority", "official": "authority",
            
            # Scarcity - creating urgency
            "urgent": "scarcity", "immediately": "scarcity", "deadline": "scarcity",
            "expires": "scarcity", "limited": "scarcity", "last": "scarcity",
            "today": "scarcity", "now": "scarcity", "soon": "scarcity",
            
            # Social proof - everyone else is doing it
            "others": "social_proof", "colleagues": "social_proof", "everyone": "social_proof",
            "recommended": "social_proof", "trusted": "social_proof",
            
            # Likeability - polite words (often in legitimate emails)
            "thank": "likeability", "appreciate": "likeability", "please": "likeability",
            "kindly": "likeability", "happy": "likeability",
            
            # Common phishing words
            "verify": "authority", "confirm": "authority", "update": "authority",
            "account": "phishing_context", "password": "phishing_context",
            "suspended": "scarcity", "limited": "scarcity",
            "click": "phishing_action", "link": "phishing_action"
        }
        
        # URL checker for links
        self.urlChecker = URLChecker()
        
        if not self.silent:
            print("      [FastExplainer] Ready!")
    
    def mapWord(self, word):
        # Map a word to its persuasion principle
        # This is just for translation, not for detection
        # If a word isn't in the map, it gets labeled "unknown"
        
        # Remove punctuation and make lowercase so we match consistently
        clean = re.sub(r'[^\w\s]', '', word).lower()
        
        # Check exact match first
        if clean in self.persuasionMap:
            return self.persuasionMap[clean]
        
        # Check if the word contains any key word
        for key, value in self.persuasionMap.items():
            if key in clean:
                return value
        
        # If nothing matches, it's unknown
        return "unknown"
    
    def explainEmail(self, email_text):
        # Run the fast explanation and return scores and word breakdown
        # This is the main method - call this to get an explanation
        
        if not self.silent:
            print("      [FastExplainer] Running fast explanation...")
        
        # STEP 1: Get the AI text score
        # This runs the actual AI model on the email
        # The tokenizer converts words to numbers, then the model predicts
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
        
        textScore = int(probs[0][1].item() * 100)
        
        # STEP 2: Get the URL score
        # This checks links in the email for suspicious patterns
        urlResult = self.urlChecker.analyseEmail(email_text)
        urlScore = urlResult['score']
        
        # STEP 3: Get word attributions using transformers-interpret
        # This is where the magic happens
        # transformers-interpret looks at the model and figures out
        # which words had the biggest influence on its decision
        # It runs the model once and tracks how each word affects the output
        explainer = SequenceClassificationExplainer(self.model, self.tokenizer)
        wordAttributions = explainer(email_text)
        
        # wordAttributions is a list of (word, weight) pairs
        # Positive weight = pushed toward PHISHING
        # Negative weight = pushed toward LEGITIMATE
        # Higher absolute weight = more influence
        
        # Take top words (more than 10 so we see more)
        topWords = wordAttributions[:20]  # can change this
        
        # STEP 4: Map them to persuasion principles
        # This turns "urgent" into "scarcity", etc.
        mappedWords = []
        persuasionBreakdown = {}
        
        for word, weight in topWords:
            principle = self.mapWord(word)
            mappedWords.append({
                "word": word,
                "weight": weight,
                "principle": principle
            })
            
            if principle not in persuasionBreakdown:
                persuasionBreakdown[principle] = []
            persuasionBreakdown[principle].append({"word": word, "weight": weight})
        
        # STEP 5: Build the summary for the user
        # This creates a human-readable explanation
        summaryParts = []
        
        # First, show mapped persuasion words (what they mean in human terms)
        for principle, words in persuasionBreakdown.items():
            if principle != "unknown" and principle != "phishing_context":
                wordList = [w["word"] for w in words[:3]]
                summaryParts.append(f"{principle} ({', '.join(wordList)})")
        
        # Then, show important words that weren't in the map
        # These are still important to the AI, just not in my persuasion list
        unmappedWords = []
        for item in mappedWords:
            if item['principle'] == "unknown":
                unmappedWords.append(item['word'])
        
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
        
        # STEP 6: Return everything
        # This includes both the raw data (what the model actually saw)
        # and the translated version (what the user can understand)
        return {
            "textScore": textScore,
            "urlScore": urlScore,
            "rawWords": topWords,                    # What the model actually saw
            "mappedWords": mappedWords,               # Words with principles
            "persuasionBreakdown": persuasionBreakdown,  # Grouped by principle
            "unmappedWords": unmappedWords,           # Important words not in map
            "summary": summary,
            "urls": urlResult,
            "time": "fast"
        }