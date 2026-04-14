# LIME Explainer with Persuasion Mapping
# Shows which words influenced the AI and maps them to persuasion principles
# This one is slow - takes 1-3 minutes because it runs the model hundreds of times
# I keep it for detailed analysis but use fast_explainer for quick tests

from src.components.url_checker import URLChecker
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from lime.lime_text import LimeTextExplainer
import re
from dotenv import load_dotenv
import os

load_dotenv()

class LimeExplainer:
    
    def __init__(self):
        # Load the AI model and set up LIME
        print("      [LimeExplainer] Starting up...")
        
        # Load the AI model
        print("      [LimeExplainer] Loading AI model...")
        #self.modelId = "aamoshdahal/email-phishing-distilbert-finetuned"
        self.modelId = "rahulkothuri/phishing-email-disilBERT"
        self.tokenizer = AutoTokenizer.from_pretrained(self.modelId)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.modelId)
        
        # Persuasion word map for explaining what the AI found
        # Based on Cialdini's principles from Tooher and Lallie (2025)
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
        
        # Create URL checker
        self.urlChecker = URLChecker()
        
        # Set up LIME
        print("      [LimeExplainer] Setting up LIME...")
        self.classNames = ["legitimate", "phishing"]
        self.explainer = LimeTextExplainer(class_names=self.classNames)
        
        print("      [LimeExplainer] Ready!")
    
    def predictProba(self, texts):
        # Wrapper function that LIME needs to call the AI model
        # This runs the model on a list of texts and returns probabilities
        # LIME calls this many times with slightly modified versions of the email
        inputs = self.tokenizer(
            texts, 
            return_tensors="pt", 
            truncation=True, 
            padding=True, 
            max_length=512
        )
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        return probs.numpy()
    
    def mapWord(self, word):
        # Map a word to its persuasion principle
        # This is just for translation, not for detection
        # If a word isn't in the map, it gets labeled "unknown"
        
        # Remove punctuation and make lowercase so we match consistently
        cleanWord = re.sub(r'[^\w\s]', '', word).lower()
        
        # Check exact match first
        if cleanWord in self.persuasionMap:
            return self.persuasionMap[cleanWord]
        
        # Check if the word contains any key word
        for key, value in self.persuasionMap.items():
            if key in cleanWord:
                return value
        
        # If nothing matches, it's unknown
        return "unknown"
    
    def explainEmail(self, email_text):
        # Run LIME and map words to persuasion principles
        # This is the main method - call this to get a detailed explanation
        
        print("      [LimeExplainer] Running LIME (this takes 1-3 minutes)...")
        
        # STEP 1: Get the AI text score
        # This runs the actual AI model on the email
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
        
        # STEP 3: Run LIME
        # LIME works by creating many copies of the email, each with different words removed
        # It runs the model on each version to see how the prediction changes
        # Words that cause big changes when removed are the important ones
        # This is why LIME is slow - it runs the model hundreds of times
        exp = self.explainer.explain_instance(
            email_text, 
            self.predictProba,
            num_features=20, # change the amount of words shown
            labels=[1]
        )
        
        # Get top words with their weights
        # Positive weight = pushed toward PHISHING
        # Negative weight = pushed toward LEGITIMATE
        rawExplanation = exp.as_list(label=1)
        
        # STEP 4: Map each word to persuasion principles
        # This turns "urgent" into "scarcity", etc.
        mappedWords = []
        for word, weight in rawExplanation[:20]: # changes how many word shows
            principle = self.mapWord(word)
            mappedWords.append({
                "word": word,
                "weight": weight,
                "principle": principle
            })
        
        # Group by persuasion principle
        persuasionBreakdown = {}
        for item in mappedWords:
            principle = item["principle"]
            if principle not in persuasionBreakdown:
                persuasionBreakdown[principle] = []
            persuasionBreakdown[principle].append(item)
        
        # STEP 5: Build the summary for the user
        # This creates a human-readable explanation
        summaryParts = []
        
        # First, show mapped persuasion words (what they mean in human terms)
        for principle, words in persuasionBreakdown.items():
            if principle != "unknown" and principle != "phishing_context":
                wordList = [w["word"].strip('"') for w in words[:3]]
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
            "rawLime": rawExplanation,           # What the model actually saw (with weights)
            "mappedWords": mappedWords,           # Words with principles
            "persuasionBreakdown": persuasionBreakdown,  # Grouped by principle
            "unmappedWords": unmappedWords,       # Important words not in map
            "summary": summary,
            "urls": urlResult
        }