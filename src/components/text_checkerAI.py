# AI Text Checker
# Uses a pre-trained model to detect phishing emails
# I got this from Hugging Face - it's DistilBERT fine-tuned on phishing emails

from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

class TextChecker:
    # Loads the AI model when we create it
    # This is the main brain for checking email text
    
    def __init__(self):
        # Load the model when we create this object
        print(" Loading AI model...")
        
        # ============================================================
        # MODEL OPTIONS FOR TESTING
        # ============================================================
        
        # MODEL 1: aamoshdahal/email-phishing-distilbert-finetuned
        # - The original model from literature review
        # - Text scores: HIGHLY INCONSISTENT (0%, 1%, 14%, 24%, 51%, 82%, 90%, 99%)
        # - Some phishing emails scored 0-14% (amazon_game, tesco_final_notice)
        # - Some legitimate emails scored 99% (microsoft_alert, volkswagen_video)
        # - Before calibration: 100% accuracy (but relied heavily on URL + metadata)
        # - After calibration: 100% accuracy
        # - Verdict: Works but text scores are unreliable/unpredictable
        # - Best for: When URL and metadata are strong (not recommended for text-only)
        #self.model_id = "aamoshdahal/email-phishing-distilbert-finetuned"
        
        # MODEL 2: cybersectony/phishing-email-detection-distilbert_v2.4.1
        # - Most popular alternative (688+ downloads per month - 9x more than Model 1)
        # - Training: Diverse dataset with URLs + email content
        # - Performance: Claims 99.58% accuracy, 99.58% F1-score
        # - Text scores: TOO AGGRESSIVE (75-99% on EVERYTHING - phishing AND legitimate)
        # - Legitimate emails scored 99% (acme_security, chase_transaction, portswigger, streamsync)
        # - Before calibration: 86.7% accuracy (4 false positives on legitimate emails)
        # - After calibration: 100% accuracy (fixed by metaScore ≥70 requirement in Override 2)
        # - Verdict: Excellent phishing detection but cries wolf constantly
        # - Best for: Maximum detection when false positives are acceptable
        #self.model_id = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        
        # MODEL 3: rahulkothuri/phishing-email-disilBERT
        # - Balanced alternative (SELECTED FOR FINAL SYSTEM)
        # - Downloads: Moderate (between Model 1 and Model 2)
        # - Training: 3 epochs, validation loss 0.0266
        # - Performance: Claims 99.39% accuracy
        # - Text scores: MOST BALANCED (46%, 49%, 72%, 81%, 85%, 97%, 98%, 99% on phishing)
        # - Legitimate scores: LOW (0%, 3% on most - only microsoft_alert scored 99%)
        # - Before calibration: 93.3% accuracy (2 false positives on chase_transaction, portswigger)
        # - After calibration: 100% accuracy
        # - Verdict: Best balance between sensitivity and specificity
        # - Best for: Production use where both phishing and legitimate need accurate handling
        self.model_id = "rahulkothuri/phishing-email-disilBERT"
        
        # Load the tokenizer (turns words into numbers)
        # 512 is the max on this model - enough for most emails
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        
        # Load the actual model (the AI brain)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
        
        print(" AI model ready!")
    
    def checkEmail(self, email_text):
        # Analyse an email and return a phishing score
        # This is the main method I'll call from other files
        
        # Convert email to numbers that the model understands
        inputs = self.tokenizer(
            email_text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512  # Fine for now, might need to split longer emails later
        )
        
        # Run the model (no gradient needed - we're just using it, not training)
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        
        # Get the phishing probability (index 1 means phishing)
        phishing_prob = probs[0][1].item()
        score = int(phishing_prob * 100)
        
        # These are the thresholds I decided on
        # | Score Range | Verdict      | Meaning                           |
        # |-------------|--------------|-----------------------------------|
        # | 0% - 29%    | LEGITIMATE   | Almost certainly safe             |
        # | 30% - 69%   | SUSPICIOUS   | Might be phishing, be careful     |
        # | 70% - 100%  | PHISHING     | Almost certainly a phishing attempt |
        # Lower these numbers to make it more suspicious 
        
        if score >= 70:
            verdict = "PHISHING"
        elif score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"
        
        return {
            "score": score,
            "verdict": verdict,
            "raw_probability": phishing_prob  # Keeping this for debugging
        }