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
        
        # The model ID from Hugging Face
        # This is the DistilBERT model fine-tuned on phishing emails
        # Found it in my literature review - aamoshdahal's version
        self.model_id = "aamoshdahal/email-phishing-distilbert-finetuned"
        
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