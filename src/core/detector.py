# Main phishing detector 
# All sections will be called in here

import sys
import os
from email import policy
from email.parser import BytesParser

# Add the components folder so I can import my modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from components.text_checkerAI import TextChecker
from components.url_checker import URLChecker
from components.metadata_checker import MetadataChecker
from components.scorer import Scorer

class PhishingDetector:
    # Main program - this will run all the checks

    def __init__(self):
        # Sets everything up on start
        print("Starting up Phishing Detector...")

        # Load all the components
        print("  Loading text checker...")
        self.textChecker = TextChecker()
        
        print("  Loading URL checker...")
        self.urlChecker = URLChecker()
        
        print("  Loading metadata checker...")
        self.metadataChecker = MetadataChecker()
        
        print("  Loading scorer...")
        self.scorer = Scorer()
        
        print("Detector is ready!")

    def checkEmail(self, email_text, email_headers=None):
        # Look at an email and decide if it's phishing
        # If no headers are provided, we can't do metadata check
        
        print("Analysing email...")

        # 1. Text analysis
        textResult = self.textChecker.checkEmail(email_text)
        
        # 2. URL analysis
        urlResult = self.urlChecker.analyseEmail(email_text)
        
        # 3. Metadata analysis (only if headers provided)
        if email_headers:
            metadataResult = self.metadataChecker.analyseEmail(email_headers)
        else:
            # No headers provided - assume nothing suspicious
            metadataResult = {
                "score": 0,
                "spoofed": False,
                "issues": ["No headers provided"],
                "summary": "No header data available"
            }
        
        # 4. Combine everything using the scorer
        final = self.scorer.combine(
            textScore=textResult["score"],
            urlScore=urlResult["score"],
            metaScore=metadataResult["score"],
            urlBlacklisted=urlResult.get("blacklisted", False),
            senderSpoofed=metadataResult.get("spoofed", False)
        )
        
        # Build the final result
        result = {
            "score": final["finalScore"],
            "verdict": final["verdict"],
            "reason": final["reason"],
            "components": final["components"],
            "text_details": textResult,
            "url_details": urlResult,
            "metadata_details": metadataResult
        }
        
        return result


# Quick test to see if it works
if __name__ == "__main__":
    print("=" * 50)
    print("TESTING MAIN DETECTOR")
    print("=" * 50)
    
    # Create a detector
    detector = PhishingDetector()
    
    # Test email - a phishing attempt
    testEmail = """URGENT: Your PayPal account has been suspended.
Please verify your account immediately by clicking here:
http://paypal-security-verify.com"""
    
    # Test headers - fake sender
    testHeaders = """From: "PayPal Security" <security@paypal-security.com>
Subject: URGENT: Account Limited
Date: Mon, 25 Mar 2025 10:00:00 +0000"""
    
    # Parse headers
    headerMessage = BytesParser(policy=policy.default).parsebytes(testHeaders.encode())
    
    print("\nTesting email:")
    print("-" * 40)
    print(testEmail)
    print("-" * 40)
    
    result = detector.checkEmail(testEmail, headerMessage)
    
    print("\n" + "=" * 50)
    print("RESULT")
    print("=" * 50)
    print(f"  Final Score: {result['score']}%")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Reason: {result['reason']}")
    
    print("\n  Component breakdown:")
    print(f"    Text: {result['components']['text']}%")
    print(f"    URL: {result['components']['url']}%")
    print(f"    Metadata: {result['components']['metadata']}%")