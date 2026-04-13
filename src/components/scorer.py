# Fusion Scorer
# Combines text, URL, and metadata scores
# Uses different weights for whitelisted vs unknown domains

import json
import os

class Scorer:
    
    def __init__(self):
        # Load whitelist for domain checking
        self.whitelisted_domains = self.loadWhitelist()
        
        # Load threshold from whitelist.json
        self.spoofedThreshold = self.loadThreshold()
        
        # ============================================================
        # WEIGHT SETTINGS - CHANGE THESE TO CALIBRATE
        # ============================================================
        self.text_weight_normal = 0.5
        self.url_weight_normal = 0.3
        self.meta_weight_normal = 0.2
        
        self.text_weight_trusted = 0.2
        self.url_weight_trusted = 0.4
        self.meta_weight_trusted = 0.4
        
        self.highThreshold = 70
        self.boostAmount = 20
        self.whitelist_legit_threshold = 30
        self.whitelist_max_text = 10
        # ============================================================
    
    def loadWhitelist(self):
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'whitelist.json')
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                return data.get("trusted_domains", [])
        except Exception as e:
            print(f"[DEBUG] Error loading whitelist in scorer: {e}")
            return []
    
    def loadThreshold(self):
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'whitelist.json')
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                return data.get("spoofed_override_threshold", 50)
        except:
            return 50
    
    def is_whitelisted(self, sender_domain):
        if not sender_domain:
            return False
        return sender_domain in self.whitelisted_domains
    
    def combine(self, textScore, urlScore, metaScore, urlBlacklisted=False, senderSpoofed=False, sender_domain=None):
        
        # Override 1: URL blacklisted
        if urlBlacklisted:
            return {
                "finalScore": 100,
                "verdict": "PHISHING",
                "reason": "Blacklisted URL detected",
                "components": {
                    "text": textScore,
                    "url": urlScore,
                    "metadata": metaScore
                }
            }
        
        # Override 2: Sender is spoofed with suspicious content
        if senderSpoofed:
            # Check if any other component is suspicious (>20%)
            text_suspicious = textScore > 20
            url_suspicious = urlScore > 20
            
            if text_suspicious or url_suspicious:
                return {
                    "finalScore": 100,
                    "verdict": "PHISHING",
                    "reason": "Spoofed sender with suspicious content",
                    "components": {
                        "text": textScore,
                        "url": urlScore,
                        "metadata": metaScore
                    }
                }
            # If spoofed but everything else clean, continue to normal scoring (will be caught later)
        
        trusted = self.is_whitelisted(sender_domain)
        
        if trusted and textScore > self.whitelist_max_text:
            textScore = self.whitelist_max_text
        
        if trusted:
            finalScore = (textScore * self.text_weight_trusted) + \
                         (urlScore * self.url_weight_trusted) + \
                         (metaScore * self.meta_weight_trusted)
        else:
            finalScore = (textScore * self.text_weight_normal) + \
                         (urlScore * self.url_weight_normal) + \
                         (metaScore * self.meta_weight_normal)
        
        finalScore = round(finalScore, 1)
        
        # Special case: Spoofed sender but clean content
        if senderSpoofed and textScore <= 20 and urlScore <= 20:
            finalScore = max(finalScore, 25)
            verdict = "SUSPICIOUS"
            reason = "Spoofed sender - content appears normal but verify sender before replying"
            return {
                "finalScore": finalScore,
                "verdict": verdict,
                "reason": reason,
                "components": {
                    "text": textScore,
                    "url": urlScore,
                    "metadata": metaScore
                },
                "highCount": 0,
                "boosted": False,
                "whitelisted": trusted
            }
        
        highCount = 0
        if textScore >= self.highThreshold:
            highCount += 1
        if urlScore >= self.highThreshold:
            highCount += 1
        if metaScore >= self.highThreshold:
            highCount += 1
        
        if highCount >= 2 and not trusted:
            finalScore = finalScore + self.boostAmount
            if finalScore > 100:
                finalScore = 100
        
        if finalScore >= 70:
            verdict = "PHISHING"
            reason = f"{highCount} high-risk component(s) detected"
        elif finalScore >= 30:
            verdict = "SUSPICIOUS"
            reason = "Some suspicious signals detected"
        else:
            verdict = "LEGITIMATE"
            reason = "No significant threats detected"
        
        if trusted and finalScore < self.whitelist_legit_threshold:
            verdict = "LEGITIMATE"
            reason = "Trusted domain with no significant threats"
        
        if finalScore == 100 and highCount >= 2:
            reason = f"{highCount} high-risk components combined for maximum confidence"
        
        return {
            "finalScore": finalScore,
            "verdict": verdict,
            "reason": reason,
            "components": {
                "text": textScore,
                "url": urlScore,
                "metadata": metaScore
            },
            "highCount": highCount,
            "boosted": highCount >= 2,
            "whitelisted": trusted
        }