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
        self.text_weight_normal = 0.5  # 50% of final score from AI text
        self.url_weight_normal = 0.3   # % from URL analysis
        self.meta_weight_normal = 0.2  # % from SPF/DKIM checks
        
        self.text_weight_trusted = 0.2  # Only 20% from text
        self.url_weight_trusted = 0.4   # 40% from URLs 
        self.meta_weight_trusted = 0.4  # 40% from metadata (this is set to 0% for whitelisted!)
        
        self.highThreshold = 70
        self.boostAmount = 20   # Up from 20 bigger boost when multiple signals
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
        # Direct match
        if sender_domain in self.whitelisted_domains:
            return True
        # Check parent domains (e.g., "email.halfords.com" -> "halfords.com")
        parts = sender_domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.whitelisted_domains:
                return True
        return False
    
    def combine(self, textScore, urlScore, metaScore, urlBlacklisted=False, senderSpoofed=False, sender_domain=None, url_safe=False):
        
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
        
        # Override 2: URL verified safe by reputation API (FIXES MARKETING EMAILS)
        if url_safe and textScore >= 70 and urlScore <= 30:
            return {
                "finalScore": 15,
                "verdict": "LEGITIMATE",
                "reason": "Links verified safe by threat intelligence - likely marketing email",
                "components": {
                    "text": textScore,
                    "url": urlScore,
                    "metadata": metaScore
                }
            }
        
        # Override 3: Sender is spoofed with suspicious content
        if senderSpoofed:
            # Only trigger if metadata is also high (strong spoofing evidence)
            # This prevents legitimate emails with weak spoofing (40%) from triggering
            text_suspicious = textScore >= 20 and metaScore >= 70
            url_suspicious = urlScore >= 20
            
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
        
        # NEW RULE: Extremely high text confidence + spoofed sender = PHISHING
        # This catches emails with 95%+ text score and at least weak spoofing (40%+ metadata)
        # Does NOT apply to whitelisted domains (which have meta=0%)
        if textScore >= 95 and metaScore >= 40 and not self.is_whitelisted(sender_domain):
            return {
                "finalScore": 100,
                "verdict": "PHISHING",
                "reason": "Extremely high confidence phishing text with spoofed sender",
                "components": {
                    "text": textScore,
                    "url": urlScore,
                    "metadata": metaScore
                }
            }
        
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