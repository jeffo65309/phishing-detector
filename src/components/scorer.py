# Fusion Scorer
# Combines text, URL, and metadata scores
# Uses different weights for whitelisted vs unknown domains

import json
import os

class Scorer:
    
    def __init__(self):
        # Load whitelist for domain checking
        self.whitelisted_domains = self.loadWhitelist()
        
        # ============================================================
        # WEIGHT SETTINGS - CHANGE THESE TO CALIBRATE
        # ============================================================
        # For unknown domains (not whitelisted)
        self.text_weight_normal = 0.5
        self.url_weight_normal = 0.3
        self.meta_weight_normal = 0.2
        
        # For whitelisted domains (trusted senders)
        # Text weight is reduced because legitimate emails can look like phishing
        # URL and metadata weights are increased to catch compromised accounts
        self.text_weight_trusted = 0.2
        self.url_weight_trusted = 0.4
        self.meta_weight_trusted = 0.4
        
        # Threshold for "high" risk
        self.highThreshold = 70
        
        # How much to boost when two components are high
        self.boostAmount = 20
        
        # Minimum score for whitelisted domain to be considered suspicious
        # If score is below this, treat as legitimate
        self.whitelist_legit_threshold = 30
        
        # Max text score for whitelisted domains (legitimate emails often look like phishing)
        self.whitelist_max_text = 10
        # ============================================================
    
    def loadWhitelist(self):
        # Go up two levels: from src/components to project root
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'whitelist.json')
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                return data.get("trusted_domains", [])
        except Exception as e:
            print(f"[DEBUG] Error loading whitelist in scorer: {e}")
            return []
    
    def is_whitelisted(self, sender_domain):
        """Check if domain is in whitelist"""
        if not sender_domain:
            return False
        return sender_domain in self.whitelisted_domains
    
    def combine(self, textScore, urlScore, metaScore, urlBlacklisted=False, senderSpoofed=False, sender_domain=None):
        """
        Combine all scores into final verdict
        """
        # Write to debug file
        with open('debug.txt', 'a') as f:
            f.write(f"[Scorer] Received sender_domain: '{sender_domain}'\n")
            f.write(f"[Scorer] Is whitelisted? {self.is_whitelisted(sender_domain)}\n")
        
        # ============================================================
        # OVERRIDES - These always take priority
        # ============================================================
        
        # Override 1: URL is blacklisted -> 100% PHISHING
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
        
        # Override 2: Sender is spoofed AND metadata score is high -> 100% PHISHING
        if senderSpoofed and metaScore >= 50:
            return {
                "finalScore": 100,
                "verdict": "PHISHING",
                "reason": "Spoofed sender detected with high confidence",
                "components": {
                    "text": textScore,
                    "url": urlScore,
                    "metadata": metaScore
                }
            }
        
        # ============================================================
        # WHITELIST TEXT OVERRIDE
        # Legitimate emails from trusted domains often look like phishing
        # So we cap the text score for whitelisted domains
        # ============================================================
        
        trusted = self.is_whitelisted(sender_domain)
        
        if trusted and textScore > self.whitelist_max_text:
            original_text = textScore
            textScore = self.whitelist_max_text
        
        # ============================================================
        # WEIGHTED SCORE - Different weights for whitelisted domains
        # ============================================================
        
        if trusted:
            # For trusted domains, text matters less, URL and metadata matter more
            finalScore = (textScore * self.text_weight_trusted) + \
                         (urlScore * self.url_weight_trusted) + \
                         (metaScore * self.meta_weight_trusted)
        else:
            # For unknown domains, use normal weights
            finalScore = (textScore * self.text_weight_normal) + \
                         (urlScore * self.url_weight_normal) + \
                         (metaScore * self.meta_weight_normal)
        
        finalScore = round(finalScore, 1)
        
        # ============================================================
        # BOOST LOGIC - If two or more components are high
        # ============================================================
        
        highCount = 0
        if textScore >= self.highThreshold:
            highCount += 1
        if urlScore >= self.highThreshold:
            highCount += 1
        if metaScore >= self.highThreshold:
            highCount += 1
        
        # Only apply boost for unknown domains (not whitelisted)
        if highCount >= 2 and not trusted:
            finalScore = finalScore + self.boostAmount
            if finalScore > 100:
                finalScore = 100
        
        # ============================================================
        # VERDICT DETERMINATION
        # ============================================================
        # Score ranges:
        # | 0% - 29%    | LEGITIMATE   | Almost certainly safe
        # | 30% - 69%   | SUSPICIOUS   | Might be phishing, be careful
        # | 70% - 100%  | PHISHING     | Almost certainly a phishing attempt
        # ============================================================
        
        if finalScore >= 70:
            verdict = "PHISHING"
            reason = f"{highCount} high-risk component(s) detected"
        elif finalScore >= 30:
            verdict = "SUSPICIOUS"
            reason = "Some suspicious signals detected"
        else:
            verdict = "LEGITIMATE"
            reason = "No significant threats detected"
        
        # Special case: whitelisted domain with low score -> LEGITIMATE
        if trusted and finalScore < self.whitelist_legit_threshold:
            verdict = "LEGITIMATE"
            reason = "Trusted domain with no significant threats"
        
        # If we boosted to 100, give better explanation
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