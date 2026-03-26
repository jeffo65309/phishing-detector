# Fusion Scorer
# Combines text, URL, and metadata scores
# I decided to use overrides for direct threats like blacklisted URLs or spoofed senders
# If it's clearly bad, just make it 100% and be done with it

class Scorer:
    
    def __init__(self):
        # Threshold for what I consider "high" risk
        # I picked 70% because that's where the AI model flags as phishing
        self.highThreshold = 70
        
        # How much to boost when two components are high
        # 20% feels right - enough to push it to 100% if something else is also high
        self.boostAmount = 20
    
    def combine(self, textScore, urlScore, metaScore, urlBlacklisted=False, senderSpoofed=False):
        # This is the main method - takes all three scores and returns final verdict
        
        # Override 1: URL is blacklisted
        # If a URL is in URLhaus, that's direct evidence of a threat
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
        
        # Override 2: Sender is spoofed
        # If SPF/DKIM/DMARC fail, someone is pretending to be someone else
        if senderSpoofed:
            return {
                "finalScore": 100,
                "verdict": "PHISHING",
                "reason": "Spoofed sender detected",
                "components": {
                    "text": textScore,
                    "url": urlScore,
                    "metadata": metaScore
                }
            }
        
        # No overrides - start with the highest individual score
        finalScore = max(textScore, urlScore, metaScore)
        
        # Count how many components are "high" (above my threshold)
        highCount = 0
        if textScore >= self.highThreshold:
            highCount += 1
        if urlScore >= self.highThreshold:
            highCount += 1
        if metaScore >= self.highThreshold:
            highCount += 1
        
        # If two or more components are high, add a boost
        # This makes sense - multiple signals should increase confidence
        if highCount >= 2:
            finalScore = finalScore + self.boostAmount
            if finalScore > 100:
                finalScore = 100
        
        # Determine verdict based on final score
        # I kept the same thresholds as the AI model for consistency
        # | Score Range | Verdict      | Meaning                           |
        # |-------------|--------------|-----------------------------------|
        # | 0% - 29%    | LEGITIMATE   | Almost certainly safe             |
        # | 30% - 69%   | SUSPICIOUS   | Might be phishing, be careful     |
        # | 70% - 100%  | PHISHING     | Almost certainly a phishing attempt |
        
        if finalScore >= 70:
            verdict = "PHISHING"
            reason = f"{highCount} high-risk component(s) detected"
        elif finalScore >= 30:
            verdict = "SUSPICIOUS"
            reason = "Some suspicious signals detected"
        else:
            verdict = "LEGITIMATE"
            reason = "No significant threats detected"
        
        # If we boosted to 100, give a better explanation
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
            "boosted": highCount >= 2
        }