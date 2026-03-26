# LIME explainer test (slow)
# Shows what the AI model actually saw (raw words with weights)
# And translates them to persuasion principles where possible

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.components.lime_explainer import LimeExplainer
from src.core.detector import PhishingDetector
from test_data import TEST_EMAIL

def test_email():
    print("=" * 60)
    print("TESTING LIME EXPLAINER (SLOW)")
    print("=" * 60)
    
    detector = PhishingDetector()
    result = detector.checkEmail(TEST_EMAIL)
    
    print(f"\nQuick result: {result['score']}% - {result['verdict']}")
    
    ask = input("\nRun LIME deep analysis? (y/n): ")
    
    if ask.lower() == 'y':
        print("\nRunning LIME (this takes 1-3 minutes)...")
        explainer = LimeExplainer()
        explanation = explainer.explainEmail(TEST_EMAIL)
        
        print("\n" + "=" * 60)
        print("LIME ANALYSIS")
        print("=" * 60)
        
        # First, show the summary (human-readable)
        print(f"\n{explanation['summary']}")
        
        # 1. RAW WORDS WITH WEIGHTS - what the model actually saw
        print("\n" + "-" * 40)
        print("RAW WORDS FROM MODEL (with weights)")
        print("-" * 40)
        print("Positive weight = pushed toward PHISHING")
        print("Negative weight = pushed toward LEGITIMATE")
        print("Higher number = more influence")
        print()
        
        for word, weight in explanation['rawLime'][:20]: # changes how many words are shown
            if weight > 0:
                arrow = "↑"  # up arrow for phishing
            else:
                arrow = "↓"  # down arrow for legitimate
            print(f"   {word}: {weight:.3f} {arrow}")
        
        # 2. PERSUASION BREAKDOWN - grouped by principle
        if explanation['persuasionBreakdown']:
            print("\n" + "-" * 40)
            print("PERSUASION BREAKDOWN (mapped to principles)")
            print("-" * 40)
            for p, words in explanation['persuasionBreakdown'].items():
                if p != "unknown":
                    word_list = [w['word'] for w in words]
                    print(f"   {p}: {', '.join(word_list)}")
        
        # 3. UNMAPPED IMPORTANT WORDS - not in persuasion map
        if explanation.get('unmappedWords'):
            print("\n" + "-" * 40)
            print("OTHER IMPORTANT WORDS (not in persuasion map)")
            print("-" * 40)
            for word in explanation['unmappedWords'][:5]:
                print(f"   {word}")
        
        # 4. SCORES
        print("\n" + "-" * 40)
        print("SCORES")
        print("-" * 40)
        print(f"   Text score: {explanation['textScore']}%")
        print(f"   URL score: {explanation['urlScore']}%")
    
    print("\nDone")

if __name__ == "__main__":
    test_email()