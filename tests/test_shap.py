# SHAP explainer test
# Shows what the AI model actually saw (raw words with weights)
# SHAP is consistent (same result every time) and mathematically rigorous

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.components.shap_explainer import ShapExplainer
from src.core.detector import PhishingDetector
from test_data import TEST_EMAIL

def test_email():
    print("=" * 60)
    print("TESTING SHAP EXPLAINER")
    print("=" * 60)
    
    detector = PhishingDetector()
    result = detector.checkEmail(TEST_EMAIL)
    
    print(f"\nQuick result: {result['score']}% - {result['verdict']}")
    
    ask = input("\nRun SHAP analysis? (y/n): ")
    
    if ask.lower() == 'y':
        print("\nRunning SHAP (this takes 10-30 seconds)...")
        explainer = ShapExplainer()
        explanation = explainer.explainEmail(TEST_EMAIL)
        
        print("\n" + "=" * 60)
        print("SHAP ANALYSIS")
        print("=" * 60)
        
        # First, show the summary
        print(f"\n{explanation['summary']}")
        
        # 1. RAW WORDS WITH WEIGHTS
        print("\n" + "-" * 40)
        print("RAW WORDS FROM MODEL (with weights)")
        print("-" * 40)
        print("Positive weight = pushed toward PHISHING")
        print("Negative weight = pushed toward LEGITIMATE")
        print()
        
        for word, weight in explanation['rawWords'][:20]:
            if weight > 0:
                arrow = "↑"
            else:
                arrow = "↓"
            print(f"   {word}: {weight:.4f} {arrow}")
        
        # 2. PERSUASION BREAKDOWN
        if explanation['persuasionBreakdown']:
            print("\n" + "-" * 40)
            print("PERSUASION BREAKDOWN (mapped to principles)")
            print("-" * 40)
            for p, words in explanation['persuasionBreakdown'].items():
                if p != "unknown":
                    word_list = [w['word'] for w in words]
                    print(f"   {p}: {', '.join(word_list)}")
        
        # 3. UNMAPPED WORDS
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