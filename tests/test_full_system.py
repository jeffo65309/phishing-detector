# Full System Test
# Runs text, URL, and metadata checks together
# Uses the fusion scorer for final verdict
# Lets you choose which explainer to use

import sys
import os
import warnings
from email import policy
from email.parser import BytesParser

# Suppress warnings
warnings.filterwarnings("ignore")

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.components.text_checkerAI import TextChecker
from src.components.url_checker import URLChecker
from src.components.metadata_checker import MetadataChecker
from src.components.scorer import Scorer
from test_data import TEST_EMAIL, TEST_HEADERS

# Import all three explainers
from src.components.fast_explainer import FastExplainer
from src.components.lime_explainer import LimeExplainer
from src.components.shap_explainer import ShapExplainer

# Redirect stdout to hide loading messages
import contextlib
import io

def choose_explainer():
    """Let user choose which explainer to use"""
    print("\n" + "-" * 40)
    print("CHOOSE EXPLAINER:")
    print("1. Fast Explainer (1-2 seconds)")
    print("2. LIME Explainer (1-3 minutes)")
    print("3. SHAP Explainer (30-60 seconds)")
    print("-" * 40)
    
    while True:
        choice = input("Enter 1, 2, or 3: ")
        if choice == "1":
            print("\nUsing Fast Explainer")
            return FastExplainer()
        elif choice == "2":
            print("\nUsing LIME Explainer (this will take 1-3 minutes)")
            return LimeExplainer()
        elif choice == "3":
            print("\nUsing SHAP Explainer (this will take 30-60 seconds)")
            return ShapExplainer()
        else:
            print("Invalid choice. Enter 1, 2, or 3")

def test_full_system():
    print("=" * 60)
    print("FULL PHISHING DETECTION SYSTEM")
    print("=" * 60)
    
    # Let user choose the explainer
    explainer = choose_explainer()
    
    # Parse headers
    header_message = BytesParser(policy=policy.default).parsebytes(TEST_HEADERS.encode())
    
    # Get text score and raw words (hide loading messages)
    with contextlib.redirect_stdout(io.StringIO()):
        textChecker = TextChecker()
        textResult = textChecker.checkEmail(TEST_EMAIL)
        
        explanation = explainer.explainEmail(TEST_EMAIL)
    
    # Print the explainer output (raw words, persuasion, other words)
    print("\n" + "=" * 60)
    print("EXPLAINER OUTPUT")
    print("=" * 60)
    
    print("\n----------------------------------------")
    print("RAW WORDS FROM MODEL (with weights)")
    print("----------------------------------------")
    print("Positive weight = pushed toward PHISHING")
    print("Negative weight = pushed toward LEGITIMATE")
    print("Higher number = more influence")
    print()
    
    # Handle different explainer output formats
    if 'rawWords' in explanation:
        raw_data = explanation['rawWords']
    elif 'rawLime' in explanation:
        raw_data = explanation['rawLime']
    else:
        raw_data = []
    
    # Filter out technical tokens
    skip_words = ['[CLS]', ':', '.', ',', ';', '(', ')', '[', ']', '::']
    
    for item in raw_data[:20]:
        if isinstance(item, tuple):
            word, weight = item
        else:
            continue
            
        if word in skip_words:
            continue
        if weight > 0:
            arrow = "↑"
        else:
            arrow = "↓"
        print(f"   {word}: {weight:.4f} {arrow}")
    
    # Show persuasion breakdown
    if explanation.get('persuasionBreakdown'):
        print("\n----------------------------------------")
        print("PERSUASION BREAKDOWN (mapped to principles)")
        print("----------------------------------------")
        for p, words in explanation['persuasionBreakdown'].items():
            if p != "unknown":
                word_list = [w['word'] for w in words]
                print(f"   {p}: {', '.join(word_list)}")
    
    # Show unmapped words
    if explanation.get('unmappedWords'):
        print("\n----------------------------------------")
        print("OTHER IMPORTANT WORDS (not in persuasion map)")
        print("----------------------------------------")
        for word in explanation['unmappedWords'][:8]:
            print(f"   {word}")
    
    # Now the full system parts
    print("\n" + "=" * 60)
    print("FULL SYSTEM RESULTS")
    print("=" * 60)
    
    # 1. Text score (already have it)
    print("\n1. TEXT ANALYSIS")
    print("-" * 40)
    print(f"   Score: {textResult['score']}%")
    print(f"   Verdict: {textResult['verdict']}")
    
    # 2. URL analysis
    print("\n2. URL ANALYSIS")
    print("-" * 40)
    with contextlib.redirect_stdout(io.StringIO()):
        urlChecker = URLChecker()
        urlResult = urlChecker.analyseEmail(TEST_EMAIL)
    print(f"   Score: {urlResult['score']}%")
    print(f"   URLs found: {len(urlResult['urls_found'])}")
    if urlResult['issues']:
        print(f"   Top issue: {urlResult['issues'][0]}")
    
    # 3. Metadata analysis
    print("\n3. METADATA ANALYSIS")
    print("-" * 40)
    with contextlib.redirect_stdout(io.StringIO()):
        metadataChecker = MetadataChecker()
        metadataResult = metadataChecker.analyseEmail(header_message)
    print(f"   Score: {metadataResult['score']}%")
    print(f"   Spoofed: {metadataResult['spoofed']}")
    print(f"   Sender: {metadataResult['sender']}")
    
    # 4. Fusion
    print("\n4. FUSION LAYER")
    print("-" * 40)
    scorer = Scorer()
    final = scorer.combine(
        textScore=textResult['score'],
        urlScore=urlResult['score'],
        metaScore=metadataResult['score'],
        urlBlacklisted=urlResult['blacklisted'],
        senderSpoofed=metadataResult['spoofed']
    )
    
    print(f"\n   FINAL SCORE: {final['finalScore']}%")
    print(f"   FINAL VERDICT: {final['verdict']}")
    print(f"   REASON: {final['reason']}")
    
    print("\n   Component breakdown:")
    print(f"      Text: {final['components']['text']}%")
    print(f"      URL: {final['components']['url']}%")
    print(f"      Metadata: {final['components']['metadata']}%")
    
    print("\n" + "=" * 60)
    print("Test complete")
    print("=" * 60)

if __name__ == "__main__":
    test_full_system()