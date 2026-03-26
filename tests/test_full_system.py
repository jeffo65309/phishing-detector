# Full System Test
# Runs text, URL, and metadata checks together
# Uses the fusion scorer for final verdict

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
#from src.components.fast_explainer import FastExplainer # link to fast explainer (comment other out if not using)
from src.components.lime_explainer import LimeExplainer # link to Lime explainer (comment other out if not using)
from test_data import TEST_EMAIL, TEST_HEADERS

# Redirect stdout to hide loading messages
import contextlib
import io

def test_full_system():
    print("=" * 60)
    print("FULL PHISHING DETECTION SYSTEM")
    print("=" * 60)
    
    # Parse headers
    header_message = BytesParser(policy=policy.default).parsebytes(TEST_HEADERS.encode())
    
    # Get text score and raw words (hide loading messages)
    with contextlib.redirect_stdout(io.StringIO()):
        textChecker = TextChecker()
        textResult = textChecker.checkEmail(TEST_EMAIL)
        
        #explainer = FastExplainer() # link to fast explainer (comment other out if not using)
        explainer = LimeExplainer() # link to Lime explainer (comment other out if not using)
        explanation = explainer.explainEmail(TEST_EMAIL)
    
    # Print the same output as Fast (raw words, persuasion, other words)
    print("\n----------------------------------------")
    print("RAW WORDS FROM MODEL (with weights)")
    print("----------------------------------------")
    print("Positive weight = pushed toward PHISHING")
    print("Negative weight = pushed toward LEGITIMATE")
    print("Higher number = more influence")
    print()
    
    # Filter out technical tokens if you want, or show all
    skip_words = ['[CLS]', ':', '.', ',', ';', '(', ')', '[', ']', '::']
    
    if 'rawWords' in explanation:
        raw_data = explanation['rawWords']
    else:
        raw_data = explanation['rawLime']

    for word, weight in raw_data[:20]:
        if word in skip_words:
            continue
        if weight > 0:
            arrow = "↑"
        else:
            arrow = "↓"
        print(f"   {word}: {weight:.3f} {arrow}")
    
    print("\n----------------------------------------")
    print("PERSUASION BREAKDOWN (mapped to principles)")
    print("----------------------------------------")
    for p, words in explanation['persuasionBreakdown'].items():
        if p != "unknown":
            word_list = [w['word'] for w in words]
            print(f"   {p}: {', '.join(word_list)}")
    
    print("\n----------------------------------------")
    print("OTHER IMPORTANT WORDS (not in persuasion map)")
    print("----------------------------------------")
    for word in explanation.get('unmappedWords', [])[:8]:
        print(f"   {word}")
    
    # Now the full system parts
    print("\n" + "=" * 60)
    print("FULL SYSTEM RESULTS")
    print("=" * 60)
    
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