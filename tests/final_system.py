# Final Phishing Detection System
# First it does a fast check and shows the result
# Then asks if you want a detailed explanation

import sys
import os
import warnings
from email import policy
from email.parser import BytesParser

# Turn off warnings to keep output clean
warnings.filterwarnings("ignore")

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.components.text_checkerAI import TextChecker
from src.components.url_checker import URLChecker
from src.components.metadata_checker import MetadataChecker
from src.components.scorer import Scorer
from src.components.shap_explainer import ShapExplainer
from test_data import TEST_EMAIL, TEST_HEADERS

# Hide all the loading messages
import contextlib
import io

def run_fast_check(email_text, email_headers):
    """Run the fast detection - no explainer, just the scores"""
    
    with contextlib.redirect_stdout(io.StringIO()):
        textChecker = TextChecker()
        textResult = textChecker.checkEmail(email_text)
        
        urlChecker = URLChecker()
        urlResult = urlChecker.analyseEmail(email_text)
        
        metadataChecker = MetadataChecker()
        metadataResult = metadataChecker.analyseEmail(email_headers)
    
    return {
        "textScore": textResult["score"],
        "textVerdict": textResult["verdict"],
        "urlScore": urlResult["score"],
        "urlIssues": urlResult["issues"],
        "metaScore": metadataResult["score"],
        "spoofed": metadataResult["spoofed"],
        "sender": metadataResult["sender"],
        "urlBlacklisted": urlResult["blacklisted"]
    }

def run_shap_detail(email_text):
    """Run SHAP for detailed word explanation"""
    print("\nRunning detailed analysis...")
    print("This takes 30-60 seconds...")
    
    with contextlib.redirect_stdout(io.StringIO()):
        explainer = ShapExplainer()
        explanation = explainer.explainEmail(email_text)
    
    return explanation

def show_results(scores):
    """Show the fast detection results"""
    print("\n" + "=" * 50)
    print("DETECTION RESULTS")
    print("=" * 50)
    
    print("\nScores:")
    print("  Text score: " + str(scores['textScore']) + "% (" + scores['textVerdict'] + ")")
    print("  URL score:  " + str(scores['urlScore']) + "%")
    print("  Metadata:   " + str(scores['metaScore']) + "%")
    
    if scores['spoofed']:
        print("\nWarning: Sender appears to be spoofed - " + scores['sender'])
    
    if scores['urlIssues']:
        print("\nURL issues found:")
        for issue in scores['urlIssues'][:2]:
            print("  - " + issue)
    
    # Calculate final score
    scorer = Scorer()
    final = scorer.combine(
        textScore=scores['textScore'],
        urlScore=scores['urlScore'],
        metaScore=scores['metaScore'],
        urlBlacklisted=scores['urlBlacklisted'],
        senderSpoofed=scores['spoofed']
    )
    
    print("\nFinal verdict: " + final['verdict'])
    print("Confidence: " + str(final['finalScore']) + "%")
    print("Reason: " + final['reason'])

def show_shap_results(explanation):
    """Show SHAP detailed explanation"""
    print("\n" + "=" * 50)
    print("DETAILED EXPLANATION")
    print("=" * 50)
    
    # Summary
    print("\n" + explanation['summary'])
    
    # Top words
    print("\nTop words that influenced the decision:")
    print("  Positive weight = pushed toward phishing")
    print("  Negative weight = pushed toward legitimate")
    print()
    
    for word, weight in explanation['rawWords'][:10]:
        if weight > 0:
            direction = "phishing"
        else:
            direction = "legitimate"
        print("  " + word + ": " + str(weight)[:6] + " (" + direction + ")")
    
    # Persuasion breakdown
    if explanation.get('persuasionBreakdown'):
        print("\nPersuasion techniques found:")
        for principle, words in explanation['persuasionBreakdown'].items():
            if principle != "unknown" and principle != "phishing_context":
                word_list = []
                for w in words[:3]:
                    word_list.append(w['word'])
                print("  " + principle + ": " + ", ".join(word_list))
    
    # Unmapped words
    if explanation.get('unmappedWords'):
        print("\nOther important words found:")
        for word in explanation['unmappedWords'][:5]:
            print("  " + word)

def final_system():
    """Main function"""
    
    print("=" * 50)
    print("PHISHING DETECTION SYSTEM")
    print("=" * 50)
    
    # Parse headers
    header_message = BytesParser(policy=policy.default).parsebytes(TEST_HEADERS.encode())
    
    # Step 1: Fast check
    print("\nAnalysing email...")
    scores = run_fast_check(TEST_EMAIL, header_message)
    
    # Step 2: Show results
    show_results(scores)
    
    # Step 3: Ask about detailed explanation
    print("\n" + "-" * 40)
    ask = input("Do you want a detailed explanation? (y/n): ")
    
    if ask.lower() == 'y':
        explanation = run_shap_detail(TEST_EMAIL)
        show_shap_results(explanation)
    else:
        print("\nOK. Run again with 'y' to see detailed explanation.")
    
    print("\n" + "=" * 50)
    print("Done")
    print("=" * 50)

if __name__ == "__main__":
    final_system()