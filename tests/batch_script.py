"""
Test Runner - Goes through all test emails and records results
Run this to see how well your system is performing
"""

import os
import sys
import datetime
from email import policy
from email.parser import BytesParser

# Add parent folder to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.components.text_checkerAI import TextChecker
from src.components.url_checker import URLChecker
from src.components.metadata_checker import MetadataChecker
from src.components.scorer import Scorer

# Hide loading messages
import contextlib
import io

def test_one_email(email_text, email_headers, expected_type, filename):
    """
    Test a single email and return the results
    """
    
    with contextlib.redirect_stdout(io.StringIO()):
        textChecker = TextChecker()
        textResult = textChecker.checkEmail(email_text)
        
        urlChecker = URLChecker()
        urlResult = urlChecker.analyseEmail(email_text)
        
        metadataChecker = MetadataChecker()
        metadataResult = metadataChecker.analyseEmail(email_headers)
    
    # Get sender domain for scorer
    sender_domain = metadataResult.get('domain', '')
    if '@' in sender_domain:
        sender_domain = sender_domain.split('@')[-1]
    
    # Calculate final score
    scorer = Scorer()
    final = scorer.combine(
        textScore=textResult["score"],
        urlScore=urlResult["score"],
        metaScore=metadataResult["score"],
        urlBlacklisted=urlResult["blacklisted"],
        senderSpoofed=metadataResult["spoofed"],
        sender_domain=sender_domain
    )
    
    # Determine if correct
    if expected_type == "PHISHING":
        correct = (final["verdict"] == "PHISHING")
    else:
        correct = (final["verdict"] != "PHISHING")
    
    return {
        "filename": filename,
        "expected": expected_type,
        "verdict": final["verdict"],
        "final_score": final["finalScore"],
        "text_score": textResult["score"],
        "url_score": urlResult["score"],
        "meta_score": metadataResult["score"],
        "spoofed": metadataResult["spoofed"],
        "correct": correct
    }


def parse_email_file(filepath):
    """
    Read an email file and split into headers and body
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.split('\n')
    headers = []
    body = []
    in_headers = True
    
    for line in lines:
        if in_headers:
            if line.strip() == "":
                in_headers = False
            else:
                headers.append(line)
        else:
            body.append(line)
    
    headers_text = '\n'.join(headers)
    body_text = '\n'.join(body)
    
    # Parse headers into email message object
    try:
        msg = BytesParser(policy=policy.default).parsebytes(headers_text.encode())
    except:
        from email.message import EmailMessage
        msg = EmailMessage()
        for line in headers:
            if line.lower().startswith('from:'):
                msg['From'] = line[5:].strip()
    
    return body_text, msg


def run_all_tests():
    """
    Run all emails in the test_emails folder
    """
    
    test_dir = os.path.join(os.path.dirname(__file__), "test_emails")
    
    if not os.path.exists(test_dir):
        print(f"Error: {test_dir} not found")
        print("Create it and add some .txt email files")
        return []
    
    all_results = []
    
    # Test phishing emails
    phishing_folder = os.path.join(test_dir, "phishing")
    if os.path.exists(phishing_folder):
        for filename in os.listdir(phishing_folder):
            if filename.endswith(".txt"):
                filepath = os.path.join(phishing_folder, filename)
                print(f"Testing phishing email: {filename}")
                body, headers = parse_email_file(filepath)
                result = test_one_email(body, headers, "PHISHING", filename)
                all_results.append(result)
    else:
        print(f"Warning: {phishing_folder} not found")
    
    # Test legitimate emails
    legit_folder = os.path.join(test_dir, "legitimate")
    if os.path.exists(legit_folder):
        for filename in os.listdir(legit_folder):
            if filename.endswith(".txt"):
                filepath = os.path.join(legit_folder, filename)
                print(f"Testing legitimate email: {filename}")
                body, headers = parse_email_file(filepath)
                result = test_one_email(body, headers, "LEGITIMATE", filename)
                all_results.append(result)
    else:
        print(f"Warning: {legit_folder} not found")
    
    return all_results


def print_results(results):
    """
    Print formatted results to screen
    """
    
    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)
    print(f"Run at: {datetime.datetime.now()}")
    print("=" * 70)
    
    correct_count = 0
    false_positives = 0
    false_negatives = 0
    
    for r in results:
        if r["correct"]:
            correct_count += 1
            status = "PASS"
        else:
            status = "FAIL"
            if r["expected"] == "PHISHING":
                false_negatives += 1
            else:
                false_positives += 1
        
        print(f"\n{status} | {r['filename']}")
        print(f"  Expected: {r['expected']} | Got: {r['verdict']}")
        print(f"  Scores: Text={r['text_score']}% URL={r['url_score']}% Meta={r['meta_score']}% Final={r['final_score']}%")
        if r['spoofed']:
            print(f"  [Spoofed sender detected]")
    
    # Summary
    total = len(results)
    accuracy = (correct_count / total * 100) if total > 0 else 0
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total emails tested: {total}")
    print(f"Correct: {correct_count}")
    print(f"Accuracy: {accuracy:.1f}%")
    print(f"False positives: {false_positives} (legitimate flagged as phishing)")
    print(f"False negatives: {false_negatives} (phishing missed)")
    print("=" * 70)


def save_results_to_file(results, filename="test_results.txt"):
    """
    Save results to a text file
    """
    with open(filename, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("PHISHING DETECTOR TEST RESULTS\n")
        f.write("=" * 70 + "\n")
        f.write(f"Run at: {datetime.datetime.now()}\n")
        f.write("=" * 70 + "\n\n")
        
        for r in results:
            status = "PASS" if r["correct"] else "FAIL"
            f.write(f"{status} | {r['filename']}\n")
            f.write(f"  Expected: {r['expected']} | Got: {r['verdict']}\n")
            f.write(f"  Scores: Text={r['text_score']}% URL={r['url_score']}% Meta={r['meta_score']}% Final={r['final_score']}%\n")
            if r['spoofed']:
                f.write(f"  [Spoofed sender detected]\n")
            f.write("\n")
        
        correct = sum(1 for r in results if r["correct"])
        total = len(results)
        accuracy = (correct / total * 100) if total > 0 else 0
        
        f.write("=" * 70 + "\n")
        f.write("SUMMARY\n")
        f.write("=" * 70 + "\n")
        f.write(f"Total emails tested: {total}\n")
        f.write(f"Correct: {correct}\n")
        f.write(f"Accuracy: {accuracy:.1f}%\n")
        f.write("=" * 70 + "\n")
    
    print(f"\nResults saved to {filename}")


# Main
if __name__ == "__main__":
    print("=" * 70)
    print("PHISHING DETECTOR TEST SUITE")
    print("=" * 70)
    print()
    
    results = run_all_tests()
    
    if results:
        print_results(results)
        save_results_to_file(results)
    else:
        print("No tests were run. Make sure you have email files in:")
        print("  tests/test_emails/phishing/")
        print("  tests/test_emails/legitimate/")