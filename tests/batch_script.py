# Batch test script
# Runs all emails through our detector to find the best weight settings
# I wrote this to test different combinations of text, URL, and metadata scores

import os
import sys
from email import policy
from email.parser import BytesParser

# Add the src folder so we can import our code
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.components.text_checkerAI import TextChecker
from src.components.url_checker import URLChecker
from src.components.metadata_checker import MetadataChecker

# Silence the loading messages so the output is clean
import contextlib
import io

# These are the different weight combinations I want to test
# Each one gives different importance to text, URL, and metadata
WEIGHT_SETS = [
    {"name": "Balanced", "text": 0.5, "url": 0.3, "meta": 0.2},
    {"name": "Text Heavy", "text": 0.7, "url": 0.2, "meta": 0.1},
    {"name": "URL Heavy", "text": 0.3, "url": 0.5, "meta": 0.2},
    {"name": "Meta Heavy", "text": 0.3, "url": 0.2, "meta": 0.5},
    {"name": "Aggressive", "text": 0.6, "url": 0.3, "meta": 0.3},
]


def split_email(file_content):
    """
    Split an email file into headers and body
    Headers are the lines before the first blank line
    Body is everything after that
    """
    lines = file_content.split('\n')
    
    headers = []
    body = []
    reading_headers = True
    
    for line in lines:
        if reading_headers:
            # Empty line means headers are done
            if line.strip() == "":
                reading_headers = False
            else:
                headers.append(line)
        else:
            body.append(line)
    
    headers_text = '\n'.join(headers)
    body_text = '\n'.join(body)
    
    return headers_text, body_text


def make_email_message(headers_text):
    """
    Turn the headers text into an email message object
    This is what the metadata checker needs
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(headers_text.encode())
        return msg
    except:
        # If parsing fails, just make a simple message
        from email.message import EmailMessage
        msg = EmailMessage()
        # Try to find the From header
        for line in headers_text.split('\n'):
            if line.lower().startswith('from:'):
                msg['From'] = line[5:].strip()
                break
        return msg


def get_scores(body_text, headers_message):
    """
    Run all three checkers on one email
    Returns text score, URL score, and metadata score
    """
    
    # Hide all the loading messages so they don't clutter the output
    with contextlib.redirect_stdout(io.StringIO()):
        # Text analysis
        text_checker = TextChecker()
        text_result = text_checker.checkEmail(body_text)
        
        # URL analysis
        url_checker = URLChecker()
        url_result = url_checker.analyseEmail(body_text)
        
        # Metadata analysis
        meta_checker = MetadataChecker()
        meta_result = meta_checker.analyseEmail(headers_message)
    
    return {
        "text": text_result["score"],
        "url": url_result["score"],
        "meta": meta_result["score"],
        "url_blacklisted": url_result["blacklisted"],
        "sender_spoofed": meta_result["spoofed"]
    }


def run_tests():
    """
    Main function - finds all emails and tests different weight settings
    """
    
    print("=" * 60)
    print("BATCH TESTING - FINDING BEST WEIGHTS")
    print("=" * 60)
    
    # Where are the test emails stored?
    test_folder = os.path.join(os.path.dirname(__file__), "test_emails")
    
    if not os.path.exists(test_folder):
        print("\nError: test_emails folder not found")
        print("Create it and add some .txt email files")
        return
    
    # Collect all emails
    print("\nCollecting emails...")
    print("-" * 40)
    
    all_emails = []
    categories = ["phishing", "legitimate", "custom"]
    
    for cat in categories:
        folder = os.path.join(test_folder, cat)
        if not os.path.exists(folder):
            print(f"  {cat}: folder not found")
            continue
        
        count = 0
        for filename in os.listdir(folder):
            if not filename.endswith(".txt"):
                continue
                
            filepath = os.path.join(folder, filename)
            count += 1
            
            # Read the file
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Split into headers and body
            headers_text, body_text = split_email(content)
            headers_msg = make_email_message(headers_text)
            
            # Get the scores
            scores = get_scores(body_text, headers_msg)
            scores["category"] = cat
            scores["filename"] = filename
            all_emails.append(scores)
        
        print(f"  {cat}: {count} emails found")
    
    if not all_emails:
        print("\nNo emails found. Add some .txt files to the test_emails folder.")
        return
    
    print(f"\nTotal emails collected: {len(all_emails)}")
    
    # Show a sample of the scores
    print("\nSample scores (first 5 emails):")
    print("-" * 50)
    for i, email in enumerate(all_emails[:5]):
        print(f"  {email['filename']} ({email['category']}):")
        print(f"    Text: {email['text']}% | URL: {email['url']}% | Meta: {email['meta']}%")
    
    # Test each weight combination
    print("\n" + "=" * 60)
    print("TESTING WEIGHT COMBINATIONS")
    print("=" * 60)
    
    best_weights = None
    best_accuracy = 0
    best_correct = 0
    best_total = 0
    
    for weights in WEIGHT_SETS:
        print(f"\n{weights['name']}: text={weights['text']}, url={weights['url']}, meta={weights['meta']}")
        
        correct = 0
        total = 0
        false_pos = 0
        false_neg = 0
        suspicious = 0
        
        for email in all_emails:
            # Calculate final score with these weights
            final_score = (
                email["text"] * weights["text"] +
                email["url"] * weights["url"] +
                email["meta"] * weights["meta"]
            )
            
            # Determine the verdict
            if final_score >= 70:
                verdict = "PHISHING"
            elif final_score >= 30:
                verdict = "SUSPICIOUS"
            else:
                verdict = "LEGITIMATE"
            
            # Check if it was correct
            is_phish = (email["category"] == "phishing" or email["category"] == "custom")
            is_legit = (email["category"] == "legitimate")
            
            if is_phish and verdict == "PHISHING":
                correct += 1
            elif is_legit and verdict == "LEGITIMATE":
                correct += 1
            elif is_phish and verdict == "SUSPICIOUS":
                suspicious += 1
            elif is_phish and verdict != "PHISHING" and verdict != "SUSPICIOUS":
                false_neg += 1
            elif is_legit and verdict != "LEGITIMATE":
                false_pos += 1
            
            total += 1
        
        accuracy = (correct / total * 100) if total > 0 else 0
        print(f"  Correct: {correct}/{total} = {accuracy:.1f}%")
        print(f"  Suspicious (partial): {suspicious}")
        print(f"  False positives: {false_pos}")
        print(f"  False negatives: {false_neg}")
        
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_weights = weights
            best_correct = correct
            best_total = total
    
    print("\n" + "=" * 60)
    print("BEST WEIGHTS FOUND")
    print("=" * 60)
    print(f"Weights: text={best_weights['text']}, url={best_weights['url']}, meta={best_weights['meta']}")
    print(f"Accuracy: {best_correct}/{best_total} = {best_accuracy:.1f}%")
    print("\n" + "=" * 60)
    print("Done")
    print("=" * 60)


# Run the tests
if __name__ == "__main__":
    run_tests()