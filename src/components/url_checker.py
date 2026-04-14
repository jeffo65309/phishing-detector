# URL Checker
# Looks for suspicious links in emails
# I built this myself - checks URL patterns, no external APIs needed

import re
import requests
from urllib.parse import urlparse, unquote, parse_qs

class URLChecker:
    
    def __init__(self):
        # Set up the patterns I look for in URLs
        print("      [URLChecker] Setting up...")
        
        # Words that often appear in phishing URLs
        # Real companies don't usually put these in their domain names
        self.suspicious_words = [
            "secure", "verify", "update", "confirm", "login",
            "signin", "account", "banking", "alert", "warning",
            "validate", "authenticate", "unlock", "restore",
            "paypal", "amazon", "apple", "microsoft", "bank"
        ]
        
        # URL shorteners - phishers use these to hide where links really go
        self.shortener_domains = [
            "bit.ly", "tinyurl.com", "ow.ly", "is.gd",
            "buff.ly", "short.url", "goo.gl", "t.co",
            "tiny.cc", "tr.im", "shortlink"
        ]
        
        # Suspicious TLDs commonly used in phishing
        self.suspicious_tlds = [
            ".shop", ".xyz", ".top", ".club", ".online", 
            ".live", ".site", ".work", ".rent", ".monster", 
            ".guru", ".life", ".beauty", ".click", ".win",
            ".bid", ".date", ".download", ".review", ".trade", 
            ".fit", ".lat", ".world" 
        ]
        
        # Safe domains that should not be penalized
        self.safe_domains = [
            "safelinks.protection.outlook.com",
            "click.email.microsoft.com",
            "links.aws.amazon.com"
        ]
        
        print("      [URLChecker] Ready!")
    
    def decode_safelink(self, url):
        """Extract the real URL from Microsoft safelinks and similar services"""
        try:
            # Check for Microsoft safelinks
            if "safelinks.protection.outlook.com" in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if 'url' in params:
                    real_url = unquote(params['url'][0])
                    return real_url
            
            # Check for other redirect services (add more as needed)
            if "click.email.microsoft.com" in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if 'u' in params:
                    real_url = unquote(params['u'][0])
                    return real_url
            
            return url
        except:
            return url
    
    def extractURLs(self, text):
        # Find every web link in the email text
        # This regex looks for http:// or https://
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        return urls
    
    def getDomain(self, url):
        # Get the main domain from a URL
        # Example: https://www.paypal.com/login -> paypal.com
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove www. if it's there
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except:
            return "unknown"
    
    def is_safe_domain(self, domain):
        """Check if the domain is in the safe list"""
        for safe in self.safe_domains:
            if safe in domain:
                return True
        return False
    
    def check_suspicious_tld(self, url_lower):
        """Check if URL has a suspicious TLD"""
        for tld in self.suspicious_tlds:
            if tld in url_lower:
                return True, tld
        return False, None
    
    def checkOneURL(self, url):
        # Look at one URL and give it a suspicion score
        # Higher score = more likely to be phishing
        
        # Debug to file
        with open('url_debug.txt', 'a') as f:
            f.write(f"\n[DEBUG] Original URL: {url}\n")
        
        # Store original for return
        original_url = url
        was_safelink = False  # Flag to track if this was a safelink
        
        # Decode safelink once
        decoded = self.decode_safelink(url)
        if decoded != url:
            with open('url_debug.txt', 'a') as f:
                f.write(f"[DEBUG] Decoded URL: {decoded}\n")
            url = decoded
            was_safelink = True  # Mark that this was a safelink
        
        score = 0
        issues = []
        url_lower = url.lower()
        
        # Check 1: Is it a URL shortener?
        for shortener in self.shortener_domains:
            if shortener in url_lower:
                score += 30
                issues.append(f"Uses URL shortener ({shortener}) - hides real destination")
                break
        
        # Check 2: Does it have suspicious words?
        found_words = []
        for word in self.suspicious_words:
            if word in url_lower:
                found_words.append(word)
        
        if found_words:
            score += 20
            words_text = ', '.join(found_words[:3])
            issues.append(f"Contains suspicious words: {words_text}")
        
        # Check 3: Is it an IP address instead of a domain?
        ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            score += 40
            issues.append("Uses IP address instead of domain name - very suspicious")
        
        # Check 4: Is the URL very long?
        if len(url) > 100:
            score += 10
            issues.append("Unusually long URL")
        
        # Check 5: Does it have a suspicious TLD?
        has_suspicious_tld, tld = self.check_suspicious_tld(url_lower)
        if has_suspicious_tld:
            with open('url_debug.txt', 'a') as f:
                f.write(f"[DEBUG] Suspicious TLD found: {tld} for URL: {url}\n")
            score += 40
            issues.append(f"Suspicious domain extension ({tld}) - common in phishing")
        
        # Added Safelink bonus only if the decoded URL was suspicious
        # This gives a small boost when phishers hide behind safelinks
        if was_safelink and len(issues) > 0:
            score += 15
            issues.append("URL hidden behind Microsoft Safelinks - verify the real destination")
            with open('url_debug.txt', 'a') as f:
                f.write(f"[DEBUG] Safelink bonus applied (+15) because decoded URL had issues\n")
        
        # Check 6: Is it in URLhaus database? (free threat feed)
        # This is optional - might be slow, but catches known bad sites
        # in_urlhaus, msg = self.checkURLhaus(url)
        # if in_urlhaus:
        #     score += 50
        #     issues.append(msg)
        
        if score > 100:
            score = 100
        
        domain = self.getDomain(url)
        
        return {
            "url": original_url,
            "decoded_url": url if url != original_url else None,
            "domain": domain,
            "score": score,
            "issues": issues
        }
    
    def checkURLhaus(self, url):
        # Check if URL is in URLhaus database (free, no API key)
        # Run by abuse.ch - tracks malware and phishing URLs
        try:
            response = requests.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': url},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'url_known':
                    threat = data.get('threat', 'malicious')
                    return True, f"Found in URLhaus ({threat})"
        except:
            pass
        return False, "Not found"
    
    def analyseEmail(self, email_text):
        # Main function - call this to check all URLs in an email
        
        # First, find all the URLs
        urls = self.extractURLs(email_text)
        
        if not urls:
            return {
                "has_urls": False,
                "urls_found": [],
                "issues": [],
                "summary": "No links found",
                "score": 0,
                "blacklisted": False
            }
        
        # Check each URL
        all_issues = []
        total_score = 0
        checked_urls = []
        
        for url in urls:
            result = self.checkOneURL(url)
            checked_urls.append(result)
            total_score += result["score"]
            for issue in result["issues"]:
                if issue not in all_issues:
                    all_issues.append(issue)
        
        # Average score across all URLs
        avg_score = total_score / len(urls)
        
        # Check if any URL is blacklisted
        blacklisted = False
        for result in checked_urls:
            for issue in result["issues"]:
                if "URLhaus" in issue:
                    blacklisted = True
                    break
            if blacklisted:
                break
        
        # Summary based on score
        if avg_score >= 70:
            summary = f"Found {len(urls)} link(s) - high risk"
        elif avg_score >= 30:
            summary = f"Found {len(urls)} link(s) - some suspicious patterns"
        else:
            summary = f"Found {len(urls)} link(s) - looks ok"
        
        return {
            "has_urls": True,
            "urls_found": urls,
            "checked_urls": checked_urls,
            "issues": all_issues[:5],
            "summary": summary,
            "score": round(avg_score, 1),
            "blacklisted": blacklisted
        }