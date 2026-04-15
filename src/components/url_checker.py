# URL Checker
# Looks for suspicious links in emails
# I built this myself - checks URL patterns, no external APIs needed

import re
import requests
import base64
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
            ".fit", ".lat", ".world", ".co"
        ]
        
        # Legitimate multi-part TLDs (these should NEVER be flagged as suspicious)
        self.legitimate_tlds = [
            ".co.uk", ".org.uk", ".ac.uk", ".gov.uk",
            ".co.nz", ".org.nz", ".ac.nz", ".govt.nz",
            ".com.au", ".org.au", ".net.au", ".edu.au",
            ".co.jp", ".or.jp", ".ne.jp",
            ".com.br", ".org.br", ".edu.br",
            ".co.za", ".org.za",
            ".com.mx", ".org.mx",
            ".co.il", ".org.il",
            ".com.sg", ".org.sg"
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
    
    def decode_base64_urls(self, url):
        """Extract and decode base64 encoded URLs hidden in fragments or parameters"""
        decoded_urls = []
        
        # Patterns to look for base64 encoded strings
        base64_patterns = [
            r'#([A-Za-z0-9+/=]{20,})',           # After #
            r'[?&]data=([A-Za-z0-9+/=]{20,})',   # data= parameter
            r'[?&]url=([A-Za-z0-9+/=]{20,})',    # url= parameter
            r'[?&]redirect=([A-Za-z0-9+/=]{20,})', # redirect= parameter
            r'[?&]return=([A-Za-z0-9+/=]{20,})',  # return= parameter
        ]
        
        for pattern in base64_patterns:
            matches = re.findall(pattern, url)
            for encoded in matches:
                try:
                    # Add padding if needed
                    padding = 4 - (len(encoded) % 4)
                    if padding != 4:
                        encoded += '=' * padding
                    
                    decoded = base64.b64decode(encoded).decode('utf-8')
                    # Check if decoded looks like a URL
                    if 'http' in decoded or 'www' in decoded or '.' in decoded:
                        decoded_urls.append(decoded)
                except:
                    pass
        
        return decoded_urls
    
    def extractURLs(self, text):
        # Find every web link in the email text
        # This regex looks for http:// or https://
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        # Also look for URLs without protocol (starting with www.)
        www_pattern = r'www\.[^\s<>"{}|\\^`\[\]]+'
        www_urls = re.findall(www_pattern, text)
        for url in www_urls:
            urls.append('https://' + url)
        
        # Also look for shortened URLs without protocol (bit.ly, tinyurl, etc.)
        shortener_pattern = r'(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd)/[^\s<>"{}|\\^`\[\]]+'
        short_urls = re.findall(shortener_pattern, text)
        for url in short_urls:
            if not url.startswith('http'):
                urls.append('https://' + url)
        
        # Also look for markdown links [text](url)
        markdown_pattern = r'\]\((https?://[^\)]+)\)'
        markdown_urls = re.findall(markdown_pattern, text)
        urls.extend(markdown_urls)
        
        # Clean up trailing punctuation and extra text from URLs
        cleaned_urls = []
        for url in urls:
            # Remove trailing punctuation
            url = re.sub(r'[.,;:!?)\]>,]+$', '', url)
            # Remove common extra text like ",then" or ".after" that got attached
            url = re.sub(r'(,then|\.after|\.com\w+)$', '', url)
            cleaned_urls.append(url)
        
        # Remove duplicates
        return list(set(cleaned_urls))
    
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
    
    def get_tld_from_domain(self, domain):
        """Extract the TLD from a domain, handling multi-part TLDs like .co.nz"""
        domain_parts = domain.split('.')
        
        # Check for legitimate multi-part TLDs first (longest match)
        for i in range(len(domain_parts) - 1, 0, -1):
            possible_tld = '.' + '.'.join(domain_parts[i-1:])
            if possible_tld in self.legitimate_tlds:
                return possible_tld, True  # Legitimate multi-part TLD
        
        # Check for suspicious multi-part TLDs (like .shop.xyz - unlikely)
        for i in range(len(domain_parts) - 1, 0, -1):
            possible_tld = '.' + '.'.join(domain_parts[i-1:])
            if possible_tld in self.suspicious_tlds:
                return possible_tld, False  # Suspicious multi-part TLD
        
        # Default: just the last part
        if len(domain_parts) >= 1:
            return '.' + domain_parts[-1], False
        return '', False
    
    def check_suspicious_tld(self, url_lower):
        """Check if URL has a suspicious TLD (handles multi-part TLDs properly)"""
        
        # First, extract the domain properly
        try:
            # Handle URLs with or without protocol
            if '://' in url_lower:
                parsed = urlparse(url_lower)
                domain = parsed.netloc
            else:
                # For URLs without protocol (like www.example.com)
                domain = url_lower.split('/')[0]
            
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
        except:
            domain = url_lower.split('/')[0]
            if domain.startswith('www.'):
                domain = domain[4:]
        
        # Get the TLD (handles multi-part like .co.nz)
        tld, is_legitimate = self.get_tld_from_domain(domain)
        
        # If it's a legitimate multi-part TLD, don't flag it
        if is_legitimate:
            return False, None
        
        # Check if the TLD is in suspicious list
        for suspicious_tld in self.suspicious_tlds:
            if tld == suspicious_tld:
                return True, tld
        
        return False, None
    
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
    
    def check_url_reputation(self, url):
        """Check URL against free threat intelligence APIs"""
        
        # Try URLhaus first
        try:
            response = requests.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': url},
                timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'url_known':
                    return {
                        "malicious": True,
                        "safe": False,
                        "source": "URLhaus",
                        "details": data.get('threat', 'malicious')
                    }
        except:
            pass
        
        # Try IPQualityScore free endpoint
        try:
            response = requests.get(
                f"https://ipqualityscore.com/api/json/url/free/{url}",
                timeout=3
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('phishing') == True or data.get('malware') == True:
                    return {
                        "malicious": True,
                        "safe": False,
                        "source": "IPQualityScore",
                        "details": f"phishing={data.get('phishing')}, malware={data.get('malware')}"
                    }
                if data.get('risk_score', 0) < 30 and data.get('unsafe', False) == False:
                    return {
                        "malicious": False,
                        "safe": True,
                        "source": "IPQualityScore",
                        "details": f"risk_score={data.get('risk_score')}"
                    }
        except:
            pass
        
        # Default: unknown - don't override
        return {
            "malicious": False,
            "safe": False,
            "source": "unknown",
            "details": "Could not verify"
        }
    
    def checkOneURL(self, url):
        # Look at one URL and give it a suspicion score
        # Higher score = more likely to be phishing
        
        # Store original for return
        original_url = url
        was_safelink = False  # Flag to track if this was a safelink
        
        # Decode safelink once
        decoded = self.decode_safelink(url)
        if decoded != url:
            url = decoded
            was_safelink = True  # Mark that this was a safelink
        
        score = 0
        issues = []
        url_lower = url.lower()
        
        # NEW: Check for base64 encoded URLs hidden in fragments
        base64_decoded = self.decode_base64_urls(url)
        if base64_decoded:
            for decoded_url in base64_decoded:
                score += 40
                issues.append(f"Base64 encoded malicious URL detected: {decoded_url[:80]}...")
                # Also check the decoded URL for suspicious patterns
                decoded_lower = decoded_url.lower()
                has_suspicious_tld, tld = self.check_suspicious_tld(decoded_lower)
                if has_suspicious_tld:
                    score += 20
                    issues.append(f"Decoded URL has suspicious TLD ({tld})")
                # Check for suspicious words in decoded URL
                found_words = []
                for word in self.suspicious_words:
                    if word in decoded_lower:
                        found_words.append(word)
                if found_words:
                    score += 10
                    issues.append(f"Decoded URL contains suspicious words: {', '.join(found_words[:2])}")
        
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
        
        # Check 5: Does it have a suspicious TLD? (UPDATED to handle multi-part TLDs)
        has_suspicious_tld, tld = self.check_suspicious_tld(url_lower)
        if has_suspicious_tld:
            score += 40
            issues.append(f"Suspicious domain extension ({tld}) - common in phishing")
        
        # NEW: Check for random-looking subdomains (common in phishing)
        # Looks for patterns like q5bju9815i8yur8 (random letters/numbers)
        # Extract the full domain (remove protocol and path)
        domain_match = re.search(r'://([^/]+)', url_lower)
        if domain_match:
            full_domain = domain_match.group(1)
            parts = full_domain.split('.')
            
            # If there are 3+ parts, check the first part (subdomain)
            if len(parts) >= 3:
                subdomain = parts[0]
                # Check if subdomain looks random:
                # - Contains mix of letters and numbers
                # - Length > 6
                # - No recognizable words
                has_mixed = re.search(r'[a-z]+\d+[a-z]+', subdomain) or re.search(r'\d+[a-z]+\d+', subdomain)
                is_long = len(subdomain) > 6
                
                if has_mixed and is_long:
                    score += 35
                    issues.append(f"Suspicious random subdomain: '{subdomain}' - phishers use random strings to bypass filters")
        
        # FIXED: Check Safelink - only penalize if decoded domain is NOT whitelisted
        if was_safelink:
            # Get decoded domain to check if it's trusted
            decoded_domain = self.getDomain(decoded) if decoded != original_url else ""
            is_trusted_safelink = False
            
            # Check if decoded domain is whitelisted (Halfords, etc.)
            if decoded_domain and decoded_domain != "unknown":
                try:
                    import json
                    import os
                    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'whitelist.json')
                    with open(config_path, 'r') as f:
                        data = json.load(f)
                        trusted_domains = data.get("trusted_domains", [])
                        
                        # Check direct or parent domain
                        if decoded_domain in trusted_domains:
                            is_trusted_safelink = True
                        else:
                            parts = decoded_domain.split('.')
                            for i in range(1, len(parts)):
                                if '.'.join(parts[i:]) in trusted_domains:
                                    is_trusted_safelink = True
                                    break
                except:
                    pass
            
            # Only penalize Safelinks that go to untrusted domains
            if not is_trusted_safelink and len(issues) > 0:
                score += 15
                issues.append("URL hidden behind Microsoft Safelinks - verify the real destination")
            elif is_trusted_safelink:
                issues.append("[INFO] Microsoft Safelink to trusted domain")
        
        # Check 6: Is it in URLhaus database? (free threat feed) can disable if slow
        in_urlhaus, msg = self.checkURLhaus(url)
        if in_urlhaus:
            score += 50
            issues.append(msg)
        
        # Check reputation using APIs
        reputation = self.check_url_reputation(url)
        if reputation["malicious"]:
            score = 100
            issues.append(f"[BLOCKED] {reputation['source']}: {reputation['details']}")
        elif reputation["safe"] and score > 30:
            # Safe URL overrides suspicion - reduce score
            score = max(score - 30, 0)
            issues.append(f"[SAFE] {reputation['source']} verified this link")
        
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
                "blacklisted": False,
                "urls_safe": False
            }
        
        # Check each URL
        all_issues = []
        total_score = 0
        checked_urls = []
        any_url_safe = False
        
        for url in urls:
            result = self.checkOneURL(url)
            checked_urls.append(result)
            total_score += result["score"]
            for issue in result["issues"]:
                if issue not in all_issues:
                    all_issues.append(issue)
                if "[SAFE]" in issue:
                    any_url_safe = True
        
        # Average score across all URLs
        avg_score = total_score / len(urls)
        
        # Check if any URL is blacklisted
        blacklisted = False
        for result in checked_urls:
            for issue in result["issues"]:
                if "URLhaus" in issue or "[BLOCKED]" in issue:
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
            "blacklisted": blacklisted,
            "urls_safe": any_url_safe
        }