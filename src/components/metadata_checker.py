# Metadata Checker
# Checks SPF, DKIM, DMARC to see if the sender is spoofed
# This is based on email authentication standards

import dns.resolver
import dkim
from email import policy
from email.parser import BytesParser
import re
import json
import os

class MetadataChecker:
    
    def __init__(self):
        print("      [MetadataChecker] Setting up...")
        print("      [MetadataChecker] Ready!")
    
    def loadWhitelist(self):
        """Load trusted domains from whitelist.json"""
        config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'whitelist.json')
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                return data.get("trusted_domains", [])
        except Exception as e:
            print(f"[DEBUG] Error loading whitelist: {e}")
            return []
    
    def getSenderInfo(self, email_headers):
        """Extract sender email and domain from email headers"""
        sender_email = ""
        sender_domain = ""
        
        from_header = email_headers.get('From', '')
        if from_header:
            # Handle format like "Name <email@domain.com>"
            match = re.search(r'<(.+?)>', from_header)
            if match:
                sender_email = match.group(1)
            else:
                sender_email = from_header
        
        if '@' in sender_email:
            sender_domain = sender_email.split('@')[-1]
        
        return sender_email, sender_domain
    
    def checkSPF(self, domain):
        """Check if domain has an SPF record"""
        if not domain or domain == "unknown":
            return False, "No domain to check"
        
        try:
            records = dns.resolver.resolve(domain, 'TXT')
            for rdata in records:
                txt = rdata.strings[0].decode('utf-8')
                if txt.startswith('v=spf1'):
                    return True, "SPF record found"
            return False, "No SPF record found"
        except:
            return False, "SPF check failed"
    
    def checkDKIM(self, email_message):
        """Check if email has a valid DKIM signature"""
        try:
            dkim_header = email_message.get('DKIM-Signature', '')
            if not dkim_header:
                return False, "No DKIM signature"
            
            email_bytes = email_message.as_bytes()
            if dkim.verify(email_bytes):
                return True, "DKIM signature valid"
            else:
                return False, "DKIM signature invalid"
        except:
            return False, "DKIM check failed"
    
    def checkDKIM_raw(self, raw_bytes):
        """Verify DKIM using original raw email bytes"""
        try:
            if dkim.verify(raw_bytes):
                return True, "DKIM signature valid"
            else:
                return False, "DKIM signature invalid"
        except Exception as e:
            return False, f"DKIM check failed: {str(e)[:50]}"
    
    def checkDMARC(self, domain):
        """Check DMARC policy for the domain"""
        if not domain or domain == "unknown":
            return "none", "No domain to check"
        
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                record = rdata.strings[0].decode('utf-8')
                if 'p=reject' in record:
                    return "reject", "Domain has strict DMARC policy (reject)"
                elif 'p=quarantine' in record:
                    return "quarantine", "Domain recommends quarantining failures"
            return "none", "No DMARC policy found"
        except:
            return "none", "No DMARC record found"
    
    def analyseEmail(self, email_headers, raw_bytes=None):
        """Main function - analyse email headers and return score"""
        score = 0
        issues = []
        spoofed = False
        
        sender_email, sender_domain = self.getSenderInfo(email_headers)
        
        # Load whitelist to check later
        trusted_domains = self.loadWhitelist()
        is_whitelisted = sender_domain in trusted_domains
        
        if not sender_domain:
            return {
                "score": 50,
                "spoofed": True,
                "issues": ["Could not extract sender"],
                "summary": "Unable to verify sender"
            }
        
        # Check SPF
        spf_ok, spf_msg = self.checkSPF(sender_domain)
        if spf_ok:
            issues.append(f"[OK] {spf_msg}")
        else:
            score += 30
            issues.append(f"[FAIL] {spf_msg}")
            spoofed = True
        
        # Check DKIM using raw bytes if available
        if raw_bytes:
            dkim_ok, dkim_msg = self.checkDKIM_raw(raw_bytes)
        else:
            dkim_ok, dkim_msg = self.checkDKIM(email_headers)
        
        if dkim_ok:
            issues.append(f"[OK] {dkim_msg}")
        else:
            score += 40
            issues.append(f"[FAIL] {dkim_msg}")
            spoofed = True
        
        # Check DMARC
        dmarc_policy, dmarc_msg = self.checkDMARC(sender_domain)
        issues.append(f"[INFO] {dmarc_msg}")
        
        # Apply whitelist override
        if is_whitelisted:
            warning_msg = ""
            failed_checks = []
            if not spf_ok:
                failed_checks.append("SPF")
            if not dkim_ok:
                failed_checks.append("DKIM")
            
            if failed_checks:
                warning_msg = f"Authentication failed ({', '.join(failed_checks)}) but domain is whitelisted"
            
            return {
                "score": 0,
                "spoofed": False,
                "warning": warning_msg,
                "issues": issues + ["[INFO] Whitelisted domain - authentication failures overridden"],
                "summary": "Whitelisted domain (authentication failed but trusted)",
                "sender": sender_email,
                "domain": sender_domain
            }
        
        if spoofed:
            summary = "Sender authentication failed - likely spoofed"
        else:
            summary = "Sender appears legitimate"
        
        return {
            "score": min(score, 100),
            "spoofed": spoofed,
            "issues": issues,
            "summary": summary,
            "sender": sender_email,
            "domain": sender_domain
        }