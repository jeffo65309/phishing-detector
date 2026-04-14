# Phishing Detection GUI
# Paste an email, click analyse, and see if it's phishing

import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import sys
import os
import threading
from email import policy
from email.parser import BytesParser
import re

# Add parent folder to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.components.text_checkerAI import TextChecker
from src.components.url_checker import URLChecker
from src.components.metadata_checker import MetadataChecker
from src.components.scorer import Scorer
from src.components.shap_explainer import ShapExplainer

# Hide loading messages
import contextlib
import io


class PhishingDetectorGUI:
    def __init__(self, root):
        self.root = root
        root.title("Phishing Email Detector")
        root.geometry("800x700")
        
        # Colours for the interface
        self.bg_colour = '#f0f0f0'
        self.button_colour = '#4CAF50'
        self.button_text_colour = 'white'
        self.input_bg = '#ffffcc'
        self.results_bg = '#ffffff'
        self.results_fg = '#333333'
        self.status_bg = '#e0e0e0'
        
        root.configure(bg=self.bg_colour)
        
        # Email input box
        tk.Label(root, text="Paste Email Here:", font=("Arial", 12, "bold"), 
                 bg=self.bg_colour).pack(pady=(10,5))
        
        self.email_text = scrolledtext.ScrolledText(root, height=15, width=90, 
                                                     font=("Courier", 10),
                                                     bg=self.input_bg)
        self.email_text.pack(pady=5, padx=10)
        
        # Buttons
        button_frame = tk.Frame(root, bg=self.bg_colour)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Load from File", command=self.load_file, 
                  width=15, bg=self.button_colour, fg=self.button_text_colour,
                  font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Analyse Email", command=self.analyse_email, 
                  width=15, bg=self.button_colour, fg=self.button_text_colour,
                  font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(button_frame, text="Clear", command=self.clear_text, 
                  width=10, bg=self.button_colour, fg=self.button_text_colour,
                  font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        
        # Results area
        tk.Label(root, text="Results:", font=("Arial", 12, "bold"), 
                 bg=self.bg_colour).pack(pady=(10,5))
        
        self.results_text = scrolledtext.ScrolledText(root, height=12, width=90, 
                                                       font=("Courier", 10),
                                                       bg=self.results_bg, 
                                                       fg=self.results_fg)
        self.results_text.pack(pady=5, padx=10)
        
        # Status bar at the bottom
        self.status_label = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, 
                                      anchor=tk.W, bg=self.status_bg)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Store results for later use (like detailed explanation)
        self.last_scores = None
        self.last_email = None
        self.last_headers = None
        self.last_raw = None
        self.detail_button = None
        
        # Put a sample email in the box so users see an example
        self.add_sample_email()
    
    def add_sample_email(self):
        """Add a sample phishing email so users know what to paste"""
        sample = """From: "PayPal Security" <security@paypal-security.com>
Subject: URGENT: Your Account Has Been Limited

URGENT: Your PayPal account has been limited due to unusual activity.

Please verify your account immediately by clicking here:
http://paypal-security-verify.com/login

Failure to do so will result in permanent account closure.

PayPal Security Team"""
        
        self.email_text.insert(tk.END, sample)
    
    def load_file(self):
        """Open a text file and load its contents into the email box"""
        filename = filedialog.askopenfilename(
            title="Select email file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.email_text.delete(1.0, tk.END)
                self.email_text.insert(tk.END, content)
                self.status_label.config(text="Loaded: " + filename)
            except Exception as e:
                messagebox.showerror("Error", "Could not load file: " + str(e))
    
    def clear_text(self):
        """Clear both the email input and results area"""
        self.email_text.delete(1.0, tk.END)
        self.results_text.delete(1.0, tk.END)
        self.status_label.config(text="Cleared")

    def highlight_urgency_words(self, email_text):
        """Put brackets around suspicious words like [URGENT] or [VERIFY]"""
        urgency_words = ["urgent", "immediately", "deadline", "expires", "limited", 
                        "last chance", "today only", "now", "soon", "warning",
                        "action required", "verify", "confirm", "suspended", "locked",
                        "immediate", "failure", "permanent", "closure", "within",
                        "click", "here", "update", "validate", "restore"]
        
        highlighted = email_text
        
        for word in urgency_words:
            # Match whole words only, not parts of words
            pattern = r'\b' + re.escape(word) + r'\b'
            highlighted = re.sub(pattern, f'[{word.upper()}]', highlighted, flags=re.IGNORECASE)
        
        return highlighted

    def disable_links(self, text, score):
        """If score is high risk (RED), replace clickable links with plain text"""
        # Only disable links for high risk emails (71% and above)
        if score < 71:
            return text
        
        # Find all URLs and replace them
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        
        def replace_url(match):
            url = match.group(0)
            return f"[LINK DISABLED: {url}]"
        
        return re.sub(url_pattern, replace_url, text)
    
    def parse_email(self, content):
        """Split the email into headers (who it's from) and body (the message)"""
        lines = content.split('\n')
        headers = []
        body = []
        in_headers = True
        
        for line in lines:
            if in_headers:
                if line.strip() == "":
                    in_headers = False  # Blank line separates headers from body
                else:
                    headers.append(line)
            else:
                body.append(line)
        
        headers_text = '\n'.join(headers)
        body_text = '\n'.join(body)
        
        # Keep raw bytes for DKIM verification
        raw_bytes = content.encode('utf-8')
        
        # Turn headers into an email object
        try:
            msg = BytesParser(policy=policy.default).parsebytes(headers_text.encode())
        except:
            from email.message import EmailMessage
            msg = EmailMessage()
            for line in headers:
                if line.lower().startswith('from:'):
                    msg['From'] = line[5:].strip()
        
        return body_text, msg, raw_bytes
    
    def analyse_email(self):
        """Start the analysis (runs in background so GUI doesn't freeze)"""
        email_content = self.email_text.get(1.0, tk.END).strip()
        if not email_content:
            messagebox.showwarning("No Email", "Please paste an email or load a file")
            return
        
        self.status_label.config(text="Analysing email...")
        self.results_text.delete(1.0, tk.END)
        self.root.update()
        
        # Run in background so the window doesn't freeze
        thread = threading.Thread(target=self._do_analysis, args=(email_content,))
        thread.daemon = True
        thread.start()
    
    def _do_analysis(self, email_content):
        """Actually run the three checkers (text, URL, metadata)"""
        try:
            # Split email into headers and body
            body_text, headers_msg, raw_bytes = self.parse_email(email_content)
            self.last_email = body_text
            self.last_headers = headers_msg
            self.last_raw = raw_bytes
            
            # Run the three checkers (hide their loading messages)
            with contextlib.redirect_stdout(io.StringIO()):
                textChecker = TextChecker()
                textResult = textChecker.checkEmail(body_text)
                
                urlChecker = URLChecker()
                urlResult = urlChecker.analyseEmail(body_text)
                
                metadataChecker = MetadataChecker()
                metadataResult = metadataChecker.analyseEmail(headers_msg, raw_bytes)
            
            # Save all the scores
            self.last_scores = {
                "textScore": textResult["score"],
                "textVerdict": textResult["verdict"],
                "urlScore": urlResult["score"],
                "urlIssues": urlResult["issues"],
                "metaScore": metadataResult["score"],
                "spoofed": metadataResult["spoofed"],
                "warning": metadataResult.get("warning", ""),
                "sender": metadataResult["sender"],
                "urlBlacklisted": urlResult["blacklisted"]
            }

            # Extract just the domain from the sender email (e.g., gmail.com)
            sender_domain = metadataResult.get('domain', '')
            if '@' in sender_domain:
                sender_domain = sender_domain.split('@')[-1]
            
            # Combine the three scores into one final verdict
            scorer = Scorer()
            final = scorer.combine(
                textScore=self.last_scores["textScore"],
                urlScore=self.last_scores["urlScore"],
                metaScore=self.last_scores["metaScore"],
                urlBlacklisted=self.last_scores["urlBlacklisted"],
                senderSpoofed=self.last_scores["spoofed"],
                sender_domain=sender_domain
            )
            
            # Show results in the GUI
            self.root.after(0, self._display_results, final)
            
        except Exception as err:
            error_msg = str(err)
            self.root.after(0, lambda: self._show_error(error_msg))
    
    def _display_results(self, final):
        """Show the results in the results text box"""
        self.results_text.delete(1.0, tk.END)
        
        # Set up colours for risk levels
        self.results_text.tag_config("red", foreground="red")
        self.results_text.tag_config("green", foreground="green")
        self.results_text.tag_config("orange", foreground="orange")
        
        # Title
        self.results_text.insert(tk.END, "=" * 50 + "\n")
        self.results_text.insert(tk.END, "DETECTION RESULTS\n")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")
        
        # Show each score
        self.results_text.insert(tk.END, "Text score: " + str(self.last_scores['textScore']) + "% (" + self.last_scores['textVerdict'] + ")\n")
        self.results_text.insert(tk.END, "URL score:  " + str(self.last_scores['urlScore']) + "%\n")
        self.results_text.insert(tk.END, "Metadata:   " + str(self.last_scores['metaScore']) + "%\n\n")
        
        # Warn if sender is spoofed
        if self.last_scores['spoofed']:
            self.results_text.insert(tk.END, "WARNING: Sender appears to be spoofed - " + self.last_scores['sender'] + "\n\n", "red")
        
        # Warn if domain is whitelisted but authentication failed
        if self.last_scores.get('warning'):
            self.results_text.insert(tk.END, "WARNING: " + self.last_scores['warning'] + "\n\n", "orange")
        
        # List any URL issues found
        if self.last_scores['urlIssues']:
            self.results_text.insert(tk.END, "URL issues found:\n")
            for issue in self.last_scores['urlIssues'][:3]:
                self.results_text.insert(tk.END, "  - " + issue + "\n")
            self.results_text.insert(tk.END, "\n")

        # Show the email with suspicious words highlighted
        email_to_show = self.last_email
        if final['finalScore'] >= 71:
            email_to_show = self.disable_links(email_to_show, final['finalScore'])
        
        highlighted_email = self.highlight_urgency_words(email_to_show)
        self.results_text.insert(tk.END, "\n" + "-" * 40 + "\n")
        self.results_text.insert(tk.END, "SUSPICIOUS WORDS HIGHLIGHTED:\n")
        self.results_text.insert(tk.END, "-" * 40 + "\n")
        
        # Only show first 400 characters to keep the display tidy
        if len(highlighted_email) > 400:
            self.results_text.insert(tk.END, highlighted_email[:400] + "...\n")
        else:
            self.results_text.insert(tk.END, highlighted_email + "\n")
        
        # Final verdict and risk level
        self.results_text.insert(tk.END, "FINAL VERDICT: " + final['verdict'] + "\n")
        self.results_text.insert(tk.END, "Confidence: " + str(final['finalScore']) + "%\n")
        
        self.results_text.insert(tk.END, "Risk Level: ")
        
        if final['finalScore'] >= 71:
            self.results_text.insert(tk.END, "RED", "red")
            risk_message = " (HIGH RISK - Dangerous elements would be disabled)"
        elif final['finalScore'] >= 21:
            self.results_text.insert(tk.END, "AMBER", "orange")
            risk_message = " (SUSPICIOUS - Check before clicking links)"
        else:
            self.results_text.insert(tk.END, "GREEN", "green")
            risk_message = " (LOW RISK - No action needed)"
        
        self.results_text.insert(tk.END, risk_message + "\n")
        self.results_text.insert(tk.END, "Reason: " + final['reason'] + "\n")
        
        self.results_text.insert(tk.END, "\n" + "-" * 40 + "\n")
        self.results_text.insert(tk.END, "Click 'Get Detailed Explanation' for word-by-word analysis\n")
        
        self.status_label.config(text="Analysis complete")
        
        # Add the detailed explanation button if it doesn't exist yet
        if self.detail_button is None:
            self.detail_button = tk.Button(self.root, 
                                          text="Get Detailed Explanation (SHAP - 30-60 sec)", 
                                          command=self.detailed_explanation,
                                          bg='#2196F3',
                                          fg='white',
                                          font=("Arial", 10))
            self.detail_button.pack(pady=5)
    
    def _show_error(self, error_msg):
        """Show an error popup"""
        messagebox.showerror("Error", "Analysis failed: " + error_msg)
        self.status_label.config(text="Error")
    
    def detailed_explanation(self):
        """Run SHAP to show which words influenced the decision"""
        if not self.last_email:
            messagebox.showwarning("No Email", "Analyse an email first")
            return
        
        if self.detail_button:
            self.detail_button.config(state=tk.DISABLED)
        
        self.status_label.config(text="Running SHAP analysis (30-60 seconds)...")
        self.results_text.insert(tk.END, "\n\nRunning detailed analysis... Please wait...\n")
        self.root.update()
        
        thread = threading.Thread(target=self._run_shap)
        thread.daemon = True
        thread.start()
    
    def _run_shap(self):
        """Run SHAP in background"""
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                explainer = ShapExplainer()
                explanation = explainer.explainEmail(self.last_email)
            
            self.root.after(0, lambda: self._display_shap_results(explanation))
            
        except Exception as err:
            error_msg = str(err)[:100]
            self.root.after(0, lambda: self._show_error("SHAP failed: " + error_msg))
        finally:
            self.root.after(0, lambda: self.detail_button.config(state=tk.NORMAL) if self.detail_button else None)
    
    def _display_shap_results(self, explanation):
        """Show the SHAP word-by-word explanation"""
        self.results_text.insert(tk.END, "\n\n" + "=" * 50 + "\n")
        self.results_text.insert(tk.END, "DETAILED EXPLANATION (SHAP)\n")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")
        
        self.results_text.insert(tk.END, explanation['summary'] + "\n\n")
        
        self.results_text.insert(tk.END, "Top words that influenced the decision:\n")
        self.results_text.insert(tk.END, "  Positive weight = pushed toward phishing\n")
        self.results_text.insert(tk.END, "  Negative weight = pushed toward legitimate\n\n")
        
        for word, weight in explanation['rawWords'][:10]:
            if weight > 0:
                direction = "phishing"
            else:
                direction = "legitimate"
            self.results_text.insert(tk.END, "  " + word + ": " + str(weight)[:6] + " (" + direction + ")\n")
        
        if explanation.get('persuasionBreakdown'):
            self.results_text.insert(tk.END, "\nPersuasion techniques found:\n")
            for principle, words in explanation['persuasionBreakdown'].items():
                if principle != "unknown" and principle != "phishing_context":
                    word_list = []
                    for w in words[:3]:
                        word_list.append(w['word'])
                    self.results_text.insert(tk.END, "  " + principle + ": " + ", ".join(word_list) + "\n")
        
        self.results_text.see(tk.END)
        self.status_label.config(text="SHAP analysis complete")


# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    root.mainloop()