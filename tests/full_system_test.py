# remove_no_url_phishing.py
import os
import sys
import re

# Add your project path
sys.path.append(r'C:\Users\jeffo\OneDrive\Desktop\phishing-project')

from src.components.url_checker import URLChecker

# Set the folder path
phishing_folder = r'C:\Users\jeffo\OneDrive\Desktop\Uni\groupProject\AImodel\test_files\phishing'

# Initialize URL checker
checker = URLChecker()

# Counters
no_urls = 0
has_urls = 0
deleted = []

print(f"Scanning: {phishing_folder}")
print()

# Scan all files
for filename in os.listdir(phishing_folder):
    if filename.endswith('.txt'):
        filepath = os.path.join(phishing_folder, filename)
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Extract URLs
        urls = checker.extractURLs(content)
        
        if not urls:
            # No URLs found - delete this file
            os.remove(filepath)
            no_urls += 1
            deleted.append(filename)
            print(f"🗑️ DELETED: {filename} (no URLs)")
        else:
            has_urls += 1
            print(f"✅ KEPT: {filename} ({len(urls)} URL(s))")

# Summary
print()
print("=" * 50)
print("SUMMARY")
print("=" * 50)
print(f"Files deleted (no URLs): {no_urls}")
print(f"Files kept (have URLs): {has_urls}")
print(f"Total files processed: {no_urls + has_urls}")