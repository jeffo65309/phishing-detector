# Phishing Email Detector

A tool that checks if an email is phishing by looking at the text, the links, and who sent it.

## What It Does

I built three separate checks:

- **Text check** - Uses an AI model (DistilBERT) to read the email and spot phishing language
- **URL check** - Looks at links for dodgy patterns (shorteners, IP addresses, suspicious words)
- **Sender check** - Checks SPF, DKIM, and DMARC to see if the sender is faking who they are

Then it combines all three into one final score.

## How to Get It Running

### Step 1: Python

You need Python installed. I used 3.14 but anything above 3.8 should work.

### Step 2: Create a virtual environment

Open command prompt in this folder and type:
python -m venv venv
venv\Scripts\activate


The `(venv)` should appear at the start of your command line.

### Step 3: Install everything

pip install -r requirements.txt


This might take a few minutes. It installs all the libraries I used.

### Step 4: Set your Hugging Face token (optional)

If you want faster downloads, create a file called `.env` and put:

HF_TOKEN=your_token_here


You can get a free token from huggingface.co/settings/tokens. If you don't do this, it still works but you'll see a warning.

## How to Test It

### Quick test (just the AI)

python gui_app.py


## How the Scoring Works

Each check gives a score 0-100:

- **Text score** - from the AI model
- **URL score** - from checking the links
- **Sender score** - from SPF/DKIM/DMARC checks

Then it uses these rules:

- If a URL is in a blacklist → straight to 100%
- If the sender is spoofed → straight to 100%
- If two checks are high (above 70%) → boost to 100%
- Otherwise, just take the highest score

## File Structure

phishing-project/
├── src/
│ ├── components/
│ │ ├── text_checkerAI.py # AI text analysis
│ │ ├── url_checker.py # URL checks
│ │ ├── metadata_checker.py # SPF/DKIM/DMARC
│ │ ├── scorer.py # Combines everything
│ │ ├── fast_explainer.py # Quick word explanation
│ │ ├── lime_explainer.py # Detailed LIME analysis
│ │ └── shap_explainer.py # SHAP analysis
│ └── core/
│ └── detector.py # Main hub
├── tests/
│ ├── test_full_system.py # Full test
│ ├── test_fast.py # Quick explainer
│ ├── test_lime.py # LIME explainer
│ ├── test_shap.py # SHAP explainer
│ └── test_data.py # Shared test email
├── gui_app.py # GUI application
├── whitelist.json # Trusted domains
├── requirements.txt # Packages needed
└── README.md # This filee


## Common Problems

**"Module not found"**  
You probably forgot to activate the virtual environment. Run `venv\Scripts\activate` first.

**"No module named requests"**  
Run `pip install -r requirements.txt` again.

**Hugging Face warning**  
Ignore it, or create the `.env` file with your token.

**SPF/DKIM checks fail**  
That's normal for test emails. Real emails would pass if they're legit.

## Who Made This

This was a group project for 5200COMP. The code has lots of comments because I wanted to understand what each part does.