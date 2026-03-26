# Shared test data for all test files
# Just change the email here and all tests will use it

# The email to test
TEST_EMAIL = """URGENT: Your PayPal account has been limited.

Please verify your account immediately by clicking here:
http://paypal-security-verify.com/login
http://bit.ly/3xYz7Qa
http://192.168.1.1/bank

Failure to do so will result in permanent account closure.
PayPal Security Team"""

# The email headers (who it claims to be from)
TEST_HEADERS = """From: "PayPal Security" <security@paypal-security.com>
Subject: URGENT: Account Limited
Date: Mon, 25 Mar 2025 10:00:00 +0000"""