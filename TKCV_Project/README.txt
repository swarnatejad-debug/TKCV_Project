TKCV Exams - how to run (Windows)

1. Open PowerShell inside this folder.
2. Install packages (one time):
       py -m pip install -r requirements.txt
3. Start the app:
       py app.py
4. Open http://localhost:5000 in your browser.
5. Click Admin > Create an account (Gmail address ending in @gmail.com), sign in, and create an exam.

Notes
- The database file exam.db is created automatically on first run.
- Password reset emails: without GMAIL_USER and GMAIL_APP_PASSWORD set, the reset link is
  printed in the PowerShell window instead of being emailed.
- For phones on the same Wi-Fi to use the QR code, set BASE_URL to your PC's address first:
       $env:BASE_URL = "http://192.168.1.10:5000"
       py app.py
  (replace 192.168.1.10 with your PC's IP from ipconfig)
- Optional: set SECRET_KEY to a long random text before using this for real exams.
