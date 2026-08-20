import os
import sqlite3
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

RECAPTCHA_SECRET = os.getenv('RECAPTCHA_SECRET_KEY', '')
ALLOWED_ORIGINS = ['https://thunderous-raindrop-7b846f.netlify.app', 'http://localhost:3000', 'http://localhost:5500']

TEMP_EMAIL_DOMAINS = [
    'mailinator.com', 'tempmail.org', '10minutemail.com', 'guerrillamail.com',
    'sharklasers.com', 'throwawaymail.com', 'dispostable.com', 'maildrop.cc',
    'getnada.com', 'temp-mail.org', 'tempmail.net', 'fakeinbox.com',
    'mailcatch.com', 'trashmail.com', 'yopmail.com', 'emailondeck.com',
    'spamgourmet.com', 'mintemail.com', 'mailnesia.com', 'mailnull.com',
    'example.com', 'test.com', 'mytemp.email', 'tempinbox.com',
    'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org',
    'trash-mail.com', 'opayq.com', 'mailinator.net', 'mailinator.org',
    'spamobox.com', 'binkmail.com', 'deadaddress.com', 'discardmail.com',
    'dodgeit.com', 'e4ward.com', 'gishpuppy.com', 'junkmail.com',
    'mailexpire.com', 'mailmetrash.com', 'mailslite.com', 'mypacks.net',
    'objectmail.com', 'proxymail.com', 'rcpt.at', 'shortmail.net',
    'sogetthis.com', 'tyldd.com', 'uggsrock.com', 'wuzup.net',
    'xs4all.nl', 'yopmail.fr', 'yopmail.net', 'cool.fr.nf',
    'jetable.fr.nf', 'nospammail.net', 'spambox.us', 'zybermail.com'
]

ALLOWED_INTERESTS = ['Collector', 'Commission', 'Art Decks', 'AI Services', 'General']


def init_db():
    conn = sqlite3.connect('signups.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS signups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        interest TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()


def cors_response(data, status=200):
    response = jsonify(data)
    response.status_code = status
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response


@app.route('/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS':
        return cors_response({})

    data = request.get_json()

    if not data:
        return cors_response({'success': False, 'message': 'No data received.'}, 400)

    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    interest = data.get('interest', '').strip()
    recaptcha_response = data.get('recaptcha', '')
    honeypot = data.get('website', '')

    # Honeypot check
    if honeypot:
        return cors_response({'success': True, 'message': 'Thank you.'})

    # Name validation
    if len(name) < 2 or len(name) > 100:
        return cors_response({'success': False, 'message': 'Invalid name.'}, 400)
    if any(c in name for c in '<>{}[]()=;:'):
        return cors_response({'success': False, 'message': 'Name contains invalid characters.'}, 400)
    if any(c.isdigit() for c in name):
        return cors_response({'success': False, 'message': 'Name should not contain numbers.'}, 400)

    # Email validation
    if '@' not in email or '.' not in email.split('@')[1]:
        return cors_response({'success': False, 'message': 'Invalid email.'}, 400)

    domain = email.split('@')[1]
    if domain in TEMP_EMAIL_DOMAINS:
        return cors_response({'success': False, 'message': 'Please use a permanent email address.'}, 400)

    # Interest validation
    if interest not in ALLOWED_INTERESTS:
        return cors_response({'success': False, 'message': 'Invalid interest.'}, 400)

    # reCAPTCHA verification
    if not RECAPTCHA_SECRET:
        return cors_response({'success': False, 'message': 'Server configuration error.'}, 500)

    if not recaptcha_response:
        return cors_response({'success': False, 'message': 'reCAPTCHA is required.'}, 400)

    payload = {
        'secret': RECAPTCHA_SECRET,
        'response': recaptcha_response
    }

    try:
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
        result = r.json()
        if not result.get('success'):
            return cors_response({'success': False, 'message': 'reCAPTCHA verification failed.'}, 400)
    except:
        return cors_response({'success': False, 'message': 'reCAPTCHA verification error.'}, 500)

    # Store in database
    try:
        conn = sqlite3.connect('signups.db')
        c = conn.cursor()
        c.execute('INSERT INTO signups (name, email, interest) VALUES (?, ?, ?)', (name, email, interest))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return cors_response({'success': False, 'message': 'This email is already subscribed.'}, 400)
    except:
        return cors_response({'success': False, 'message': 'Database error.'}, 500)

    return cors_response({'success': True, 'message': 'Thank you. You are on the list.'})


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)