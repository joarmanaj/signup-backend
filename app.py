import os
import html
import requests
import psycopg2
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

RECAPTCHA_SECRET = os.getenv('RECAPTCHA_SECRET_KEY', '')
DATABASE_URL = os.getenv('DATABASE_URL', '')
RESEND_API_KEY = os.getenv('RESEND_API_KEY', '')
MAIL_RECIPIENT = os.getenv('MAIL_RECIPIENT', '')

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

ALLOWED_ORIGINS = [
    'https://myhome-teal.vercel.app',
    'http://127.0.0.1:5000',
    'http://localhost:5000',
    'http://127.0.0.1:5500',
    'http://localhost:5500'
]

# Field length limits
MAX_NAME = 100
MAX_EMAIL = 150
MAX_TEXT = 2000
MAX_PHONE = 30
MAX_COUNTRY = 60


def cors_response(data, status=200):
    origin = request.headers.get('Origin', '')
    response = jsonify(data)
    response.status_code = status
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    else:
        response.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0]
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response


def clean_field(value, max_length=MAX_TEXT):
    """Strip, limit length, and escape HTML."""
    if not isinstance(value, str):
        return ''
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    return html.escape(value)


def send_email(subject, html_body):
    if not RESEND_API_KEY or not MAIL_RECIPIENT:
        print("Email not configured — skipping.")
        return False

    try:
        response = requests.post(
            'https://api.resend.com/emails',
            headers={
                'Authorization': f'Bearer {RESEND_API_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'from': 'Studio <onboarding@resend.dev>',
                'to': [MAIL_RECIPIENT],
                'subject': subject,
                'html': html_body
            }
        )
        if response.status_code in [200, 201]:
            print("Email sent.")
            return True
        else:
            print(f"Email failed: {response.status_code} — {response.text}")
            return False
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False


@app.route('/signup', methods=['POST', 'OPTIONS'])
@limiter.limit("5 per minute")
def signup():
    if request.method == 'OPTIONS':
        return cors_response({})

    data = request.get_json()
    if not data:
        return cors_response({'success': False, 'message': 'No data received.'}, 400)

    name = clean_field(data.get('name', ''), MAX_NAME)
    email = clean_field(data.get('email', ''), MAX_EMAIL).lower()
    interest = clean_field(data.get('interest', ''), 100)
    recaptcha_response = data.get('recaptcha', '')
    honeypot = data.get('website', '')

    if honeypot:
        return cors_response({'success': True, 'message': 'Thank you.'})

    if len(name) < 2:
        return cors_response({'success': False, 'message': 'Invalid name.'}, 400)
    if any(c.isdigit() for c in name):
        return cors_response({'success': False, 'message': 'Name should not contain numbers.'}, 400)

    if '@' not in email or '.' not in email.split('@')[1]:
        return cors_response({'success': False, 'message': 'Invalid email.'}, 400)

    domain = email.split('@')[1]
    if domain in TEMP_EMAIL_DOMAINS:
        return cors_response({'success': False, 'message': 'Please use a permanent email address.'}, 400)

    if interest not in ALLOWED_INTERESTS:
        return cors_response({'success': False, 'message': 'Invalid interest.'}, 400)

    if not RECAPTCHA_SECRET:
        return cors_response({'success': False, 'message': 'Server configuration error.'}, 500)

    if not recaptcha_response:
        return cors_response({'success': False, 'message': 'reCAPTCHA is required.'}, 400)

    try:
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': RECAPTCHA_SECRET,
            'response': recaptcha_response
        })
        result = r.json()
        if not result.get('success'):
            return cors_response({'success': False, 'message': 'reCAPTCHA verification failed.'}, 400)
    except:
        return cors_response({'success': False, 'message': 'reCAPTCHA verification error.'}, 500)

    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute(
            'INSERT INTO signups (name, email, interest) VALUES (%s, %s, %s)',
            (name, email, interest)
        )
        conn.commit()
        conn.close()
    except psycopg2.errors.UniqueViolation:
        return cors_response({'success': False, 'message': 'This email is already subscribed.'}, 400)
    except Exception as e:
        print(f'Database error: {str(e)}')
        return cors_response({'success': False, 'message': 'Database error.'}, 500)

    html_body = f"""
    <div style="font-family: Georgia, serif; color: #333;">
        <h2 style="letter-spacing: 2px;">New Signup</h2>
        <p><strong>Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Interest:</strong> {interest}</p>
    </div>
    """
    send_email(f"New Signup — {name}", html_body)

    return cors_response({'success': True, 'message': 'Thank you. You are on the list.'})


@app.route('/commission', methods=['POST', 'OPTIONS'])
@limiter.limit("3 per minute")
def commission():
    if request.method == 'OPTIONS':
        return cors_response({})

    data = request.get_json()
    if not data:
        return cors_response({'success': False, 'message': 'No data received.'}, 400)

    client_name = clean_field(data.get('client_name', ''), MAX_NAME)
    client_email = clean_field(data.get('client_email', ''), MAX_EMAIL).lower()
    client_phone = clean_field(data.get('client_phone', ''), MAX_PHONE)
    country = clean_field(data.get('country', ''), MAX_COUNTRY)
    conversation_check = clean_field(data.get('conversation_check', ''), 20)
    request_type = clean_field(data.get('request_type', ''), 30)
    piece_slug = clean_field(data.get('piece_slug', ''), 100)
    piece_title = clean_field(data.get('piece_title', ''), MAX_NAME)
    piece_image = clean_field(data.get('piece_image', ''), 200)
    commission_type = clean_field(data.get('commission_type', ''), 60)
    new_vision = clean_field(data.get('new_vision', ''), MAX_TEXT)
    size_preference = clean_field(data.get('size_preference', ''), 100)
    deadline = clean_field(data.get('deadline', ''), 30) or None
    budget_range = clean_field(data.get('budget_range', ''), 60)
    recaptcha_response = data.get('recaptcha', '')
    honeypot = data.get('website', '')

    if honeypot:
        return cors_response({'success': True, 'message': 'Thank you.'})

    if len(client_name) < 2:
        return cors_response({'success': False, 'message': 'Invalid name.'}, 400)
    if any(c.isdigit() for c in client_name):
        return cors_response({'success': False, 'message': 'Name should not contain numbers.'}, 400)

    if '@' not in client_email or '.' not in client_email.split('@')[1]:
        return cors_response({'success': False, 'message': 'Invalid email.'}, 400)

    domain = client_email.split('@')[1]
    if domain in TEMP_EMAIL_DOMAINS:
        return cors_response({'success': False, 'message': 'Please use a permanent email address.'}, 400)

    if not RECAPTCHA_SECRET:
        return cors_response({'success': False, 'message': 'Server configuration error.'}, 500)

    if not recaptcha_response:
        return cors_response({'success': False, 'message': 'reCAPTCHA is required.'}, 400)

    try:
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
            'secret': RECAPTCHA_SECRET,
            'response': recaptcha_response
        })
        result = r.json()
        if not result.get('success'):
            return cors_response({'success': False, 'message': 'reCAPTCHA verification failed.'}, 400)
    except:
        return cors_response({'success': False, 'message': 'reCAPTCHA verification error.'}, 500)

    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('''
            INSERT INTO commissions (
                client_name, client_email, client_phone, country,
                conversation_check, request_type, piece_slug, piece_title,
                piece_image, commission_type, new_vision, size_preference,
                deadline, budget_range
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            client_name, client_email, client_phone, country,
            conversation_check, request_type, piece_slug, piece_title,
            piece_image, commission_type, new_vision, size_preference,
            deadline, budget_range
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f'Commission DB error: {str(e)}')
        return cors_response({'success': False, 'message': 'Database error.'}, 500)

    html_body = f"""
    <div style="font-family: Georgia, serif; color: #333;">
        <h2>New Commission Request</h2>
        <p><strong>Client:</strong> {client_name}</p>
        <p><strong>Email:</strong> {client_email}</p>
        <p><strong>WhatsApp:</strong> {client_phone}</p>
        <p><strong>Country:</strong> {country}</p>
        <hr>
        <p><strong>Conversation Check:</strong> {conversation_check}</p>
        <p><strong>Request Type:</strong> {request_type}</p>
        <p><strong>Piece Reference:</strong> {piece_title or 'None'}</p>
        <p><strong>Commission Type:</strong> {commission_type}</p>
        <p><strong>Vision:</strong> {new_vision}</p>
        <p><strong>Size:</strong> {size_preference}</p>
        <p><strong>Deadline:</strong> {deadline or 'Not specified'}</p>
        <p><strong>Budget:</strong> {budget_range}</p>
    </div>
    """
    send_email(f"New Commission — {client_name}", html_body)

    return cors_response({'success': True, 'message': 'Thank you. Your commission request has been received.'})


@app.errorhandler(429)
def ratelimit_handler(e):
    return cors_response({'success': False, 'message': 'Too many requests. Please try again later.'}, 429)


if __name__ == '__main__':
    app.run(debug=True, port=5000)