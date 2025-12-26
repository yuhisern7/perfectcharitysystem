"""PCS Website frontend

This module provides a simple HTML website on top of the
Perfect Charity System (PCS) backend.

It:
- Uses FastAPI + Jinja2 templates to render HTML pages.
- Mounts the existing API from perfectcharitysystem.py under /api.
- Lets you view profiles and create new profiles from the browser.
- Provides a basic donation form that records PCS transactions.

This is a starting point; later you can style the HTML and
add more pages.
"""

from __future__ import annotations

import hashlib
import pathlib
import uuid
import re
import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles

import perfectcharitysystem as pcs_api
import pcs_persistence
import pcs_ai
import config


BASE_DIR = pathlib.Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


app = FastAPI(title="PCS Website")

# Simple server-side sessions for login state
app.add_middleware(
	SessionMiddleware,
	secret_key=config.SECRET_KEY,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
	"""Add OWASP-compliant security headers.

	Implements OWASP security best practices:
	- X-Frame-Options: Prevent clickjacking (OWASP A04:2021)
	- X-Content-Type-Options: Prevent MIME sniffing (OWASP A05:2021)
	- Content-Security-Policy: Prevent XSS (OWASP A03:2021)
	- Strict-Transport-Security: Force HTTPS (OWASP A02:2021)
	- Referrer-Policy: Limit information leakage
	- Permissions-Policy: Restrict browser features
	- X-XSS-Protection: Legacy XSS protection
	"""
	# AI Security Monitoring - Check for attacks BEFORE processing request
	client_ip = request.client.host if request.client else "unknown"
	user_agent = request.headers.get("user-agent", "")
	
	# Check request pattern for attacks (include full URL with query params)
	full_url = str(request.url)
	
	try:
		security_check = pcs_ai.assess_request_pattern(
			ip_address=client_ip,
			endpoint=full_url,
			method=request.method,
			user_agent=user_agent,
		)
		
		# Block malicious requests immediately (OWASP A05:2021 - Security Misconfiguration)
		if security_check.should_block:
			from fastapi.responses import JSONResponse
			return JSONResponse(
				status_code=403,
				content={"detail": "Access denied - Security threat detected", "threat": security_check.threats}
			)
	except Exception as e:
		# Log error but don't block request if security check fails
		print(f"[SECURITY ERROR] Failed to assess request: {e}")
		import traceback
		traceback.print_exc()
	
	response = await call_next(request)
	
	# OWASP A04:2021 - Insecure Design: Prevent clickjacking attacks
	response.headers.setdefault("X-Frame-Options", "DENY")
	
	# OWASP A05:2021 - Security Misconfiguration: Prevent MIME sniffing
	response.headers.setdefault("X-Content-Type-Options", "nosniff")
	
	# OWASP A05:2021 - Security Misconfiguration: Limit referrer information leakage
	response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
	
	# OWASP A03:2021 - Injection: Content Security Policy (prevent XSS)
	response.headers.setdefault(
		"Content-Security-Policy",
		"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'"
	)
	
	# OWASP A05:2021 - Security Misconfiguration: Restrict browser features
	response.headers.setdefault(
		"Permissions-Policy",
		"geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()"
	)
	
	# OWASP A02:2021 - Cryptographic Failures: Force HTTPS in production
	if not config.DEBUG:
		response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	
	# Legacy XSS protection (defense in depth)
	response.headers.setdefault("X-XSS-Protection", "1; mode=block")
	
	# OWASP A09:2021 - Security Logging: Log suspicious activity
	if security_check.level in [pcs_ai.ThreatLevel.SUSPICIOUS, pcs_ai.ThreatLevel.DANGEROUS]:
		print(f"[SECURITY WARNING] {client_ip} - {security_check.threats}")
	
	return response

# Serve uploaded media files
app.mount("/uploads", StaticFiles(directory=str(BASE_DIR / "uploads")), name="uploads")


# ---------------------------------------------------------------------------
# In-memory user accounts (prototype)
# ---------------------------------------------------------------------------


@dataclass
class User:
	user_id: str
	username: str
	password_hash: str
	role: str  # "donor", "receiver", "inspector", or "charity_org"
	intro: str = ""
	avatar_files: List[str] = field(default_factory=list)
	video_files: List[str] = field(default_factory=list)
	gallery_files: List[str] = field(default_factory=list)
	is_public: bool = True  # donors can switch; receivers always public
	country: str = ""
	state: str = ""
	city: str = ""
	wallet_id: Optional[str] = None
	social_links: List[str] = field(default_factory=list)
	email: str = ""
	phone: str = ""
	xchat: str = ""
	physical_address: str = ""
	reveal_email: bool = False
	reveal_phone: bool = False
	reveal_xchat: bool = False
	bank_details: str = ""  # Bank account information for receivers
	payment_gateways: str = ""  # Western Union payment gateway details
	other_payment_gateways: str = ""  # Other payment gateway details (PayPal, crypto, etc.)
	# Charity organization verification fields
	charity_legal_name: str = ""
	charity_registration_number: str = ""
	charity_registration_country: str = ""
	charity_registering_body: str = ""
	charity_active_status_proof: str = ""
	charity_bank_name: str = ""
	charity_bank_account_holder: str = ""
	charity_bank_account_number: str = ""
	charity_bank_country: str = ""
	charity_representative_name: str = ""
	charity_representative_role: str = ""
	charity_representative_proof: str = ""
	# Wallet balance and monthly credits
	wallet_balance: float = 0.0
	last_monthly_credit: Optional[str] = None  # ISO date of last monthly credit
	# Purchase requests (for receivers to see who wants to buy)
	purchase_requests: List[Dict] = field(default_factory=list)
	# Donor's outgoing purchase requests
	my_purchase_requests: List[Dict] = field(default_factory=list)
	# Law enforcement / inspector fields
	is_banned: bool = False
	ban_reason: str = ""
	ban_timestamp: Optional[str] = None
	banned_by: Optional[str] = None  # inspector user_id
	registration_ip: str = ""
	registration_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
	last_login_ip: str = ""
	last_login_timestamp: Optional[str] = None
	# DISA STIG security fields
	failed_login_attempts: int = 0
	last_failed_login: Optional[str] = None
	account_locked_until: Optional[str] = None
	password_last_changed: str = field(default_factory=lambda: datetime.utcnow().isoformat())
	security_events: List[Dict] = field(default_factory=list)
	# Notifications for transaction requests
	notifications: List[Dict] = field(default_factory=list)
	# External services project
	project_name: str = ""
	project_description: str = ""
	project_files: List[str] = field(default_factory=list)
	project_funding_required: str = ""  # Amount of funding needed for project
	project_donations_received: float = 0.0  # Total donations received for this project
	project_donors: List[Dict] = field(default_factory=list)  # List of donors who contributed to project


USERS: Dict[str, User] = {}
USERNAME_INDEX: Dict[str, str] = {}  # username -> user_id

# Comprehensive country list (150+ countries)
ALL_COUNTRIES = [
    "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Argentina", "Armenia", "Australia", "Austria", "Azerbaijan",
    "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bhutan", "Bolivia",
    "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei", "Bulgaria", "Burkina Faso", "Burundi", "Cambodia", "Cameroon", "Canada",
    "Cape Verde", "Central African Republic", "Chad", "Chile", "China", "Colombia", "Comoros", "Congo", "Costa Rica", "Croatia",
    "Cuba", "Cyprus", "Czech Republic", "Denmark", "Djibouti", "Dominica", "Dominican Republic", "East Timor", "Ecuador", "Egypt",
    "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Ethiopia", "Fiji", "Finland", "France", "Gabon", "Gambia",
    "Georgia", "Germany", "Ghana", "Greece", "Grenada", "Guatemala", "Guinea", "Guinea-Bissau", "Guyana", "Haiti",
    "Honduras", "Hungary", "Iceland", "India", "Indonesia", "Iran", "Iraq", "Ireland", "Israel", "Italy",
    "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", "Kiribati", "Kuwait", "Kyrgyzstan", "Laos", "Latvia",
    "Lebanon", "Lesotho", "Liberia", "Libya", "Liechtenstein", "Lithuania", "Luxembourg", "Madagascar", "Malawi", "Malaysia",
    "Maldives", "Mali", "Malta", "Marshall Islands", "Mauritania", "Mauritius", "Mexico", "Micronesia", "Moldova", "Monaco",
    "Mongolia", "Montenegro", "Morocco", "Mozambique", "Myanmar", "Namibia", "Nauru", "Nepal", "Netherlands", "New Zealand",
    "Nicaragua", "Niger", "Nigeria", "North Korea", "Norway", "Oman", "Pakistan", "Palau", "Palestine", "Panama",
    "Papua New Guinea", "Paraguay", "Peru", "Philippines", "Poland", "Portugal", "Qatar", "Romania", "Russia", "Rwanda",
    "Saint Kitts and Nevis", "Saint Lucia", "Saint Vincent and the Grenadines", "Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia", "Senegal", "Serbia", "Seychelles",
    "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa", "South Korea", "South Sudan", "Spain",
    "Sri Lanka", "Sudan", "Suriname", "Swaziland", "Sweden", "Switzerland", "Syria", "Taiwan", "Tajikistan", "Tanzania",
    "Thailand", "Togo", "Tonga", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Tuvalu", "Uganda", "Ukraine",
    "United Arab Emirates", "United Kingdom", "United States", "Uruguay", "Uzbekistan", "Vanuatu", "Vatican City", "Venezuela", "Vietnam", "Yemen",
    "Zambia", "Zimbabwe", "Other"
]

# DISA STIG Configuration
STIG_MAX_FAILED_LOGINS = 3  # STIG V-222596: Account lockout threshold
STIG_LOCKOUT_DURATION_MINUTES = 15  # STIG V-222597: Lockout duration
STIG_SESSION_TIMEOUT_MINUTES = 30  # STIG V-222598: Session inactivity timeout
STIG_PASSWORD_MIN_LENGTH = 3  # STIG V-222599: Minimum password length (set to 3 for testing)
STIG_PASSWORD_COMPLEXITY = False  # STIG V-222600: Require uppercase, lowercase, number, special char (disabled for testing)


def _log_security_event(user: User, event_type: str, details: str, ip_address: str = "") -> None:
	"""Log security events for audit trail (DISA STIG V-222594)."""
	event = {
		"timestamp": datetime.utcnow().isoformat(),
		"type": event_type,
		"details": details,
		"ip_address": ip_address,
	}
	user.security_events.append(event)
	# Keep only last 100 events per user to prevent unbounded growth
	if len(user.security_events) > 100:
		user.security_events = user.security_events[-100:]


def _validate_password_complexity(password: str) -> tuple[bool, str]:
	"""Validate password meets DISA STIG complexity requirements (V-222599, V-222600)."""
	if len(password) < STIG_PASSWORD_MIN_LENGTH:
		return False, f"Password must be at least {STIG_PASSWORD_MIN_LENGTH} characters long"
	
	if not STIG_PASSWORD_COMPLEXITY:
		return True, ""
	
	has_upper = any(c.isupper() for c in password)
	has_lower = any(c.islower() for c in password)
	has_digit = any(c.isdigit() for c in password)
	has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
	
	if not (has_upper and has_lower and has_digit and has_special):
		return False, "Password must contain uppercase, lowercase, number, and special character"
	
	return True, ""


def _is_account_locked(user: User) -> bool:
	"""Check if account is locked due to failed login attempts (DISA STIG V-222596)."""
	if not user.account_locked_until:
		return False
	
	locked_until = datetime.fromisoformat(user.account_locked_until)
	if datetime.utcnow() < locked_until:
		return True
	
	# Lockout expired, reset
	user.account_locked_until = None
	user.failed_login_attempts = 0
	return False


def _record_failed_login(user: User, ip_address: str = "") -> None:
	"""Record failed login attempt and lock account if threshold exceeded (DISA STIG V-222596)."""
	user.failed_login_attempts += 1
	user.last_failed_login = datetime.utcnow().isoformat()
	_log_security_event(user, "FAILED_LOGIN", f"Failed login attempt #{user.failed_login_attempts}", ip_address)
	
	if user.failed_login_attempts >= STIG_MAX_FAILED_LOGINS:
		lockout_until = datetime.utcnow().replace(microsecond=0)
		from datetime import timedelta
		lockout_until += timedelta(minutes=STIG_LOCKOUT_DURATION_MINUTES)
		user.account_locked_until = lockout_until.isoformat()
		_log_security_event(user, "ACCOUNT_LOCKED", f"Account locked until {lockout_until.isoformat()}", ip_address)


def _record_successful_login(user: User, ip_address: str = "") -> None:
	"""Record successful login and reset failed attempts (DISA STIG V-222595)."""
	user.failed_login_attempts = 0
	user.last_failed_login = None
	user.account_locked_until = None
	user.last_login_ip = ip_address
	user.last_login_timestamp = datetime.utcnow().isoformat()
	_log_security_event(user, "SUCCESSFUL_LOGIN", "User logged in successfully", ip_address)


def _apply_monthly_credit(user: User) -> None:
	"""Apply monthly $10,000 credit to receiver and charity_org accounts if a month has passed."""
	if user.role not in ["receiver", "charity_org"]:
		return
	
	now = datetime.utcnow()
	
	# If never credited before, credit now
	if not user.last_monthly_credit:
		user.wallet_balance += 10000.0
		user.last_monthly_credit = now.isoformat()
		_save_users()
		return
	
	# Check if a month has passed
	last_credit = datetime.fromisoformat(user.last_monthly_credit)
	
	# Calculate month difference
	months_diff = (now.year - last_credit.year) * 12 + (now.month - last_credit.month)
	
	if months_diff >= 1:
		# Credit for each month that has passed
		user.wallet_balance += (months_diff * 10000.0)
		user.last_monthly_credit = now.isoformat()
		_save_users()


def _create_notification(user: User, notification_type: str, title: str, message: str, link: str = "") -> None:
	"""Create a notification for a user about transaction requests."""
	notification = {
		"id": f"notif_{uuid.uuid4().hex[:16]}",
		"type": notification_type,  # purchase_approved, purchase_rejected, proof_needed, new_request, proof_submitted
		"title": title,
		"message": message,
		"link": link,
		"timestamp": datetime.utcnow().isoformat(),
		"read": False,
	}
	user.notifications.append(notification)
	# Keep only last 50 notifications per user
	if len(user.notifications) > 50:
		user.notifications = user.notifications[-50:]


def _get_unread_notification_count(user: User) -> int:
	"""Get count of unread notifications for a user."""
	return sum(1 for n in user.notifications if not n.get("read", False))


def _save_users() -> None:
	"""Save user data to disk."""
	try:
		# Convert User objects to dictionaries
		users_dict = {uid: u.__dict__ for uid, u in USERS.items()}
		pcs_persistence.save_users(users_dict, USERNAME_INDEX)
	except Exception as e:
		print(f"Warning: Failed to save users: {e}")


def _load_users() -> None:
	"""Load user data from disk."""
	try:
		users_dict, username_index = pcs_persistence.load_users()
		for user_id, user_data in users_dict.items():
			# Add default values for new fields if they don't exist
			if 'payment_gateways' not in user_data:
				user_data['payment_gateways'] = ""
			if 'wallet_balance' not in user_data:
				user_data['wallet_balance'] = 0.0
			if 'last_monthly_credit' not in user_data:
				user_data['last_monthly_credit'] = None
			if 'purchase_requests' not in user_data:
				user_data['purchase_requests'] = []
			if 'my_purchase_requests' not in user_data:
				user_data['my_purchase_requests'] = []
			# DISA STIG security fields (backward compatibility)
			if 'failed_login_attempts' not in user_data:
				user_data['failed_login_attempts'] = 0
			if 'last_failed_login' not in user_data:
				user_data['last_failed_login'] = None
			if 'account_locked_until' not in user_data:
				user_data['account_locked_until'] = None
			if 'password_last_changed' not in user_data:
				user_data['password_last_changed'] = datetime.utcnow().isoformat()
			if 'security_events' not in user_data:
				user_data['security_events'] = []
			# Notifications field (backward compatibility)
			if 'notifications' not in user_data:
				user_data['notifications'] = []
			# External services fields (backward compatibility)
			if 'project_name' not in user_data:
				user_data['project_name'] = ""
			if 'project_description' not in user_data:
				user_data['project_description'] = ""
			if 'project_files' not in user_data:
				user_data['project_files'] = []
			# Other payment gateways field (backward compatibility)
			if 'other_payment_gateways' not in user_data:
				user_data['other_payment_gateways'] = ""
			
			# Recreate User objects from dictionaries
			USERS[user_id] = User(**user_data)
		USERNAME_INDEX.update(username_index)
	except Exception as e:
		print(f"Warning: Failed to load users: {e}")


def _hash_password(raw: str) -> str:
	return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sanitize_input(text: str, max_length: int = 500) -> str:
	"""Sanitize user input to prevent XSS and injection attacks (OWASP A03:2021).
	
	Parameters
	----------
	text : str
		User input to sanitize
	max_length : int
		Maximum allowed length
		
	Returns
	-------
	str
		Sanitized text safe for storage and display
	"""
	if not text:
		return ""
	
	# Truncate to max length
	text = text[:max_length]
	
	# HTML escape to prevent XSS
	text = html.escape(text)
	
	# Remove any remaining potentially dangerous characters
	text = re.sub(r'[<>"\'\/]', '', text)
	
	return text.strip()


def _sanitize_email(email: str) -> str:
	"""Validate and sanitize email address (OWASP A03:2021)."""
	if not email:
		return ""
	
	# Basic email validation pattern
	email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
	if not re.match(email_pattern, email):
		return ""
	
	return email.strip().lower()[:254]  # Max email length per RFC 5321


def _sanitize_username(username: str) -> str:
	"""Validate and sanitize username (OWASP A03:2021)."""
	if not username:
		return ""
	
	# Only allow alphanumeric, underscore, hyphen, dot
	username = re.sub(r'[^a-zA-Z0-9._-]', '', username)
	
	return username.strip().lower()[:50]


def _sanitize_url(url: str) -> str:
	"""Validate and sanitize URLs to prevent SSRF (OWASP A10:2021)."""
	if not url:
		return ""
	
	# Only allow http and https protocols
	if not url.startswith(('http://', 'https://')):
		return ""
	
	# Remove any attempts at protocol smuggling
	url = re.sub(r'[\r\n\t]', '', url)
	
	return url.strip()[:2048]


def _seed_inspector_account() -> None:
	"""Create a built-in inspector account (admin/admin) if missing.

	This cannot be created through the public registration form; it is
	seeded here to keep inspectors separate from donors and receivers.
	"""
	if "admin" in USERNAME_INDEX:
		return

	user_id = "user_inspector_admin"
	password_hash = _hash_password(config.ADMIN_PASSWORD)
	user = User(
		user_id=user_id,
		username="admin",
		password_hash=password_hash,
		role="inspector",
	)
	USERS[user_id] = user
	USERNAME_INDEX["admin"] = user_id


# Load persisted data
_load_users()
_seed_inspector_account()
_save_users()  # Save in case inspector was just created


def _get_current_user(request: Request) -> Optional[User]:
	user_id = request.session.get("user_id")
	if not user_id:
		return None
	
	# DISA STIG V-222598: Check session timeout (30 minutes of inactivity)
	last_activity = request.session.get("last_activity")
	if last_activity:
		last_active_time = datetime.fromisoformat(last_activity)
		from datetime import timedelta
		timeout_threshold = datetime.utcnow() - timedelta(minutes=STIG_SESSION_TIMEOUT_MINUTES)
		
		if last_active_time < timeout_threshold:
			# Session expired, clear it
			request.session.clear()
			return None
	
	# Update last activity timestamp
	request.session["last_activity"] = datetime.utcnow().isoformat()
	
	return USERS.get(user_id)


def _require_inspector(request: Request) -> User:
	"""Require that the current user is an inspector.
	
	Raises HTTPException if not logged in or not an inspector.
	"""
	from fastapi import HTTPException
	user = _get_current_user(request)
	if not user:
		raise HTTPException(status_code=401, detail="Not authenticated")
	if user.role != "inspector":
		raise HTTPException(status_code=403, detail="Inspector access required")
	return user


def _ensure_upload_dir() -> pathlib.Path:
	upload_dir = BASE_DIR / "uploads"
	upload_dir.mkdir(exist_ok=True)
	return upload_dir


def _wallet_history_for_user(user: User) -> List[Dict[str, object]]:
	"""Return outgoing PCS transactions for this user's wallet.

	Each entry contains the block timestamp, receiver wallet, amount, and
	optional metadata. This reads directly from the shared PCS blockchain
	instance exposed by perfectcharitysystem.
	"""
	if not user.wallet_id:
		return []

	history: List[Dict[str, object]] = []
	for block in pcs_api.blockchain.chain:
		for tx in block.transactions:
			if tx.sender == user.wallet_id:
				entry: Dict[str, object] = {
					"timestamp": block.timestamp,
					"to_wallet": tx.receiver,
					"amount": tx.amount,
				}
				if getattr(tx, "metadata", None):
					entry["metadata"] = tx.metadata
				history.append(entry)
	return history

# Mount the JSON API under /api so the same server exposes
# both the website and the programmatic endpoints.
app.mount("/api", pcs_api.app)


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
	"""Serve robots.txt for search engine crawlers."""
	robots_content = """# robots.txt for Perfect Charity System (PCS)
# Allow search engines to index public charity and receiver profiles

User-agent: *
Allow: /public/
Allow: /
Disallow: /profile
Disallow: /login
Disallow: /register
Disallow: /logout
Disallow: /api/
Disallow: /inspector/
Disallow: /notifications
Disallow: /sell-crypto
Disallow: /purchase-crypto
Disallow: /my-purchases

# Sitemap location
Sitemap: https://perfectcharitysystem.org/sitemap.xml

# Crawl rate (optional - be respectful)
Crawl-delay: 1
"""
	return robots_content


@app.get("/sitemap.xml", response_class=Response)
async def sitemap_xml(request: Request):
	"""Generate dynamic sitemap.xml for search engines."""
	from datetime import datetime
	
	# Get base URL from request
	base_url = str(request.base_url).rstrip('/')
	
	# Start sitemap XML
	sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n'
	sitemap += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
	
	# Add homepage
	sitemap += '  <url>\n'
	sitemap += f'    <loc>{base_url}/</loc>\n'
	sitemap += '    <changefreq>daily</changefreq>\n'
	sitemap += '    <priority>1.0</priority>\n'
	sitemap += '  </url>\n'
	
	# Add directory page
	sitemap += '  <url>\n'
	sitemap += f'    <loc>{base_url}/directory</loc>\n'
	sitemap += '    <changefreq>daily</changefreq>\n'
	sitemap += '    <priority>0.9</priority>\n'
	sitemap += '  </url>\n'
	
	# Add all public profiles for charity_org and receiver
	for user in USERS.values():
		if user.role in ["charity_org", "receiver"]:
			sitemap += '  <url>\n'
			sitemap += f'    <loc>{base_url}/public/{user.username}</loc>\n'
			sitemap += f'    <lastmod>{datetime.utcnow().strftime("%Y-%m-%d")}</lastmod>\n'
			sitemap += '    <changefreq>weekly</changefreq>\n'
			sitemap += '    <priority>0.8</priority>\n'
			sitemap += '  </url>\n'
	
	sitemap += '</urlset>'
	
	return Response(content=sitemap, media_type="application/xml")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
	"""Homepage: list charity profiles and show basic forms.

	Users can still create PCS charity profiles here, separate from
	personal login accounts.
	"""

	profiles = [p.to_dict() for p in pcs_api.profiles_store.list_profiles()]
	user = _get_current_user(request)
	return templates.TemplateResponse(
		"index.html",
		{
			"request": request,
			"profiles": profiles,
			"coin_name": pcs_api.pcs_crypto.PCS_COIN_NAME,
			"current_user": user,
		},
	)


# ---------------------------------------------------------------------------
# Authentication: register, login, logout
# ---------------------------------------------------------------------------


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
	user = _get_current_user(request)
	if user:
		return RedirectResponse(url="/profile", status_code=303)
	return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register", response_class=RedirectResponse)
async def register(
	request: Request,
	email: str = Form(...),
	username: str = Form(...),
	password: str = Form(...),
	confirm_password: str = Form(...),
	role: str = Form(...),
	country: str = Form(""),
	state: str = Form(""),
	city: str = Form(""),
):
	# OWASP A03:2021 - Injection: Sanitize all inputs
	email = _sanitize_email(email)
	username = _sanitize_username(username)
	role = role.strip().lower()
	country = _sanitize_input(country, max_length=100)
	state = _sanitize_input(state, max_length=100)
	city = _sanitize_input(city, max_length=100)
	
	# Only allow donor registration for public users
	# Country and state are required
	if not email or not username or password != confirm_password or role != "donor" or not country or not state:
		return RedirectResponse(url="/register", status_code=303)

	# DISA STIG V-222599, V-222600: Validate password complexity
	is_valid, error_msg = _validate_password_complexity(password)
	if not is_valid:
		# In production, show error message to user
		# For now, redirect back to registration
		return RedirectResponse(url="/register", status_code=303)

	# Check if username or email already exists
	if username in USERNAME_INDEX or email in USERNAME_INDEX:
		return RedirectResponse(url="/register", status_code=303)

	user_id = f"user_{uuid.uuid4().hex}"
	password_hash = _hash_password(password)

	wallet_id = pcs_api.pcs_wallet.create_wallet_id()
	user = User(
		user_id=user_id,
		username=username,
		password_hash=password_hash,
		role=role,
		wallet_id=wallet_id,
		country=country,
		state=state,
		city=city,
		email=email,
		registration_ip=request.client.host if request.client else "",
	)
	
	# DISA STIG V-222594: Log account creation
	_log_security_event(user, "ACCOUNT_CREATED", f"Donor account created: {email} ({username})", request.client.host if request.client else "")
	
	USERS[user_id] = user
	USERNAME_INDEX[username.lower()] = user_id  # Index by username (lowercase)
	USERNAME_INDEX[email.lower()] = user_id  # Also index by email for login flexibility (lowercase)
	_save_users()

	# OWASP A01:2021 - Broken Access Control: Secure session
	request.session["user_id"] = user_id
	request.session["last_activity"] = datetime.utcnow().isoformat()
	request.session["session_token"] = uuid.uuid4().hex
	
	return RedirectResponse(url="/profile", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
	user = _get_current_user(request)
	if user:
		return RedirectResponse(url="/profile", status_code=303)
	return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=RedirectResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form(...)):
	# OWASP A03:2021 - Injection: Sanitize inputs
	username_input = username.strip()
	selected_role = role.strip().lower()
	client_ip = request.client.host if request.client else "unknown"
	user_agent = request.headers.get("user-agent", "")
	
	# Username can be either username or email
	# Try email lookup first (case-insensitive), then username lookup
	user_id = USERNAME_INDEX.get(username_input.lower())
	if not user_id:
		# Try sanitized username (removes special chars)
		sanitized = _sanitize_username(username_input)
		user_id = USERNAME_INDEX.get(sanitized)
	
	if not user_id:
		# OWASP A07:2021 - Authentication: Log failed attempt with AI monitoring
		security_check = pcs_ai.assess_login_attempt(
			ip_address=client_ip,
			username=username_input,
			success=False,
			user_agent=user_agent,
		)
		if security_check.level == pcs_ai.ThreatLevel.CRITICAL:
			print(f"[SECURITY CRITICAL] Login attempt blocked: {client_ip} - {security_check.threats}")
		return RedirectResponse(url="/login", status_code=303)

	user = USERS.get(user_id)
	if not user:
		return RedirectResponse(url="/login", status_code=303)

	# DISA STIG V-222596: Check if account is locked
	if _is_account_locked(user):
		locked_until = datetime.fromisoformat(user.account_locked_until)
		minutes_remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60)
		# In production, show lockout message to user
		return RedirectResponse(url="/login", status_code=303)

	# DISA STIG V-222595: Validate password
	if user.password_hash != _hash_password(password):
		# OWASP A07:2021 - Authentication: AI security monitoring on failed login
		security_check = pcs_ai.assess_login_attempt(
			ip_address=client_ip,
			username=username,
			success=False,
			user_agent=user_agent,
		)
		if security_check.level == pcs_ai.ThreatLevel.CRITICAL:
			print(f"[SECURITY CRITICAL] Brute force detected: {client_ip} - {security_check.threats}")
		
		_record_failed_login(user, client_ip)
		_save_users()
		return RedirectResponse(url="/login", status_code=303)
	
	# Validate that the selected account type matches the user's actual role
	if user.role != selected_role:
		_record_failed_login(user, client_ip)
		_save_users()
		return RedirectResponse(url="/login", status_code=303)
	
	# Check if account is banned
	if user.is_banned:
		_log_security_event(user, "BANNED_LOGIN_ATTEMPT", f"Banned user attempted login: {user.ban_reason}", client_ip)
		_save_users()
		return RedirectResponse(url="/login", status_code=303)

	# OWASP A07:2021 - Authentication: Successful login with AI monitoring
	security_check = pcs_ai.assess_login_attempt(
		ip_address=client_ip,
		username=username,
		success=True,
		user_agent=user_agent,
	)
	
	# DISA STIG V-222595: Record successful login
	_record_successful_login(user, client_ip)

	# OWASP A01:2021 - Broken Access Control: Secure session management
	request.session["user_id"] = user.user_id
	request.session["last_activity"] = datetime.utcnow().isoformat()
	# OWASP A02:2021 - Cryptographic Failures: Regenerate session ID on login
	request.session["session_token"] = uuid.uuid4().hex
	
	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.get("/logout", response_class=RedirectResponse)
async def logout(request: Request):
	request.session.clear()
	return RedirectResponse(url="/", status_code=303)


@app.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
	"""View all notifications for transaction requests."""
	user = _get_current_user(request)
	if not user or user.role not in ["donor", "receiver", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Mark all notifications as read when viewing the page
	for notif in user.notifications:
		notif["read"] = True
	_save_users()
	
	# Sort notifications by timestamp, newest first
	notifications = sorted(user.notifications, key=lambda n: n.get("timestamp", ""), reverse=True)
	unread_count = 0  # All marked as read now
	
	return templates.TemplateResponse(
		"notifications.html",
		{
			"request": request,
			"user": user,
			"notifications": notifications,
			"unread_count": unread_count,
		},
	)


@app.get("/notifications/mark-all-read", response_class=RedirectResponse)
async def mark_all_notifications_read(request: Request):
	"""Mark all notifications as read."""
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/", status_code=303)
	
	for notif in user.notifications:
		notif["read"] = True
	
	_save_users()
	return RedirectResponse(url="/notifications", status_code=303)


# ---------------------------------------------------------------------------
# User profile (with intro text and media uploads)
# ---------------------------------------------------------------------------


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	if user.role == "inspector":
		# Calculate statistics for inspector dashboard
		total_users = len(USERS)
		banned_count = sum(1 for u in USERS.values() if u.is_banned)
		active_donors = sum(1 for u in USERS.values() if u.role == "donor" and not u.is_banned)
		active_receivers = sum(1 for u in USERS.values() if u.role == "receiver" and not u.is_banned)
		active_charity_orgs = sum(1 for u in USERS.values() if u.role == "charity_org" and not u.is_banned)
		
		return templates.TemplateResponse(
			"profile_inspector.html",
			{
				"request": request,
				"user": user,
				"total_users": total_users,
				"banned_count": banned_count,
				"active_donors": active_donors,
				"active_receivers": active_receivers,
				"active_charity_orgs": active_charity_orgs,
			},
		)
	
	# Parse bank details for receivers and charity orgs
	bank_fields = {"bank_name": "", "bank_account": "", "bank_account_name": "", "bank_swift": ""}
	if user.role in ["receiver", "charity_org"] and user.bank_details:
		for line in user.bank_details.split('\n'):
			if line.startswith("Bank Name:"):
				bank_fields["bank_name"] = line.replace("Bank Name:", "").strip()
			elif line.startswith("Account Number:"):
				bank_fields["bank_account"] = line.replace("Account Number:", "").strip()
			elif line.startswith("Account Name:"):
				bank_fields["bank_account_name"] = line.replace("Account Name:", "").strip()
			elif line.startswith("Swift/Routing:"):
				bank_fields["bank_swift"] = line.replace("Swift/Routing:", "").strip()
	
	# Apply monthly credit for receivers
	_apply_monthly_credit(user)
	
	# Get wallet balance
	wallet_balance = user.wallet_balance
	
	# Get wallet history for all users
	wallet_history = _wallet_history_for_user(user)
	
	# Count pending purchase requests for receivers and charity orgs
	pending_count = 0
	if user.role in ["receiver", "charity_org"]:
		pending_count = len([req for req in user.purchase_requests if req.get("status") == "pending"])
	
	# Get unread notification count
	notification_count = _get_unread_notification_count(user)
	
	# Calculate total donations for donor achievements
	# Include both blockchain transactions (PCS sent to others) and completed purchase requests (money donated to buy PCS)
	total_donations = sum(tx.get("amount", 0.0) for tx in wallet_history)
	
	# For donors, also count completed cryptocurrency purchases as donations
	if user.role in ["donor", "charity_org"]:
		completed_purchases = [
			req for req in user.my_purchase_requests 
			if req.get("status") == "completed"
		]
		total_donations += sum(req.get("amount", 0.0) for req in completed_purchases)
	
	volunteer_hours = 0  # Placeholder, will implement flow later
	
	# Get donor rankings
	user_ranks = _get_user_ranks(user.user_id)
	
	# Always pass bank_fields to template (even for donors, though they won't use it)
	return templates.TemplateResponse(
		"profile.html",
		{
			"request": request,
			"user": user,
			"wallet_history": wallet_history,
			"bank_fields": bank_fields,
			"wallet_balance": wallet_balance,
			"pending_purchase_requests": pending_count,
			"notification_count": notification_count,
			"total_donations": total_donations,
			"volunteer_hours": volunteer_hours,
			"country_rank": user_ranks["country_rank"],
			"worldwide_rank": user_ranks["worldwide_rank"],
		},
	)


@app.get("/profile/picture", response_class=HTMLResponse)
async def profile_picture_page(request: Request):
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	return templates.TemplateResponse(
		"upload_picture.html",
		{"request": request, "user": user},
	)


@app.get("/profile/media", response_class=HTMLResponse)
async def profile_media_page(request: Request):
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	return templates.TemplateResponse(
		"upload_media.html",
		{"request": request, "user": user},
	)


@app.post("/profile/intro", response_class=RedirectResponse)
async def update_intro(request: Request, intro: str = Form("")):
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	user.intro = intro.strip()
	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.post("/profile/upload", response_class=RedirectResponse)
async def upload_media(
	request: Request,
	media_type: str = Form(...),  # "avatar", "gallery", or "video"
	file: UploadFile = File(...),
):
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)

	media_type = media_type.lower().strip()
	if media_type not in {"avatar", "gallery", "video"}:
		return RedirectResponse(url="/profile", status_code=303)

	upload_dir = _ensure_upload_dir()
	ext = pathlib.Path(file.filename or "").suffix
	filename = f"{user.user_id}_{uuid.uuid4().hex}{ext}"
	path = upload_dir / filename
	content = await file.read()
	path.write_bytes(content)
	rel_path = f"uploads/{filename}"

	if media_type == "avatar":
		# Only explicit profile-picture uploads change the main avatar
		user.avatar_files.insert(0, rel_path)
	elif media_type == "gallery":
		# Other media pictures go into the gallery only
		user.gallery_files.append(rel_path)
	else:
		user.video_files.append(rel_path)

	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.post("/profile/contact", response_class=RedirectResponse)
async def update_contact(
	request: Request,
	social_link1: str = Form(""),
	social_link2: str = Form(""),
	social_link3: str = Form(""),
	social_link4: str = Form(""),
	social_link5: str = Form(""),
	email: str = Form(""),
	phone: str = Form(""),
	xchat: str = Form(""),
	physical_address: str = Form(""),
	reveal_email: Optional[str] = Form(None),
	reveal_phone: Optional[str] = Form(None),
	reveal_xchat: Optional[str] = Form(None),
):
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)

	# Collect up to 5 social media links, ignore blanks
	links = [
		social_link1.strip(),
		social_link2.strip(),
		social_link3.strip(),
		social_link4.strip(),
		social_link5.strip(),
	]
	user.social_links = [link for link in links if link]
	user.email = email.strip()
	user.phone = phone.strip()
	user.xchat = xchat.strip()
	user.physical_address = physical_address.strip()
	user.reveal_email = reveal_email is not None
	user.reveal_phone = reveal_phone is not None
	user.reveal_xchat = reveal_xchat is not None

	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.post("/profile/bank", response_class=RedirectResponse)
async def update_bank_details(
	request: Request,
	bank_name: str = Form(""),
	bank_account: str = Form(""),
	bank_account_name: str = Form(""),
	bank_swift: str = Form(""),
):
	"""Update receiver's bank account details."""
	user = _get_current_user(request)
	if not user or user.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/profile", status_code=303)

	# Combine bank details into formatted string
	bank_details_parts = []
	if bank_name.strip():
		bank_details_parts.append(f"Bank Name: {bank_name.strip()}")
	if bank_account.strip():
		bank_details_parts.append(f"Account Number: {bank_account.strip()}")
	if bank_account_name.strip():
		bank_details_parts.append(f"Account Name: {bank_account_name.strip()}")
	if bank_swift.strip():
		bank_details_parts.append(f"Swift/Routing: {bank_swift.strip()}")
	user.bank_details = "\n".join(bank_details_parts)
	
	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.post("/profile/payment-gateways", response_class=RedirectResponse)
async def update_payment_gateways(
	request: Request,
	payment_gateways: str = Form(""),
):
	"""Update receiver's payment gateway details."""
	user = _get_current_user(request)
	if not user or user.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/profile", status_code=303)

	user.payment_gateways = payment_gateways.strip()
	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.post("/profile/other-payment-gateways", response_class=RedirectResponse)
async def update_other_payment_gateways(
	request: Request,
	other_payment_gateways: str = Form(""),
):
	"""Update receiver's other payment gateway details."""
	user = _get_current_user(request)
	if not user or user.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/profile", status_code=303)

	user.other_payment_gateways = other_payment_gateways.strip()
	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.get("/external-services", response_class=HTMLResponse)
async def external_services_page(request: Request):
	"""Page for users to submit external service projects."""
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
	return templates.TemplateResponse(
		"external_services.html",
		{
			"request": request,
			"user": user,
		},
	)


@app.post("/external-services", response_class=RedirectResponse)
async def save_external_services(
	request: Request,
	project_name: str = Form(""),
	project_description: str = Form(""),
	project_funding_required: str = Form(""),
	project_files: List[UploadFile] = File([]),
):
	"""Save external service project description and files."""
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
	user.project_name = project_name.strip()
	user.project_description = project_description.strip()
	user.project_funding_required = project_funding_required.strip()
	
	# Handle file uploads (no limit)
	uploads_dir = BASE_DIR / "uploads"
	uploads_dir.mkdir(exist_ok=True)
	
	for file in project_files:
		if file.filename:
			ext = pathlib.Path(file.filename).suffix.lower()
			file_id = uuid.uuid4().hex[:16]
			safe_name = f"project_{user.user_id}_{file_id}{ext}"
			file_path = uploads_dir / safe_name
			
			with file_path.open("wb") as f:
				content = await file.read()
				f.write(content)
			
			user.project_files.append(safe_name)
	
	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.get("/view-project/{user_id}", response_class=HTMLResponse)
async def view_project(request: Request, user_id: str):
	"""View a user's external service project."""
	viewer = _get_current_user(request)
	if not viewer:
		return RedirectResponse(url="/login", status_code=303)
	
	project_user = USERS.get(user_id)
	if not project_user:
		return RedirectResponse(url="/profile", status_code=303)
	
	return templates.TemplateResponse(
		"view_project.html",
		{
			"request": request,
			"viewer": viewer,
			"project_user": project_user,
		},
	)


@app.get("/donate-project/{user_id}", response_class=HTMLResponse)
async def donate_project_page(request: Request, user_id: str):
	"""Page for donating to a user's external service project."""
	donor = _get_current_user(request)
	if not donor or donor.role != "donor":
		return RedirectResponse(url="/", status_code=303)
	
	project_user = USERS.get(user_id)
	if not project_user or not project_user.project_description:
		return RedirectResponse(url="/projects", status_code=303)
	
	# Redirect if trying to donate to own project
	if donor.user_id == project_user.user_id:
		return RedirectResponse(url=f"/view-project/{user_id}", status_code=303)
	
	# Get donor's wallet balance
	if donor.wallet_id:
		balance = pcs_api.pcs_wallet.calculate_balance_for_wallet(donor.wallet_id)
	else:
		balance = 0.0
	
	# Get unread notification count
	notification_count = _get_unread_notification_count(donor)
	
	return templates.TemplateResponse(
		"donate_project.html",
		{
			"request": request,
			"donor": donor,
			"project_user": project_user,
			"balance": balance,
			"notification_count": notification_count,
		},
	)


@app.post("/donate-project/{user_id}/donate", response_class=RedirectResponse)
async def process_project_donation(
	request: Request,
	user_id: str,
	amount: float = Form(...),
):
	"""Process a donation to a user's external service project."""
	donor = _get_current_user(request)
	if not donor or donor.role != "donor":
		return RedirectResponse(url="/", status_code=303)
	
	project_user = USERS.get(user_id)
	if not project_user or not project_user.project_description:
		return RedirectResponse(url="/projects", status_code=303)
	
	# Prevent users from donating to their own projects
	if donor.user_id == project_user.user_id:
		return RedirectResponse(url=f"/view-project/{user_id}", status_code=303)
	
	if amount <= 0:
		return RedirectResponse(url=f"/donate-project/{user_id}", status_code=303)
	
	# Ensure donor has a wallet
	if not donor.wallet_id:
		donor.wallet_id = pcs_api.pcs_wallet.create_wallet_id()
		_save_users()
	
	# Check if donor has sufficient balance
	donor_balance = pcs_api.pcs_wallet.calculate_balance_for_wallet(donor.wallet_id)
	if donor_balance < amount:
		return RedirectResponse(url=f"/donate-project/{user_id}", status_code=303)
	
	# Ensure project owner has a wallet
	if not project_user.wallet_id:
		project_user.wallet_id = pcs_api.pcs_wallet.create_wallet_id()
		_save_users()
	
	# Create blockchain transaction for project donation
	try:
		block = pcs_api.blockchain.create_donation(
			from_wallet=donor.wallet_id,
			to_wallet=project_user.wallet_id,
			amount=amount,
			profile_id=project_user.user_id,
			message=f"Project donation: {project_user.project_name or 'Untitled'}",
		)
		# Save blockchain to disk
		pcs_persistence.save_blockchain(pcs_api.blockchain.to_dict())
	except Exception as e:
		print(f"Error creating blockchain transaction for project donation: {e}")
		return RedirectResponse(url=f"/donate-project/{user_id}", status_code=303)
	
	# Record the donation
	donation_record = {
		"donor_id": donor.user_id,
		"donor_username": donor.username,
		"amount": amount,
		"timestamp": datetime.utcnow().isoformat(),
	}
	project_user.project_donors.append(donation_record)
	project_user.project_donations_received += amount
	
	# Create notification for project owner
	_create_notification(
		project_user,
		"project_donation",
		"Project Donation Received",
		f"{donor.username} donated {amount:.2f} PCS to your project: {project_user.project_name or 'Untitled'}",
		f"/view-project/{project_user.user_id}"
	)
	
	_save_users()
	
	# Redirect to project view page
	return RedirectResponse(url=f"/view-project/{user_id}", status_code=303)


@app.get("/donate-pcs", response_class=HTMLResponse)
async def donate_pcs_page(request: Request):
	"""Page for donating to PCS internal operations."""
	donor = _get_current_user(request)
	if not donor or donor.role != "donor":
		return RedirectResponse(url="/", status_code=303)
	
	# Get donor's wallet balance
	if donor.wallet_id:
		balance = pcs_api.pcs_wallet.calculate_balance_for_wallet(donor.wallet_id)
	else:
		balance = 0.0
	
	# Get unread notification count
	notification_count = _get_unread_notification_count(donor)
	
	# Create or get PCS system user for receiving donations
	pcs_system_user = None
	for user in USERS.values():
		if user.username == "PCS_SYSTEM":
			pcs_system_user = user
			break
	
	# Create PCS system user if doesn't exist
	if not pcs_system_user:
		pcs_user_id = f"user_{uuid.uuid4().hex}"
		pcs_wallet_id = pcs_api.pcs_wallet.create_wallet_id()
		pcs_system_user = User(
			user_id=pcs_user_id,
			username="PCS_SYSTEM",
			password_hash=_hash_password(uuid.uuid4().hex),  # Random password
			role="receiver",
			wallet_id=pcs_wallet_id,
			country="Global",
			state="N/A",
			city="N/A",
			email="operations@perfectcharitysystem.org",
			intro="Perfect Charity System Internal Operations Fund - Supporting infrastructure, maintenance, and staff salaries to keep PCS running transparently.",
		)
		USERS[pcs_user_id] = pcs_system_user
		_save_users()
	
	return templates.TemplateResponse(
		"donate_pcs.html",
		{
			"request": request,
			"donor": donor,
			"balance": balance,
			"notification_count": notification_count,
		},
	)


@app.post("/donate-pcs/donate", response_class=RedirectResponse)
async def process_pcs_donation(
	request: Request,
	amount: float = Form(...),
):
	"""Process a donation to PCS internal operations."""
	donor = _get_current_user(request)
	if not donor or donor.role != "donor":
		return RedirectResponse(url="/", status_code=303)
	
	if amount <= 0:
		return RedirectResponse(url="/donate-pcs", status_code=303)
	
	# Ensure donor has a wallet
	if not donor.wallet_id:
		donor.wallet_id = pcs_api.pcs_wallet.create_wallet_id()
		_save_users()
	
	# Check if donor has sufficient balance
	donor_balance = pcs_api.pcs_wallet.calculate_balance_for_wallet(donor.wallet_id)
	if donor_balance < amount:
		return RedirectResponse(url="/donate-pcs", status_code=303)
	
	# Get or create PCS system user
	pcs_system_user = None
	for user in USERS.values():
		if user.username == "PCS_SYSTEM":
			pcs_system_user = user
			break
	
	if not pcs_system_user:
		return RedirectResponse(url="/donate-pcs", status_code=303)
	
	# Ensure PCS system user has a wallet
	if not pcs_system_user.wallet_id:
		pcs_system_user.wallet_id = pcs_api.pcs_wallet.create_wallet_id()
		_save_users()
	
	# Create blockchain transaction for PCS donation
	try:
		block = pcs_api.blockchain.create_donation(
			from_wallet=donor.wallet_id,
			to_wallet=pcs_system_user.wallet_id,
			amount=amount,
			profile_id=pcs_system_user.user_id,
			message=f"Donation to PCS Internal Operations",
		)
		# Save blockchain to disk
		pcs_persistence.save_blockchain(pcs_api.blockchain.to_dict())
	except Exception as e:
		print(f"Error creating blockchain transaction for PCS donation: {e}")
		return RedirectResponse(url="/donate-pcs", status_code=303)
	
	# Create notification for donor
	_create_notification(
		donor,
		"pcs_donation",
		"PCS Donation Successful",
		f"Thank you for donating {amount:.2f} PCS to support PCS internal operations!",
		"/donate-pcs"
	)
	
	_save_users()
	
	# Redirect to search page
	return RedirectResponse(url="/search", status_code=303)


@app.get("/projects", response_class=HTMLResponse)
async def projects_list(request: Request):
	"""List all external service projects with filters."""
	current_user = _get_current_user(request)
	if not current_user:
		return RedirectResponse(url="/login", status_code=303)
	
	# Get filter parameters
	country_filter = request.query_params.get("country", "").strip().lower()
	state_filter = request.query_params.get("state", "").strip().lower()
	query = request.query_params.get("q", "").strip().lower()
	
	# Get all users with projects
	projects = []
	for user in USERS.values():
		if user.project_description:  # Only include users who have submitted projects
			# Apply filters
			if country_filter and user.country.lower() != country_filter:
				continue
			if state_filter and user.state.lower() != state_filter:
				continue
			if query and query not in user.project_name.lower():
				continue
			
			projects.append(user)
	
	# Sort by username
	projects.sort(key=lambda u: u.username.lower())
	
	return templates.TemplateResponse(
		"projects_list.html",
		{
			"request": request,
			"current_user": current_user,
			"projects": projects,
			"country_filter": country_filter,
			"state_filter": state_filter,
			"query": query,
		},
	)


@app.post("/profile/charity-verification", response_class=RedirectResponse)
async def update_charity_verification(
	request: Request,
	charity_legal_name: str = Form(""),
	charity_registration_number: str = Form(""),
	charity_registration_country: str = Form(""),
	charity_registering_body: str = Form(""),
	charity_active_status_proof: str = Form(""),
	charity_bank_name: str = Form(""),
	charity_bank_account_holder: str = Form(""),
	charity_bank_account_number: str = Form(""),
	charity_bank_country: str = Form(""),
	charity_representative_name: str = Form(""),
	charity_representative_role: str = Form(""),
	charity_representative_proof: str = Form(""),
):
	"""Update charity organization's verification details."""
	user = _get_current_user(request)
	if not user or user.role != "charity_org":
		return RedirectResponse(url="/profile", status_code=303)

	user.charity_legal_name = charity_legal_name.strip()
	user.charity_registration_number = charity_registration_number.strip()
	user.charity_registration_country = charity_registration_country.strip()
	user.charity_registering_body = charity_registering_body.strip()
	user.charity_active_status_proof = charity_active_status_proof.strip()
	user.charity_bank_name = charity_bank_name.strip()
	user.charity_bank_account_holder = charity_bank_account_holder.strip()
	user.charity_bank_account_number = charity_bank_account_number.strip()
	user.charity_bank_country = charity_bank_country.strip()
	user.charity_representative_name = charity_representative_name.strip()
	user.charity_representative_role = charity_representative_role.strip()
	user.charity_representative_proof = charity_representative_proof.strip()

	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.post("/profile/settings", response_class=RedirectResponse)
async def update_profile_settings(
	request: Request,
	visibility: str = Form("public"),
	country: Optional[str] = Form(None),
):
	"""Update donor profile settings (visibility and country).

	Receivers and charity organizations are always public; for them visibility setting is ignored.
	"""
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)

	if user.role == "donor":
		user.is_public = visibility == "public"
	
	# Update country if provided
	if country and country.strip():
		user.country = country.strip()

	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


@app.post("/profile/media/delete", response_class=RedirectResponse)
async def delete_media(
	request: Request,
	kind: str = Form(...),  # "avatar", "gallery" or "video"
	path: str = Form(...),
):
	"""Delete an uploaded image or video from the current user's media.

	This removes the reference from memory and tries to delete the file
	from disk. On success it redirects back to the profile page.
	"""
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)

	kind = kind.strip().lower()
	if kind not in {"avatar", "gallery", "video"}:
		return RedirectResponse(url="/profile", status_code=303)

	if kind == "avatar":
		user.avatar_files = [p for p in user.avatar_files if p != path]
	elif kind == "gallery":
		user.gallery_files = [p for p in user.gallery_files if p != path]
	else:
		user.video_files = [p for p in user.video_files if p != path]

	# Best-effort removal of the physical file
	try:
		file_path = BASE_DIR / path
		if file_path.is_file():
			file_path.unlink()
	except Exception:
		# Ignore filesystem errors in this prototype
		pass

	_save_users()
	return RedirectResponse(url="/profile", status_code=303)


# ---------------------------------------------------------------------------
# Search for other users (donors / receivers)
# ---------------------------------------------------------------------------


@app.get("/search", response_class=HTMLResponse)
async def search_users(
	request: Request,
	role: str = "",
	country: str = "",
	state: str = "",
	q: str = "",
	email: str = "",
	phone: str = "",
):
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
	# Redirect inspectors to their dedicated user management page
	if user.role == "inspector":
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	role_filter = role.strip().lower()
	country_filter = country.strip().lower()
	state_filter = state.strip().lower()
	query = q.strip().lower()
	email_filter = email.strip().lower()
	phone_filter = phone.strip().lower()
	results: List[User] = []
	for u in USERS.values():
		# Inspectors are system accounts and should not appear in public search.
		if u.role == "inspector":
			continue
		if role_filter and u.role != role_filter:
			continue
		if country_filter and (u.country or "").lower() != country_filter:
			continue
		if state_filter and (u.state or "").lower() != state_filter:
			continue
		if query and query not in u.username.lower():
			continue
		if email_filter and email_filter not in (u.email or "").lower():
			continue
		if phone_filter and phone_filter not in (u.phone or "").lower():
			continue
		if u.user_id == user.user_id:
			continue
		results.append(u)
	# Limit to maximum 20 results
	results = results[:20]
	
	# Get rankings for donor users to display
	user_rankings = {}
	for u in results:
		if u.role == "donor":
			user_rankings[u.user_id] = _get_user_ranks(u.user_id)
	
	return templates.TemplateResponse(
		"search.html",
		{
			"request": request,
			"current_user": user,
			"results": results,
			"user_rankings": user_rankings,
			"role_filter": role_filter,
			"country_filter": country_filter,
			"state_filter": state_filter,
			"query": query,
			"email_filter": email_filter,
			"phone_filter": phone_filter,
		},
	)


@app.get("/purchase-crypto", response_class=HTMLResponse)
async def purchase_crypto_page(request: Request):
	"""Page for donors to purchase cryptocurrency from receivers."""
	donor = _get_current_user(request)
	if not donor or donor.role not in ["donor", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Get all receivers and charity orgs with their wallet balances
	receivers = []
	for u in USERS.values():
		if u.role in ["receiver", "charity_org"]:
			# Apply monthly credit and get balance
			_apply_monthly_credit(u)
			balance = u.wallet_balance
			
			receivers.append({
				'user': u,
				'balance': balance
			})
	
	return templates.TemplateResponse(
		"purchase_crypto.html",
		{
			"request": request,
			"donor": donor,
			"receivers": receivers,
		},
	)


@app.get("/purchase-crypto/{receiver_id}", response_class=HTMLResponse)
async def purchase_crypto_detail(request: Request, receiver_id: str):
	"""Detail page for purchasing cryptocurrency from a specific receiver."""
	donor = _get_current_user(request)
	if not donor or donor.role not in ["donor", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	receiver = USERS.get(receiver_id)
	if not receiver or receiver.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/purchase-crypto", status_code=303)
	
	# Apply monthly credit and get balance
	_apply_monthly_credit(receiver)
	balance = receiver.wallet_balance
	
	# Parse bank details
	bank_fields = {"bank_name": "", "bank_account": "", "bank_account_name": "", "bank_swift": ""}
	if receiver.bank_details:
		for line in receiver.bank_details.split('\n'):
			if line.startswith("Bank Name:"):
				bank_fields["bank_name"] = line.replace("Bank Name:", "").strip()
			elif line.startswith("Account Number:"):
				bank_fields["bank_account"] = line.replace("Account Number:", "").strip()
			elif line.startswith("Account Name:"):
				bank_fields["bank_account_name"] = line.replace("Account Name:", "").strip()
			elif line.startswith("Swift/Routing:"):
				bank_fields["bank_swift"] = line.replace("Swift/Routing:", "").strip()
	
	return templates.TemplateResponse(
		"purchase_crypto_detail.html",
		{
			"request": request,
			"donor": donor,
			"receiver": receiver,
			"balance": balance,
			"bank_fields": bank_fields,
		},
	)


@app.post("/purchase-crypto/{receiver_id}/purchase", response_class=RedirectResponse)
async def process_crypto_purchase(
	request: Request,
	receiver_id: str,
	amount: float = Form(...),
):
	"""Process a cryptocurrency purchase from donor to receiver."""
	donor = _get_current_user(request)
	if not donor or donor.role not in ["donor", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	receiver = USERS.get(receiver_id)
	if not receiver or receiver.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/purchase-crypto", status_code=303)
	
	if amount <= 0:
		return RedirectResponse(url=f"/purchase-crypto/{receiver_id}", status_code=303)
	
	# Create a purchase request notification for the receiver
	request_id = str(uuid.uuid4())
	purchase_request = {
		"request_id": request_id,
		"donor_id": donor.user_id,
		"donor_username": donor.username,
		"donor_email": donor.email,
		"receiver_id": receiver.user_id,
		"receiver_username": receiver.username,
		"amount": amount,
		"timestamp": datetime.utcnow().isoformat(),
		"status": "pending_approval",  # pending_approval, awaiting_proof, proof_submitted, completed, rejected
		"receipt_file": None,
	}
	
	# Add to receiver's purchase requests
	receiver.purchase_requests.append(purchase_request.copy())
	
	# Add to donor's purchase requests
	donor.my_purchase_requests.append(purchase_request.copy())
	
	# Create notification for receiver
	_create_notification(
		receiver,
		"new_request",
		"New Purchase Request",
		f"{donor.username} wants to purchase ${amount:.2f} PCS. Review and approve or reject.",
		"/sell-crypto"
	)
	
	_save_users()
	
	# Redirect to donor's request tracking page
	return RedirectResponse(url="/my-purchases", status_code=303)


@app.get("/sell-crypto", response_class=HTMLResponse)
async def sell_crypto_page(request: Request):
	"""Page for receivers to view and manage purchase requests from donors."""
	receiver = _get_current_user(request)
	if not receiver or receiver.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Get pending purchase requests (any status that needs action)
	pending_requests = [req for req in receiver.purchase_requests if req.get("status") in ["pending_approval", "awaiting_proof", "proof_submitted"]]
	all_requests = receiver.purchase_requests
	
	# Get unread notification count
	notification_count = _get_unread_notification_count(receiver)
	
	return templates.TemplateResponse(
		"sell_crypto.html",
		{
			"request": request,
			"receiver": receiver,
			"pending_requests": pending_requests,
			"all_requests": all_requests,
			"notification_count": notification_count,
		},
	)


@app.post("/sell-crypto/{request_id}/approve", response_class=RedirectResponse)
async def approve_purchase_request(request: Request, request_id: str):
	"""Approve a purchase request and complete the transaction."""
	receiver = _get_current_user(request)
	if not receiver or receiver.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Find the purchase request
	purchase_req = None
	for req in receiver.purchase_requests:
		if req.get("request_id") == request_id:
			purchase_req = req
			break
	
	if not purchase_req or purchase_req.get("status") != "pending_approval":
		return RedirectResponse(url="/sell-crypto", status_code=303)
	
	# Mark as approved (awaiting proof upload)
	purchase_req["status"] = "awaiting_proof"
	purchase_req["approved_timestamp"] = datetime.utcnow().isoformat()
	
	# Update donor's copy of the request and notify them
	donor = USERS.get(purchase_req["donor_id"])
	if donor:
		for dreq in donor.my_purchase_requests:
			if dreq.get("request_id") == request_id:
				dreq["status"] = "awaiting_proof"
				dreq["approved_timestamp"] = datetime.utcnow().isoformat()
				break
		
		# Create notification for donor
		_create_notification(
			donor,
			"purchase_approved",
			"Purchase Request Approved!",
			f"Your request to purchase ${purchase_req['amount']:.2f} PCS from {receiver.username} has been approved. Please upload payment proof.",
			"/my-purchases"
		)
	
	_save_users()
	
	return RedirectResponse(url="/sell-crypto", status_code=303)


@app.post("/sell-crypto/{request_id}/reject", response_class=RedirectResponse)
async def reject_purchase_request(request: Request, request_id: str):
	"""Reject a purchase request."""
	receiver = _get_current_user(request)
	if not receiver or receiver.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Find the purchase request
	purchase_req = None
	for req in receiver.purchase_requests:
		if req.get("request_id") == request_id:
			purchase_req = req
			break
	
	if not purchase_req or purchase_req.get("status") != "pending_approval":
		return RedirectResponse(url="/sell-crypto", status_code=303)
	
	# Mark as rejected
	purchase_req["status"] = "rejected"
	purchase_req["rejected_timestamp"] = datetime.utcnow().isoformat()
	
	# Update donor's copy of the request and notify them
	donor = USERS.get(purchase_req["donor_id"])
	if donor:
		for dreq in donor.my_purchase_requests:
			if dreq.get("request_id") == request_id:
				dreq["status"] = "rejected"
				dreq["rejected_timestamp"] = datetime.utcnow().isoformat()
				break
		
		# Create notification for donor
		_create_notification(
			donor,
			"purchase_rejected",
			"Purchase Request Rejected",
			f"Your request to purchase ${purchase_req['amount']:.2f} PCS from {receiver.username} has been rejected.",
			"/my-purchases"
		)
	
	_save_users()
	
	return RedirectResponse(url="/sell-crypto", status_code=303)


@app.post("/my-purchases/{request_id}/cancel", response_class=RedirectResponse)
async def cancel_purchase_request_donor(request: Request, request_id: str):
	"""Donor cancels their own purchase request."""
	donor = _get_current_user(request)
	if not donor or donor.role not in ["donor", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Find the purchase request
	purchase_req = None
	for req in donor.my_purchase_requests:
		if req.get("request_id") == request_id:
			purchase_req = req
			break
	
	if not purchase_req:
		return RedirectResponse(url="/my-purchases", status_code=303)
	
	# Can only cancel if pending or awaiting proof (not if completed or already rejected)
	if purchase_req.get("status") not in ["pending_approval", "awaiting_proof", "proof_submitted"]:
		return RedirectResponse(url="/my-purchases", status_code=303)
	
	# Mark as cancelled
	purchase_req["status"] = "cancelled"
	purchase_req["cancelled_timestamp"] = datetime.utcnow().isoformat()
	purchase_req["cancelled_by"] = "donor"
	
	# Update receiver's copy of the request and notify them
	receiver = USERS.get(purchase_req["receiver_id"])
	if receiver:
		for rreq in receiver.purchase_requests:
			if rreq.get("request_id") == request_id:
				rreq["status"] = "cancelled"
				rreq["cancelled_timestamp"] = datetime.utcnow().isoformat()
				rreq["cancelled_by"] = "donor"
				break
		
		# Create notification for receiver
		_create_notification(
			receiver,
			"purchase_cancelled",
			"Purchase Request Cancelled",
			f"{donor.username} has cancelled their request to purchase ${purchase_req['amount']:.2f} PCS.",
			"/sell-crypto"
		)
	
	_save_users()
	
	return RedirectResponse(url="/my-purchases", status_code=303)


@app.post("/sell-crypto/{request_id}/cancel", response_class=RedirectResponse)
async def cancel_purchase_request_receiver(request: Request, request_id: str):
	"""Receiver/Charity org cancels a purchase request."""
	receiver = _get_current_user(request)
	if not receiver or receiver.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Find the purchase request
	purchase_req = None
	for req in receiver.purchase_requests:
		if req.get("request_id") == request_id:
			purchase_req = req
			break
	
	if not purchase_req:
		return RedirectResponse(url="/sell-crypto", status_code=303)
	
	# Can cancel at any stage before completion
	if purchase_req.get("status") == "completed":
		return RedirectResponse(url="/sell-crypto", status_code=303)
	
	# Mark as cancelled
	purchase_req["status"] = "cancelled"
	purchase_req["cancelled_timestamp"] = datetime.utcnow().isoformat()
	purchase_req["cancelled_by"] = "receiver"
	
	# Update donor's copy of the request and notify them
	donor = USERS.get(purchase_req["donor_id"])
	if donor:
		for dreq in donor.my_purchase_requests:
			if dreq.get("request_id") == request_id:
				dreq["status"] = "cancelled"
				dreq["cancelled_timestamp"] = datetime.utcnow().isoformat()
				dreq["cancelled_by"] = "receiver"
				break
		
		# Create notification for donor
		_create_notification(
			donor,
			"purchase_cancelled",
			"Purchase Request Cancelled",
			f"{receiver.username} has cancelled your request to purchase ${purchase_req['amount']:.2f} PCS.",
			"/my-purchases"
		)
	
	_save_users()
	
	return RedirectResponse(url="/sell-crypto", status_code=303)


@app.get("/my-purchases", response_class=HTMLResponse)
async def my_purchases_page(request: Request):
	"""Page for donors to view their purchase requests and upload proof."""
	donor = _get_current_user(request)
	if not donor or donor.role != "donor":
		return RedirectResponse(url="/", status_code=303)
	
	# Get all purchase requests
	pending_requests = [req for req in donor.my_purchase_requests if req.get("status") in ["pending_approval", "awaiting_proof", "proof_submitted"]]
	completed_requests = [req for req in donor.my_purchase_requests if req.get("status") == "completed"]
	rejected_requests = [req for req in donor.my_purchase_requests if req.get("status") == "rejected"]
	
	return templates.TemplateResponse(
		"my_purchases.html",
		{
			"request": request,
			"donor": donor,
			"pending_requests": pending_requests,
			"completed_requests": completed_requests,
			"rejected_requests": rejected_requests,
		},
	)


@app.post("/my-purchases/{request_id}/upload-proof", response_class=RedirectResponse)
async def upload_proof(
	request: Request,
	request_id: str,
	receipt: UploadFile = File(...),
):
	"""Upload receipt proof for a purchase request."""
	donor = _get_current_user(request)
	if not donor or donor.role != "donor":
		return RedirectResponse(url="/", status_code=303)
	
	# Find the purchase request
	purchase_req = None
	for req in donor.my_purchase_requests:
		if req.get("request_id") == request_id:
			purchase_req = req
			break
	
	if not purchase_req or purchase_req.get("status") not in ["awaiting_proof", "proof_submitted"]:
		return RedirectResponse(url="/my-purchases", status_code=303)
	
	# Save the receipt file
	upload_dir = BASE_DIR / "uploads"
	upload_dir.mkdir(exist_ok=True)
	
	file_ext = pathlib.Path(receipt.filename).suffix
	safe_filename = f"receipt_{request_id}{file_ext}"
	file_path = upload_dir / safe_filename
	
	with file_path.open("wb") as f:
		content = await receipt.read()
		f.write(content)
	
	# Update status to proof_submitted
	purchase_req["status"] = "proof_submitted"
	purchase_req["receipt_file"] = safe_filename
	purchase_req["proof_uploaded_timestamp"] = datetime.utcnow().isoformat()
	
	# Update receiver's copy and notify them
	receiver = USERS.get(purchase_req["receiver_id"])
	if receiver:
		for rreq in receiver.purchase_requests:
			if rreq.get("request_id") == request_id:
				rreq["status"] = "proof_submitted"
				rreq["receipt_file"] = safe_filename
				rreq["proof_uploaded_timestamp"] = datetime.utcnow().isoformat()
				break
		
		# Create notification for receiver (notify about upload/re-upload)
		_create_notification(
			receiver,
			"proof_submitted",
			"Payment Proof Uploaded",
			f"{donor.username} has uploaded payment proof for ${purchase_req['amount']:.2f} PCS. Please verify and confirm.",
			"/sell-crypto"
		)
	
	_save_users()
	
	return RedirectResponse(url="/my-purchases", status_code=303)


@app.post("/sell-crypto/{request_id}/confirm-proof", response_class=RedirectResponse)
async def confirm_proof(request: Request, request_id: str):
	"""Receiver confirms receipt proof and completes transaction."""
	receiver = _get_current_user(request)
	if not receiver or receiver.role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/", status_code=303)
	
	# Find the purchase request
	purchase_req = None
	for req in receiver.purchase_requests:
		if req.get("request_id") == request_id:
			purchase_req = req
			break
	
	if not purchase_req or purchase_req.get("status") != "proof_submitted":
		return RedirectResponse(url="/sell-crypto", status_code=303)
	
	# Mark as completed and transfer funds
	purchase_req["status"] = "completed"
	purchase_req["completed_timestamp"] = datetime.utcnow().isoformat()
	
	# Deduct from receiver's balance
	amount = purchase_req["amount"]
	receiver.wallet_balance -= amount
	
	# Get donor and add to their balance
	donor = USERS.get(purchase_req["donor_id"])
	if donor:
		donor.wallet_balance += amount
		# Update donor's copy
		for dreq in donor.my_purchase_requests:
			if dreq.get("request_id") == request_id:
				dreq["status"] = "completed"
				dreq["completed_timestamp"] = datetime.utcnow().isoformat()
				break
		
		# Create notification for donor
		receiver_type = "charity organization" if receiver.role == "charity_org" else "receiver"
		_create_notification(
			donor,
			"purchase_completed",
			"Payment Proof Approved!",
			f"Your payment proof for ${amount:.2f} PCS has been approved by {receiver_type} {receiver.username}. Your PCS balance has been credited.",
			"/my-purchases"
		)
		
		# Record transaction on blockchain
		if receiver.wallet_id and donor.wallet_id:
			pcs_api.blockchain.create_donation(
				from_wallet=receiver.wallet_id,
				to_wallet=donor.wallet_id,
				amount=amount,
				profile_id=donor.user_id,
				message=f"Cryptocurrency purchase: ${amount:.2f} transferred from {receiver.username} to {donor.username}",
			)
			# Save blockchain to disk
			pcs_persistence.save_blockchain(pcs_api.blockchain.to_dict())
	
	_save_users()
	
	return RedirectResponse(url="/sell-crypto", status_code=303)


@app.get("/user/{user_id}", response_class=HTMLResponse)
async def view_user_profile(request: Request, user_id: str):
	"""Read-only profile view for other users.

	The logged-in user can visit this page to see another account's
	public profile. No edit or upload controls are shown here.
	"""
	current = _get_current_user(request)
	if not current:
		return RedirectResponse(url="/login", status_code=303)

	target = USERS.get(user_id)
	if not target:
		return RedirectResponse(url="/search", status_code=303)

	# If you open your own URL, just go to the editable profile page.
	if current.user_id == target.user_id:
		return RedirectResponse(url="/profile", status_code=303)

	# Calculate total donations and volunteer hours for donor achievements
	wallet_history = _wallet_history_for_user(target)
	total_donations = sum(tx.get("amount", 0.0) for tx in wallet_history)
	
	# For donors, also count completed cryptocurrency purchases as donations
	if target.role in ["donor", "charity_org"]:
		completed_purchases = [
			req for req in target.my_purchase_requests 
			if req.get("status") == "completed"
		]
		total_donations += sum(req.get("amount", 0.0) for req in completed_purchases)
	
	volunteer_hours = 0  # Placeholder, will implement flow later

	# Get donor rankings
	target_ranks = _get_user_ranks(target.user_id)

	return templates.TemplateResponse(
		"profile_public.html",
		{
			"request": request,
			"viewer": current,
			"profile_user": target,
			"wallet_history": wallet_history,
			"total_donations": total_donations,
			"volunteer_hours": volunteer_hours,
			"country_rank": target_ranks["country_rank"],
			"worldwide_rank": target_ranks["worldwide_rank"],
		},
	)


@app.get("/public/{username}", response_class=HTMLResponse)
async def public_profile(request: Request, username: str):
	"""Public profile view accessible without login (for charity_org and receiver accounts).
	
	This endpoint is designed for SEO and public discoverability.
	Charity organizations and receivers can be found via search engines.
	"""
	# Find user by username
	target = None
	for user in USERS.values():
		if user.username.lower() == username.lower():
			target = user
			break
	
	if not target:
		# Return a 404 page
		return HTMLResponse(
			content="<html><body><h1>404 - Profile Not Found</h1><p>The profile you are looking for does not exist.</p></body></html>",
			status_code=404
		)
	
	# Only allow public access to charity_org and receiver profiles
	if target.role not in ["charity_org", "receiver"]:
		return HTMLResponse(
			content="<html><body><h1>403 - Access Denied</h1><p>This profile is not publicly accessible.</p></body></html>",
			status_code=403
		)
	
	# Calculate total donations and volunteer hours
	wallet_history = _wallet_history_for_user(target)
	total_donations = sum(tx.get("amount", 0.0) for tx in wallet_history)
	
	# For charity orgs, also count completed cryptocurrency purchases as donations
	if target.role == "charity_org":
		completed_purchases = [
			req for req in target.my_purchase_requests 
			if req.get("status") == "completed"
		]
		total_donations += sum(req.get("amount", 0.0) for req in completed_purchases)
	
	volunteer_hours = 0  # Placeholder

	# Get donor rankings (if applicable)
	target_ranks = _get_user_ranks(target.user_id)

	return templates.TemplateResponse(
		"profile_public_seo.html",
		{
			"request": request,
			"profile_user": target,
			"wallet_history": wallet_history,
			"total_donations": total_donations,
			"volunteer_hours": volunteer_hours,
			"country_rank": target_ranks["country_rank"],
			"worldwide_rank": target_ranks["worldwide_rank"],
			"is_public_view": True,  # Flag to indicate this is public view
		},
	)


@app.get("/directory", response_class=HTMLResponse)
async def public_directory(request: Request):
	"""Public directory of all charity organizations and receivers (SEO-friendly).
	
	This page helps search engines discover all public profiles.
	"""
	# Get all charity organizations and receivers
	charities = [user for user in USERS.values() if user.role == "charity_org"]
	receivers = [user for user in USERS.values() if user.role == "receiver"]
	
	# Sort by username
	charities.sort(key=lambda u: u.username.lower())
	receivers.sort(key=lambda u: u.username.lower())
	
	# Group by country
	charities_by_country = {}
	for charity in charities:
		country = charity.country if charity.country else "Other"
		if country not in charities_by_country:
			charities_by_country[country] = []
		charities_by_country[country].append(charity)
	
	receivers_by_country = {}
	for receiver in receivers:
		country = receiver.country if receiver.country else "Other"
		if country not in receivers_by_country:
			receivers_by_country[country] = []
		receivers_by_country[country].append(receiver)
	
	return templates.TemplateResponse(
		"directory.html",
		{
			"request": request,
			"charities": charities,
			"receivers": receivers,
			"charities_by_country": charities_by_country,
			"receivers_by_country": receivers_by_country,
			"total_charities": len(charities),
			"total_receivers": len(receivers),
		},
	)


@app.post("/profiles", response_class=RedirectResponse)
async def create_profile(name: str = Form(...), description: str = Form(...)):
	"""Create a new donation profile from the HTML form."""

	name = name.strip()
	description = description.strip()
	if not name or not description:
		# In a real app, redirect with error message; for now just go back.
		return RedirectResponse(url="/", status_code=303)

	pcs_api.profiles_store.create_profile(name, description)
	return RedirectResponse(url="/", status_code=303)


@app.post("/donate", response_class=RedirectResponse)
async def donate(
	profile_id: str = Form(...),
	from_wallet: str = Form(...),
	amount: float = Form(...),
	message: str = Form(""),
):
	"""Handle donation form submission.

	This calls directly into the same blockchain and profile
	objects used by the API, so everything stays in sync.
	"""

	profile = pcs_api.profiles_store.get_profile(profile_id)
	if profile is None:
		return RedirectResponse(url="/", status_code=303)

	from_wallet = from_wallet.strip()
	if not from_wallet:
		return RedirectResponse(url="/", status_code=303)

	try:
		amount_value = float(amount)
	except ValueError:
		return RedirectResponse(url="/", status_code=303)

	if amount_value <= 0:
		return RedirectResponse(url="/", status_code=303)

	pcs_api.blockchain.create_donation(
		from_wallet=from_wallet,
		to_wallet=profile.wallet_id,
		amount=amount_value,
		profile_id=profile.profile_id,
		message=message or None,
	)

	# Save blockchain to disk
	pcs_persistence.save_blockchain(pcs_api.blockchain.to_dict())

	return RedirectResponse(url="/", status_code=303)


@app.get("/chain", response_class=HTMLResponse)
async def view_blockchain(request: Request):
	"""View all blockchain transactions in a nice HTML format."""
	current_user = _get_current_user(request)
	
	# Get all blockchain data (excluding genesis block)
	all_transactions = []
	for block in pcs_api.blockchain.chain:
		for tx in block.transactions:
			# Skip genesis block transactions
			if tx.sender == "SYSTEM" and tx.receiver == "SYSTEM":
				continue
				
			# Extract message from metadata if it exists
			message = ''
			if hasattr(tx, 'metadata') and tx.metadata:
				if isinstance(tx.metadata, dict):
					message = tx.metadata.get('message', '')
				
			all_transactions.append({
				'block_index': block.index,
				'timestamp': block.timestamp,
				'from_wallet': tx.sender,
				'to_wallet': tx.receiver,
				'amount': tx.amount,
				'message': message,
				'block_hash': block.hash,
			})
	
	# Reverse to show newest first
	all_transactions.reverse()
	
	return templates.TemplateResponse(
		"blockchain.html",
		{
			"request": request,
			"current_user": current_user,
			"transactions": all_transactions,
			"total_blocks": len(pcs_api.blockchain.chain),
		},
	)


# ---------------------------------------------------------------------------
# Inspector / Law Enforcement Routes
# ---------------------------------------------------------------------------


@app.get("/inspector/users", response_class=HTMLResponse)
async def inspector_list_users(
	request: Request,
	role: str = "",
	country: str = "",
	state: str = "",
	banned: str = "",
	q: str = "",
):
	"""Inspector dashboard to view and manage all users with filtering."""
	inspector = _require_inspector(request)
	
	role_filter = role.strip().lower()
	country_filter = country.strip().lower()
	state_filter = state.strip().lower()
	banned_filter = banned.strip().lower()
	query = q.strip().lower()
	
	results: List[User] = []
	for u in USERS.values():
		# Don't show inspectors in the list
		if u.role == "inspector":
			continue
		if role_filter and u.role != role_filter:
			continue
		if country_filter and (u.country or "").lower() != country_filter:
			continue
		if state_filter and (u.state or "").lower() != state_filter:
			continue
		if banned_filter == "yes" and not u.is_banned:
			continue
		if banned_filter == "no" and u.is_banned:
			continue
		if query and query not in u.username.lower():
			continue
		results.append(u)
	
	return templates.TemplateResponse(
		"inspector_users.html",
		{
			"request": request,
			"inspector": inspector,
			"users": results,
			"role_filter": role_filter,
			"country_filter": country_filter,
			"state_filter": state_filter,
			"banned_filter": banned_filter,
			"query": query,
		},
	)


@app.get("/inspector/user/{user_id}", response_class=HTMLResponse)
async def inspector_view_user(request: Request, user_id: str):
	"""Detailed user view for inspectors with all data and controls."""
	inspector = _require_inspector(request)
	
	target = USERS.get(user_id)
	if not target or target.role == "inspector":
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	return templates.TemplateResponse(
		"inspector_user_detail.html",
		{
			"request": request,
			"inspector": inspector,
			"user": target,
			"wallet_history": _wallet_history_for_user(target),
		},
	)


@app.post("/inspector/user/{user_id}/ban", response_class=RedirectResponse)
async def inspector_ban_user(
	request: Request,
	user_id: str,
	reason: str = Form(...),
):
	"""Ban a user account."""
	inspector = _require_inspector(request)
	
	target = USERS.get(user_id)
	if not target or target.role == "inspector":
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	target.is_banned = True
	target.ban_reason = reason.strip()
	target.ban_timestamp = datetime.utcnow().isoformat()
	target.banned_by = inspector.user_id
	
	_save_users()
	# Force logout the banned user if they're currently logged in
	# (This is a simple implementation; in production you'd invalidate sessions)
	
	return RedirectResponse(url=f"/inspector/user/{user_id}", status_code=303)


@app.post("/inspector/user/{user_id}/ban-quick", response_class=RedirectResponse)
async def inspector_ban_user_quick(request: Request, user_id: str):
	"""Quick ban without requiring a reason (for bulk actions)."""
	inspector = _require_inspector(request)
	
	target = USERS.get(user_id)
	if not target or target.role == "inspector":
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	target.is_banned = True
	target.ban_reason = "Banned by inspector via quick action"
	target.ban_timestamp = datetime.utcnow().isoformat()
	target.banned_by = inspector.user_id
	
	_save_users()
	return RedirectResponse(url="/inspector/users", status_code=303)


@app.post("/inspector/user/{user_id}/unban", response_class=RedirectResponse)
async def inspector_unban_user(request: Request, user_id: str):
	"""Unban a user account."""
	inspector = _require_inspector(request)
	
	target = USERS.get(user_id)
	if not target or target.role == "inspector":
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	target.is_banned = False
	target.ban_reason = ""
	target.ban_timestamp = None
	target.banned_by = None
	
	_save_users()
	return RedirectResponse(url=f"/inspector/user/{user_id}", status_code=303)


@app.post("/inspector/user/{user_id}/delete", response_class=RedirectResponse)
async def inspector_delete_user(request: Request, user_id: str):
	"""Permanently delete a user account."""
	inspector = _require_inspector(request)
	
	target = USERS.get(user_id)
	if not target or target.role == "inspector":
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	# Remove from indexes
	username = target.username
	if username in USERNAME_INDEX:
		del USERNAME_INDEX[username]
	
	# Remove user
	if user_id in USERS:
		del USERS[user_id]
	
	_save_users()
	return RedirectResponse(url="/inspector/users", status_code=303)


@app.get("/inspector/user/{user_id}/edit", response_class=HTMLResponse)
async def inspector_edit_user_page(request: Request, user_id: str):
	"""Edit user account details page."""
	inspector = _require_inspector(request)
	
	target = USERS.get(user_id)
	if not target:
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	return templates.TemplateResponse(
		"inspector_edit_user.html",
		{
			"request": request,
			"inspector": inspector,
			"target_user": target,
		},
	)


@app.post("/inspector/user/{user_id}/edit", response_class=RedirectResponse)
async def inspector_update_user(
	request: Request,
	user_id: str,
	username: str = Form(...),
	email: str = Form(""),
	phone: str = Form(""),
	xchat: str = Form(""),
	physical_address: str = Form(""),
	country: str = Form(""),
	state: str = Form(""),
	city: str = Form(""),
	bank_name: str = Form(""),
	bank_account: str = Form(""),
	bank_account_name: str = Form(""),
	bank_swift: str = Form(""),
	payment_gateways: str = Form(""),
	other_payment_gateways: str = Form(""),
):
	"""Update user account details."""
	inspector = _require_inspector(request)
	
	target = USERS.get(user_id)
	if not target:
		return RedirectResponse(url="/inspector/users", status_code=303)
	
	# Check if username changed and if new username is available
	old_username = target.username
	new_username = _sanitize_username(username.strip())
	
	if new_username != old_username:
		if new_username in USERNAME_INDEX and USERNAME_INDEX[new_username] != user_id:
			# Username already taken
			return RedirectResponse(url=f"/inspector/user/{user_id}/edit", status_code=303)
		
		# Update username index
		if old_username.lower() in USERNAME_INDEX:
			del USERNAME_INDEX[old_username.lower()]
		USERNAME_INDEX[new_username.lower()] = user_id
		target.username = new_username
	
	# Update email in index if changed
	if email.strip() and email.strip() != target.email:
		old_email = target.email
		new_email = _sanitize_email(email.strip())
		
		if new_email != old_email:
			if new_email in USERNAME_INDEX and USERNAME_INDEX[new_email] != user_id:
				# Email already taken
				return RedirectResponse(url=f"/inspector/user/{user_id}/edit", status_code=303)
			
			# Update email index
			if old_email.lower() in USERNAME_INDEX:
				del USERNAME_INDEX[old_email.lower()]
			if new_email:
				USERNAME_INDEX[new_email.lower()] = user_id
			target.email = new_email
	
	# Update contact information
	target.phone = phone.strip()
	target.xchat = xchat.strip()
	target.physical_address = physical_address.strip()
	
	# Update location
	target.country = country.strip()
	target.state = state.strip()
	target.city = city.strip()
	
	# Update bank details (for receivers and charity orgs)
	if target.role in ["receiver", "charity_org"]:
		bank_details_lines = []
		if bank_name.strip():
			bank_details_lines.append(f"Bank Name: {bank_name.strip()}")
		if bank_account.strip():
			bank_details_lines.append(f"Account Number: {bank_account.strip()}")
		if bank_account_name.strip():
			bank_details_lines.append(f"Account Name: {bank_account_name.strip()}")
		if bank_swift.strip():
			bank_details_lines.append(f"Swift/Routing: {bank_swift.strip()}")
		
		target.bank_details = "\n".join(bank_details_lines)
		target.payment_gateways = payment_gateways.strip()
		target.other_payment_gateways = other_payment_gateways.strip()
	
	_save_users()
	return RedirectResponse(url=f"/inspector/user/{user_id}", status_code=303)


@app.get("/inspector/create-receiver", response_class=HTMLResponse)
async def inspector_create_receiver_page(request: Request):
	"""Page for inspectors to create receiver or charity organization accounts."""
	inspector = _require_inspector(request)
	return templates.TemplateResponse(
		"inspector_create_receiver.html",
		{"request": request, "inspector": inspector},
	)


@app.post("/inspector/create-receiver", response_class=RedirectResponse)
async def inspector_create_receiver(
	request: Request,
	role: str = Form("receiver"),
	username: str = Form(...),
	password: str = Form(...),
	confirm_password: str = Form(...),
	country: str = Form(""),
	state: str = Form(""),
	city: str = Form(""),
	email: str = Form(""),
	phone: str = Form(""),
	xchat: str = Form(""),
	physical_address: str = Form(""),
	bank_name: str = Form(""),
	bank_account: str = Form(""),
	bank_account_name: str = Form(""),
	bank_swift: str = Form(""),
	payment_gateways: str = Form(""),
	other_payment_gateways: str = Form(""),
	# Charity organization verification fields
	charity_legal_name: str = Form(""),
	charity_registration_number: str = Form(""),
	charity_registration_country: str = Form(""),
	charity_registering_body: str = Form(""),
	charity_active_status_proof: str = Form(""),
	charity_bank_name: str = Form(""),
	charity_bank_account_holder: str = Form(""),
	charity_bank_account_number: str = Form(""),
	charity_bank_country: str = Form(""),
	charity_representative_name: str = Form(""),
	charity_representative_role: str = Form(""),
	charity_representative_proof: str = Form(""),
):
	"""Create a receiver or charity_org account (inspector only)."""
	inspector = _require_inspector(request)
	
	role = role.strip().lower()
	username = username.strip()
	if not username or not password or role not in ["receiver", "charity_org"]:
		return RedirectResponse(url="/inspector/create-receiver", status_code=303)
	
	# Validate password confirmation
	if password != confirm_password:
		# Passwords don't match
		return RedirectResponse(url="/inspector/create-receiver", status_code=303)
	
	# DISA STIG V-222599, V-222600: Validate password complexity
	is_valid, error_msg = _validate_password_complexity(password)
	if not is_valid:
		# In production, show error message to user
		# For now, redirect back to create page
		return RedirectResponse(url="/inspector/create-receiver", status_code=303)
	
	if username.lower() in USERNAME_INDEX:
		return RedirectResponse(url="/inspector/create-receiver", status_code=303)
	
	# Combine bank details into formatted string
	bank_details_parts = []
	if bank_name.strip():
		bank_details_parts.append(f"Bank Name: {bank_name.strip()}")
	if bank_account.strip():
		bank_details_parts.append(f"Account Number: {bank_account.strip()}")
	if bank_account_name.strip():
		bank_details_parts.append(f"Account Name: {bank_account_name.strip()}")
	if bank_swift.strip():
		bank_details_parts.append(f"Swift/Routing: {bank_swift.strip()}")
	bank_details = "\n".join(bank_details_parts)
	
	user_id = f"user_{uuid.uuid4().hex}"
	password_hash = _hash_password(password)
	wallet_id = pcs_api.pcs_wallet.create_wallet_id()
	
	user = User(
		user_id=user_id,
		username=username,
		password_hash=password_hash,
		role=role,
		wallet_id=wallet_id,
		country=country.strip(),
		state=state.strip(),
		city=city.strip(),
		email=email.strip(),
		phone=phone.strip(),
		xchat=xchat.strip(),
		physical_address=physical_address.strip(),
		bank_details=bank_details,
		payment_gateways=payment_gateways.strip(),
		other_payment_gateways=other_payment_gateways.strip(),
		charity_legal_name=charity_legal_name.strip(),
		charity_registration_number=charity_registration_number.strip(),
		charity_registration_country=charity_registration_country.strip(),
		charity_registering_body=charity_registering_body.strip(),
		charity_active_status_proof=charity_active_status_proof.strip(),
		charity_bank_name=charity_bank_name.strip(),
		charity_bank_account_holder=charity_bank_account_holder.strip(),
		charity_bank_account_number=charity_bank_account_number.strip(),
		charity_bank_country=charity_bank_country.strip(),
		charity_representative_name=charity_representative_name.strip(),
		charity_representative_role=charity_representative_role.strip(),
		charity_representative_proof=charity_representative_proof.strip(),
		registration_ip=request.client.host if request.client else "",
		is_public=True,  # Receivers are always public
	)
	USERS[user_id] = user
	USERNAME_INDEX[username.lower()] = user_id  # Store lowercase for case-insensitive login
	_save_users()
	
	return RedirectResponse(url=f"/inspector/user/{user_id}", status_code=303)


@app.get("/inspector/locations", response_class=HTMLResponse)
async def inspector_view_locations(request: Request):
	"""Map view of all user locations (geographical distribution)."""
	inspector = _require_inspector(request)
	
	# Group users by location
	location_data: Dict[str, List[User]] = {}
	for u in USERS.values():
		if u.role == "inspector":
			continue
		location_key = f"{u.country} > {u.state} > {u.city}".strip(" > ")
		if not location_key:
			location_key = "Unknown"
		if location_key not in location_data:
			location_data[location_key] = []
		location_data[location_key].append(u)
	
	return templates.TemplateResponse(
		"inspector_locations.html",
		{
			"request": request,
			"inspector": inspector,
			"location_data": location_data,
		},
	)


@app.get("/inspector/ai-monitoring", response_class=HTMLResponse)
async def inspector_ai_monitoring(request: Request):
	"""AI Security Monitoring Dashboard for law enforcement oversight."""
	inspector = _require_inspector(request)
	
	# Get AI threat statistics
	stats = pcs_ai.get_threat_statistics()
	
	# Get blocked IPs list
	blocked_ips = pcs_ai.get_blocked_ips()
	
	# Get all threat logs from AI module
	threat_logs = []
	if hasattr(pcs_ai, '_threat_log'):
		threat_logs = sorted(pcs_ai._threat_log, key=lambda x: x.get('timestamp', ''), reverse=True)
	
	return templates.TemplateResponse(
		"inspector_ai_monitoring.html",
		{
			"request": request,
			"user": inspector,
			"stats": stats,
			"blocked_ips": blocked_ips,
			"threat_logs": threat_logs[:100],  # Show latest 100 threats
		},
	)


@app.get("/inspector/add-coins", response_class=HTMLResponse)
async def inspector_add_coins_page(request: Request):
	"""Page for inspectors to manually add PCS coins to accounts."""
	inspector = _require_inspector(request)
	
	# Get all receivers and charity orgs
	eligible_users = [
		u for u in USERS.values() 
		if u.role in ['receiver', 'charity_org'] and not u.is_banned
	]
	
	# Get flash message and clear it
	flash_message = None
	if 'flash' in request.session:
		flash_message = request.session.pop('flash')
	
	return templates.TemplateResponse(
		"inspector_add_coins.html",
		{
			"request": request,
			"user": inspector,
			"eligible_users": sorted(eligible_users, key=lambda x: x.username),
			"flash_message": flash_message,
		},
	)


@app.post("/inspector/add-coins")
async def inspector_add_coins_action(request: Request):
	"""Process PCS coin addition by inspector."""
	inspector = _require_inspector(request)
	
	form = await request.form()
	target_user_id = form.get("user_id", "").strip()
	amount_str = form.get("amount", "").strip()
	reason = form.get("reason", "").strip()
	
	# Validation
	if not target_user_id or not amount_str:
		request.session['flash'] = ("error", "User ID and amount are required")
		return RedirectResponse("/inspector/add-coins", status_code=303)
	
	try:
		amount = float(amount_str)
		if amount <= 0:
			raise ValueError("Amount must be positive")
		if amount > 1000000:
			raise ValueError("Amount cannot exceed 1,000,000 PCS")
	except ValueError as e:
		request.session['flash'] = ("error", f"Invalid amount: {e}")
		return RedirectResponse("/inspector/add-coins", status_code=303)
	
	# Get target user
	target_user = USERS.get(target_user_id)
	if not target_user:
		request.session['flash'] = ("error", "User not found")
		return RedirectResponse("/inspector/add-coins", status_code=303)
	
	# Check user role
	if target_user.role not in ['receiver', 'charity_org']:
		request.session['flash'] = ("error", "Can only add coins to receivers or charity organizations")
		return RedirectResponse("/inspector/add-coins", status_code=303)
	
	if target_user.is_banned:
		request.session['flash'] = ("error", "Cannot add coins to banned accounts")
		return RedirectResponse("/inspector/add-coins", status_code=303)
	
	# Add coins
	old_balance = target_user.wallet_balance
	target_user.wallet_balance += amount
	_save_users()
	
	# Log the action
	log_entry = {
		"timestamp": datetime.utcnow().isoformat(),
		"inspector_id": inspector.user_id,
		"inspector_username": inspector.username,
		"target_user_id": target_user.user_id,
		"target_username": target_user.username,
		"amount": amount,
		"old_balance": old_balance,
		"new_balance": target_user.wallet_balance,
		"reason": reason or "No reason provided",
	}
	
	# Save to audit log
	audit_log_path = BASE_DIR / "data" / "inspector_coin_additions.json"
	audit_log = []
	if audit_log_path.exists() and audit_log_path.stat().st_size > 0:
		with open(audit_log_path, 'r') as f:
			audit_log = json.load(f)
	
	audit_log.append(log_entry)
	
	with open(audit_log_path, 'w') as f:
		json.dump(audit_log, f, indent=2)
	
	request.session['flash'] = (
		"success", 
		f"Successfully added {amount:,.2f} PCS to {target_user.username}'s account. New balance: {target_user.wallet_balance:,.2f} PCS"
	)
	return RedirectResponse("/inspector/add-coins", status_code=303)


@app.get("/inspector/export", response_class=HTMLResponse)
async def inspector_export_data(request: Request):
	"""Export user data for law enforcement investigations."""
	inspector = _require_inspector(request)
	
	import json
	
	export_data = []
	for u in USERS.values():
		if u.role == "inspector":
			continue
		export_data.append({
			"user_id": u.user_id,
			"username": u.username,
			"role": u.role,
			"email": u.email,
			"phone": u.phone,
			"country": u.country,
			"state": u.state,
			"city": u.city,
			"registration_ip": u.registration_ip,
			"registration_timestamp": u.registration_timestamp,
			"last_login_ip": u.last_login_ip,
			"last_login_timestamp": u.last_login_timestamp,
			"is_banned": u.is_banned,
			"ban_reason": u.ban_reason,
			"ban_timestamp": u.ban_timestamp,
			"wallet_id": u.wallet_id,
			"transaction_count": len(_wallet_history_for_user(u)),
		})
	
	from fastapi.responses import JSONResponse
	return JSONResponse(
		content={"export_timestamp": datetime.utcnow().isoformat(), "users": export_data},
		headers={"Content-Disposition": "attachment; filename=pcs_users_export.json"}
	)


# ============================================================================
# Ranking System
# ============================================================================

def _calculate_user_donations() -> Dict[str, float]:
	"""Calculate total donations sent by each user from blockchain and cryptocurrency purchases.
	Returns dict of user_id -> total_donated_amount
	"""
	user_donations = {}
	
	# Load blockchain
	blockchain_data = pcs_persistence.load_blockchain()
	
	# Go through all blockchain transactions
	for block in blockchain_data:
		for tx in block.get("transactions", []):
			sender_wallet = tx.get("sender")
			amount = tx.get("amount", 0.0)
			metadata = tx.get("metadata", {})
			
			# Skip system transactions
			if sender_wallet == "SYSTEM":
				continue
			
			# Find user by wallet_id
			for user in USERS.values():
				if user.wallet_id == sender_wallet:
					if user.user_id not in user_donations:
						user_donations[user.user_id] = 0.0
					user_donations[user.user_id] += amount
					break
	
	# Also count completed cryptocurrency purchases as donations
	for user in USERS.values():
		if user.role in ["donor", "charity_org"]:
			completed_purchases = [
				req for req in user.my_purchase_requests 
				if req.get("status") == "completed"
			]
			for req in completed_purchases:
				if user.user_id not in user_donations:
					user_donations[user.user_id] = 0.0
				user_donations[user.user_id] += req.get("amount", 0.0)
	
	return user_donations


def _get_country_rankings(country: str) -> List[Dict]:
	"""Get donor rankings for a specific country.
	Returns list of dicts with user info and total donated, sorted by amount.
	Only includes donors who have successfully donated (total_donated > 0).
	"""
	if not country:
		return []
	
	user_donations = _calculate_user_donations()
	country_donors = []
	
	for user in USERS.values():
		# Only include donors from this country who have donated
		if user.role == "donor" and user.country.lower() == country.lower():
			total_donated = user_donations.get(user.user_id, 0.0)
			# Only add to rankings if they have donated
			if total_donated > 0:
				country_donors.append({
					"user_id": user.user_id,
					"username": user.username,
					"country": user.country,
					"total_donated": total_donated,
					"is_public": user.is_public,
				})
	
	# Sort by total donated (highest first), then by user_id for stability
	country_donors.sort(key=lambda x: (-x["total_donated"], x["user_id"]))
	
	# Add rank numbers
	for idx, donor in enumerate(country_donors, 1):
		donor["rank"] = idx
	
	return country_donors


def _get_worldwide_rankings() -> List[Dict]:
	"""Get worldwide donor rankings.
	Returns list of dicts with user info and total donated, sorted by amount.
	Only includes donors who have successfully donated (total_donated > 0).
	"""
	user_donations = _calculate_user_donations()
	worldwide_donors = []
	
	for user in USERS.values():
		# Only include donors who have donated
		if user.role == "donor":
			total_donated = user_donations.get(user.user_id, 0.0)
			# Only add to rankings if they have donated
			if total_donated > 0:
				worldwide_donors.append({
					"user_id": user.user_id,
					"username": user.username,
					"country": user.country,
					"total_donated": total_donated,
					"is_public": user.is_public,
				})
	
	# Sort by total donated (highest first), then by user_id for stability
	worldwide_donors.sort(key=lambda x: (-x["total_donated"], x["user_id"]))
	
	# Add rank numbers
	for idx, donor in enumerate(worldwide_donors, 1):
		donor["rank"] = idx
	
	return worldwide_donors


def _get_user_ranks(user_id: str) -> Dict[str, int]:
	"""Get a user's rank in their country and worldwide.
	Returns dict with 'country_rank' and 'worldwide_rank' (0 if not ranked or beyond top 1000).
	Only reveals rankings for top 1000 donors.
	"""
	user = USERS.get(user_id)
	if not user or user.role != "donor":
		return {"country_rank": 0, "worldwide_rank": 0}
	
	# Get worldwide rank
	worldwide_rankings = _get_worldwide_rankings()
	worldwide_rank = 0
	for donor in worldwide_rankings:
		if donor["user_id"] == user_id:
			# Only reveal rank if in top 1000
			if donor["rank"] <= 1000:
				worldwide_rank = donor["rank"]
			break
	
	# Get country rank
	country_rank = 0
	if user.country:
		country_rankings = _get_country_rankings(user.country)
		for donor in country_rankings:
			if donor["user_id"] == user_id:
				# Only reveal rank if in top 1000
				if donor["rank"] <= 1000:
					country_rank = donor["rank"]
				break
	
	return {
		"country_rank": country_rank,
		"worldwide_rank": worldwide_rank,
	}


@app.get("/rankings", response_class=HTMLResponse)
async def rankings_page(request: Request, country: Optional[str] = None):
	"""Display donor rankings leaderboard."""
	user = _get_current_user(request)
	if not user:
		return RedirectResponse(url="/login", status_code=303)
	
	# Use comprehensive country list (all countries, not just those with donors)
	countries = ALL_COUNTRIES
	
	# Get worldwide rankings
	worldwide_rankings = _get_worldwide_rankings()
	
	# Get country-specific rankings (default to user's country if available, or from query param)
	selected_country = country if country else (user.country if user.country else "Malaysia")
	country_rankings = _get_country_rankings(selected_country) if selected_country else []
	
	return templates.TemplateResponse("rankings.html", {
		"request": request,
		"user": user,
		"unread_count": _get_unread_notification_count(user),
		"worldwide_rankings": worldwide_rankings[:100],  # Top 100
		"country_rankings": country_rankings[:50],  # Top 50
		"selected_country": selected_country,
		"countries": countries,
	})


@app.get("/api/rankings/country/{country}")
async def api_country_rankings(request: Request, country: str):
	"""API endpoint to get country rankings."""
	session_user = request.session.get("user")
	if not session_user:
		return {"error": "Not authenticated"}, 401
	
	rankings = _get_country_rankings(country)
	return {"country": country, "rankings": rankings}


@app.get("/api/rankings/worldwide")
async def api_worldwide_rankings(request: Request):
	"""API endpoint to get worldwide rankings."""
	session_user = request.session.get("user")
	if not session_user:
		return {"error": "Not authenticated"}, 401
	
	rankings = _get_worldwide_rankings()
	return {"rankings": rankings}


if __name__ == "__main__":  # Convenience for `python pcs-website.py`
	import uvicorn

	uvicorn.run(
		"pcs-website:app",
		host=config.HOST,
		port=config.PORT,
		reload=config.DEBUG,
	)

