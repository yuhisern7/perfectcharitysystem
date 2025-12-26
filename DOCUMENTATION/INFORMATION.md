# Perfect Charity System (PCS)

A blockchain-based charity donation platform with transparent transaction tracking, user management, and law enforcement controls.

## Features

- 🔗 **Private Blockchain**: Transparent, immutable donation tracking using the PCS coin
- 👥 **User Management**: Separate donor and receiver accounts
- 🔒 **Inspector Controls**: Law enforcement dashboard with:
  - User account banning/unbanning
  - Geographical location tracking
  - Transaction monitoring
  - Data export for investigations
- 💾 **Data Persistence**: All data saved to disk automatically
- 🌐 **Web Interface**: Modern, responsive HTML interface
- 📊 **Transaction History**: Full audit trail of all donations
- 🎯 **Profile System**: Verified receiver profiles for charities

## Quick Start

### Prerequisites
- Python 3.11 or higher
- pip (Python package manager)

### Installation

1. **Clone or download this repository**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python pcs-website.py
   ```

4. **Access the website:**
   - Open your browser to: http://localhost:8000
   - Default admin credentials: `admin` / `admin`

## Project Structure

```
PCS/
├── pcs-crypto.py           # Blockchain implementation
├── pcs-wallet.py           # Wallet management
├── pcs-profiles.py         # Charity profile management
├── pcs_ai.py               # Donation risk assessment
├── pcs_persistence.py      # Data persistence layer
├── perfectcharitysystem.py # Core API
├── pcs-website.py          # Web frontend (main app)
├── config.py               # Production configuration
├── templates/              # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html
│   ├── profile_inspector.html
│   ├── inspector_users.html
│   ├── inspector_user_detail.html
│   ├── inspector_locations.html
│   └── inspector_create_receiver.html
├── data/                   # Persisted data (auto-created)
│   ├── users.json
│   ├── blockchain.json
│   └── profiles.json
└── uploads/                # User-uploaded media

```

## User Roles

### Donor
- Register through public signup
- Create personal profile with media
- Donate PCS to receivers
- View transaction history
- Optional privacy controls

### Receiver
- Created by admin/inspector only
- Always public profile
- Receive donations
- Linked to charity profiles

### Inspector (Law Enforcement)
- Pre-seeded admin account
- Ban/unban user accounts
- View all user data and locations
- Track IP addresses and login history
- Export data for investigations
- Create verified receiver accounts

## Data Persistence

All data is automatically saved to the `data/` directory:
- **users.json**: All user accounts, profiles, and settings
- **blockchain.json**: Complete blockchain transaction history
- **profiles.json**: Charity profiles

Data is saved immediately after any changes, ensuring no data loss.

## Security Features

- Password hashing (SHA-256)
- Session-based authentication
- Inspector-only protected routes
- Ban system prevents login for suspended accounts
- IP address tracking
- Security headers (X-Frame-Options, X-Content-Type-Options)
- Environment-based configuration for production

## Production Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment instructions including:
- Docker deployment
- Cloud hosting (AWS, Azure, Google Cloud)
- Nginx reverse proxy setup
- HTTPS/SSL configuration
- Systemd service setup

### Quick Docker Deploy

```bash
docker-compose up -d
```

## Configuration

Set environment variables for production:

```bash
export PCS_SECRET_KEY="your-long-random-secret-key"
export PCS_ADMIN_PASSWORD="secure-admin-password"
export PCS_HOST="0.0.0.0"
export PCS_PORT="8000"
```

## API Endpoints

The system also exposes a REST API under `/api`:

- `GET /api/health` - Health check
- `POST /api/profiles` - Create charity profile
- `GET /api/profiles` - List all profiles
- `GET /api/profiles/{id}` - Get profile details
- `POST /api/donate` - Make a donation
- `GET /api/wallets/{id}` - Get wallet balance
- `GET /api/chain` - View blockchain

## Development

Run in development mode with auto-reload:

```bash
uvicorn pcs-website:app --reload
```

## Technology Stack

- **Backend**: FastAPI, Python 3.11+
- **Frontend**: HTML, Jinja2 templates
- **Storage**: JSON file-based persistence
- **Blockchain**: Custom SHA-256 implementation
- **Session**: Starlette session middleware

## License

This is a prototype/educational system. Use at your own risk.

## Warning

⚠️ **Change the default admin password before deploying to production!**

Set the `PCS_ADMIN_PASSWORD` environment variable or the system will use the default password.

## Support

For deployment help, see [DEPLOYMENT.md](DEPLOYMENT.md)

---

Built with ❤️ for transparent charitable giving
