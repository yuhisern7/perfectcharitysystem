# Perfect Charity System (PCS)

A blockchain-based charity donation platform with transparent transaction tracking, user management, and law enforcement controls.

## Features

- 🔗 **Private Blockchain**: Transparent, immutable donation tracking using the PCS coin
- 👥 **User Management**: Separate donor and receiver accounts
- 🤖 **AI Security Monitoring**: Real-time threat detection and attack prevention
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
   uvicorn codes.pcs_website:app --reload --host 0.0.0.0 --port 8000
   ```

4. **Access the website:**
   - Open your browser to: http://localhost:8000
   - Default admin credentials: `admin` / `admin`

## Project Structure

```
perfectcharitysystem/
├── codes/                      # Core backend package
│   ├── pcs-crypto.py           # Blockchain implementation
│   ├── pcs-wallet.py           # Wallet management
│   ├── pcs-profiles.py         # Charity profile management
│   ├── pcs_ai.py               # Donation risk assessment & security
│   ├── pcs_persistence.py      # Data persistence layer
│   ├── perfectcharitysystem.py # Core API
│   └── pcs-website.py          # Web frontend (main app)
│
├── config/
│   ├── config.py               # Production configuration
│   └── apache.conf             # Web server config (optional)
│
├── docker/
│   ├── Dockerfile              # Dev/standard container image
│   ├── Dockerfile.prod         # Production container image
│   ├── docker-compose.yml      # Docker orchestration
│   └── docker-compose.prod.yml # Production orchestration
│
├── templates/                  # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── profile.html
│   ├── profile_inspector.html
│   ├── inspector_users.html
│   ├── inspector_user_detail.html
│   ├── inspector_locations.html
│   ├── inspector_create_receiver.html
│   └── directory.html
│
├── data/                       # Persisted data (auto-created)
│   ├── users.json
│   ├── blockchain.json
│   ├── inspector_coin_additions.json
│   └── ml_models/
│
├── uploads/                    # User-uploaded media
│
├── documentation/              # Project documentation
│   ├── deployment.md
│   ├── implementation.md
│   ├── information.md
│   └── production.md
│
├── scripts/
│   ├── start.bat               # Windows startup
│   └── start.sh                # Linux/Mac startup
│
├── requirements.txt            # Python dependencies
├── .env.example                # Environment template
└── .gitignore                  # Git ignore configuration

```

## User Roles

### Donor
- Register through public signup
- Create personal profile with media
- Purchase PCS from receivers/charities (purchasing IS the donation)
- PCS stays permanently in wallet as proof of charitable giving
- View transaction history
- Optional privacy controls

### Receiver
- Created by admin/inspector only
- Always public profile
- Sell PCS cryptocurrency to donors for real money
- Receive $10,000 PCS monthly credit
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
- **inspector_coin_additions.json**: Inspector coin change audit log

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

See [documentation/deployment.md](documentation/deployment.md) for detailed deployment instructions including:
- Docker deployment
- Cloud hosting (AWS, Azure, Google Cloud)
- Nginx reverse proxy setup
- HTTPS/SSL configuration
- Systemd service setup

### Quick Docker Deploy

```bash
docker-compose -f docker/docker-compose.yml up -d
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
- `GET /api/profiles` - List all profiles
- `POST /api/donate` - Record PCS transfer (internal blockchain operation)
- `GET /api/chain` - View blockchain

## Development

Run in development mode with auto-reload:

```bash
uvicorn codes.pcs_website:app --reload
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

For deployment help, see [documentation/deployment.md](documentation/deployment.md)

---

Built with ❤️ for transparent charitable giving
