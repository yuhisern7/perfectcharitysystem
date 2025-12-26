# PCS - Quick Reference

## 🚀 Quick Commands

### Start Server
```bash
# Windows
start.bat

# Linux/Mac
./start.sh

# Or directly
python pcs-website.py
```

### Access
- **URL**: http://localhost:8000
- **Admin Login**: `admin` / `admin`

## 👥 User Roles

| Role | Registration | Features |
|------|--------------|----------|
| **Donor** | Public signup | Create profile, donate, view history |
| **Receiver** | Admin creates | Receive donations, public profile |
| **Inspector** | Pre-seeded | Ban users, view locations, export data |

## 🔗 Key URLs

- `/` - Homepage
- `/register` - Sign up (donors only)
- `/login` - Login
- `/profile` - Your profile
- `/search` - Search users
- `/inspector/users` - Manage users (admin)
- `/inspector/locations` - Geographic view (admin)
- `/inspector/create-receiver` - Create receiver (admin)

## 📊 Data Files

Located in `data/` directory:
- `users.json` - All user accounts
- `blockchain.json` - Transaction history
- `profiles.json` - Charity profiles

**Backup**: Just copy the `data/` and `uploads/` folders!

## 🔐 Production Setup

```bash
# 1. Set environment variables
export PCS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export PCS_ADMIN_PASSWORD="your-secure-password"

# 2. Run with workers
uvicorn pcs-website:app --host 0.0.0.0 --port 8000 --workers 4

# 3. Or use Docker
docker-compose up -d
```

## 🛠️ Common Tasks

### Change Admin Password
```bash
export PCS_ADMIN_PASSWORD="new-password"
# Delete data/users.json
python pcs-website.py
```

### View Data
```bash
# Pretty print JSON
python -m json.tool data/users.json
python -m json.tool data/blockchain.json
```

### Backup
```bash
# Windows
tar -czf backup.tar.gz data uploads

# Linux
tar -czf pcs-backup-$(date +%Y%m%d).tar.gz data/ uploads/
```

### Restore
```bash
tar -xzf backup.tar.gz
```

## 📡 API Endpoints (under /api)

- `GET /api/health` - Health check
- `GET /api/profiles` - List profiles
- `POST /api/donate` - Make donation
- `GET /api/chain` - View blockchain

## 🐛 Troubleshooting

**Port in use?**
```bash
# Windows
netstat -ano | findstr :8000

# Linux
lsof -i :8000
```

**Dependencies missing?**
```bash
pip install -r requirements.txt
```

**Data not saving?**
- Check `data/` folder exists and is writable
- Look for errors in console output

## 🔒 Security

✅ Change default admin password
✅ Set random `PCS_SECRET_KEY`
✅ Enable HTTPS in production
✅ Regular backups
✅ Monitor `data/users.json` for banned users

## 📚 Full Documentation

- `README.md` - Complete guide
- `DEPLOYMENT.md` - Deployment instructions
- `IMPLEMENTATION.md` - Technical details
