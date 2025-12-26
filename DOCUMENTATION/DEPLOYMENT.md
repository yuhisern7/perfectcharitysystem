# Perfect Charity System (PCS) - Deployment Guide

## Quick Start (Local Development)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python pcs-website.py
   ```
   
   Or using uvicorn directly:
   ```bash
   uvicorn pcs-website:app --reload --host 0.0.0.0 --port 8000
   ```

3. **Access the application:**
   - Open your browser to: http://localhost:8000
   - Default admin login: `admin` / `admin`

## Data Persistence

All data is automatically saved to the `data/` directory:
- `data/users.json` - User accounts and profiles
- `data/blockchain.json` - PCS blockchain transactions
- `data/profiles.json` - Charity profiles

User uploads are stored in the `uploads/` directory.

## Production Deployment

### Using Docker

1. **Build the image:**
   ```bash
   docker build -t pcs-charity-system .
   ```

2. **Run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

3. **Access the application:**
   - http://your-server-ip:8000

### Using a Cloud Provider (e.g., AWS, Azure, Google Cloud)

1. **Prepare the server:**
   - Ubuntu/Debian: `sudo apt update && sudo apt install python3 python3-pip`
   - Install requirements: `pip3 install -r requirements.txt`

2. **Run with production settings:**
   ```bash
   uvicorn pcs-website:app --host 0.0.0.0 --port 8000 --workers 4
   ```

3. **Setup as a systemd service:**
   Create `/etc/systemd/system/pcs.service`:
   ```ini
   [Unit]
   Description=PCS Charity System
   After=network.target

   [Service]
   User=www-data
   WorkingDirectory=/var/www/pcs
   ExecStart=/usr/local/bin/uvicorn pcs-website:app --host 0.0.0.0 --port 8000 --workers 4
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

   Then:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable pcs
   sudo systemctl start pcs
   ```

### Nginx Reverse Proxy (Recommended for HTTPS)

1. **Install Nginx:**
   ```bash
   sudo apt install nginx certbot python3-certbot-nginx
   ```

2. **Configure Nginx** (`/etc/nginx/sites-available/pcs`):
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }

       location /uploads/ {
           alias /var/www/pcs/uploads/;
       }

       client_max_body_size 50M;
   }
   ```

3. **Enable HTTPS with Let's Encrypt:**
   ```bash
   sudo ln -s /etc/nginx/sites-available/pcs /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   sudo certbot --nginx -d your-domain.com
   ```

## Environment Variables

For production, set these environment variables:

- `PCS_SECRET_KEY` - Secret key for sessions (generate a random string)
- `PCS_ADMIN_PASSWORD` - Override default admin password

Example:
```bash
export PCS_SECRET_KEY="your-very-long-random-secret-key-here"
export PCS_ADMIN_PASSWORD="secure-admin-password"
```

## Security Checklist

- [ ] Change default admin password
- [ ] Set a strong `PCS_SECRET_KEY`
- [ ] Enable HTTPS (use Let's Encrypt)
- [ ] Setup firewall (allow only 80, 443, and SSH)
- [ ] Regular backups of `data/` and `uploads/` directories
- [ ] Keep dependencies updated: `pip install -r requirements.txt --upgrade`
- [ ] Monitor logs for suspicious activity
- [ ] Consider rate limiting with nginx

## Backup and Recovery

**Backup:**
```bash
tar -czf pcs-backup-$(date +%Y%m%d).tar.gz data/ uploads/
```

**Restore:**
```bash
tar -xzf pcs-backup-YYYYMMDD.tar.gz
```

## Troubleshooting

**Port already in use:**
```bash
# Find process using port 8000
lsof -i :8000
# Kill it
kill -9 <PID>
```

**Permission errors:**
```bash
sudo chown -R www-data:www-data /var/www/pcs
sudo chmod -R 755 /var/www/pcs
```

**Data not persisting:**
- Check that `data/` directory exists and is writable
- Review logs for permission errors

## Support

For issues or questions, review the application logs:
```bash
journalctl -u pcs -f  # If using systemd
docker-compose logs -f  # If using Docker
```
