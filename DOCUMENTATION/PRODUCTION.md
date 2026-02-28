# Production Deployment Guide for PCS

## Prerequisites

- Linux server (Ubuntu 20.04+ recommended)
- Docker and Docker Compose installed
- Domain name pointed to your server's IP address
- SSH access to your server

## Step-by-Step Production Deployment

### 1. Prepare Your Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install docker-compose -y

# Add your user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Install certbot for SSL
sudo apt install certbot -y
```

### 2. Upload Your Code

```bash
# Option A: Using Git (recommended)
git clone https://github.com/your-username/perfectcharitysystem.git
cd perfectcharitysystem

# Option B: Using SCP from your local machine
# scp -r /path/to/perfectcharitysystem user@your-server-ip:/home/user/
```

### 3. Configure Domain and SSL

**Edit apache.conf:**
```bash
nano config/apache.conf
# Replace "your-domain.com" with your actual domain (appears in multiple places)
```

**Get SSL Certificate:**
```bash
# Create directory for certbot challenges
sudo mkdir -p /var/www/certbot

# Get SSL certificate
sudo certbot certonly --standalone -d your-domain.com -d www.your-domain.com

# Copy certificates to project (for Docker Apache container)
sudo mkdir -p docker/certs
sudo cp -r /etc/letsencrypt/* docker/certs/
sudo chown -R $USER:$USER docker/certs/
```

### 4. Set Environment Variables

```bash
# Generate a secure secret key
export PCS_SECRET_KEY=$(openssl rand -hex 32)

# Save it to .env file for persistence
echo "PCS_SECRET_KEY=$PCS_SECRET_KEY" > .env

# Important: Keep this secret! Don't commit .env to git
```

### 5. Configure Firewall

```bash
# Install and configure UFW
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 6. Deploy the Application

```bash
# Build and start containers (from project root)
docker-compose -f docker/docker-compose.prod.yml up -d --build

# Check if containers are running
docker-compose -f docker/docker-compose.prod.yml ps

# View logs
docker-compose -f docker/docker-compose.prod.yml logs -f
```

### 7. Verify Deployment

Visit your domain in a browser:
- **http://your-domain.com** → Should redirect to HTTPS
- **https://your-domain.com** → Should show PCS login page

Default admin credentials:
- Username: `admin`
- Password: `admin`

**⚠️ IMPORTANT: Change the admin password immediately!**

## SSL Certificate Auto-Renewal

```bash
# Set up automatic renewal
sudo crontab -e

# Add this line to renew certificates monthly
0 0 1 * * certbot renew --quiet && docker-compose -f /path/to/perfectcharitysystem/docker/docker-compose.prod.yml restart apache
```

## Backup Strategy

### Automatic Daily Backups

```bash
# Create backup script
nano backup.sh
```

Add this content:
```bash
#!/bin/bash
BACKUP_DIR="/home/$USER/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/pcs_backup_$DATE.tar.gz data/ uploads/

# Keep only last 30 days of backups
find $BACKUP_DIR -name "pcs_backup_*.tar.gz" -mtime +30 -delete
```

```bash
# Make executable
chmod +x backup.sh

# Add to crontab (runs daily at 2 AM)
crontab -e
# Add: 0 2 * * * /home/$USER/perfectcharitysystem/backup.sh
```

## Updating the Application

```bash
# Pull latest code (from project root)
git pull

# Rebuild and restart
docker-compose -f docker/docker-compose.prod.yml up -d --build

# Clean up old images
docker image prune -f
```

## Monitoring

```bash
# View live logs
docker-compose -f docker/docker-compose.prod.yml logs -f

# Check container health
docker-compose -f docker/docker-compose.prod.yml ps

# View Apache logs
docker-compose -f docker/docker-compose.prod.yml logs -f apache
```

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs pcs-web

# Rebuild from scratch
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml up -d --build --force-recreate
```

### SSL issues
```bash
# Check certificate expiry
sudo certbot certificates

# Renew manually
sudo certbot renew
```

### High memory usage
```bash
# Restart containers
docker-compose -f docker-compose.prod.yml restart

# Check resource usage
docker stats
```

## Security Checklist

- [ ] Changed default admin password
- [ ] Set strong PCS_SECRET_KEY
- [ ] Enabled firewall (UFW)
- [ ] SSL certificates installed and working
- [ ] Regular backups configured
- [ ] Server kept up-to-date
- [ ] Monitoring logs for suspicious activity

## Performance Optimization

### For high traffic:

Edit [docker/Dockerfile.prod](docker/Dockerfile.prod) and increase workers:
```dockerfile
CMD ["gunicorn", "codes.pcs_website:app", \
     "--workers", "8", \  # Increase from 4 to 8
```

Then rebuild:
```bash
docker-compose -f docker/docker-compose.prod.yml up -d --build
```

## Stopping the Application

```bash
# Stop containers
docker-compose -f docker/docker-compose.prod.yml down

# Stop and remove all data (CAUTION!)
docker-compose -f docker/docker-compose.prod.yml down -v
```

## Support

For issues:
1. Check logs: `docker-compose -f docker/docker-compose.prod.yml logs`
2. Verify firewall: `sudo ufw status`
3. Check DNS: `nslookup your-domain.com`
4. Test locally: `curl http://localhost:8000`

---

**You're now running PCS in production! 🎉**

Access: https://your-domain.com
