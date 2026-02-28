# File Purpose Map

This document explains the purpose of each file and key folder in the Perfect Charity System workspace.

## Root

- `.env.example` – Example environment variable file for local/production configuration.
- `.git/` – Git version control metadata (auto-managed, not part of app logic).
- `.gitignore` – Tells Git which files and folders to ignore (caches, virtualenvs, etc.).
- `codes/` – Python package containing all core backend source code.
- `config/` – Server and app configuration files (Apache, app config, robots).
- `data/` – Runtime JSON data and machine-learning models (created/updated by the app).
- `docker/` – Docker and Docker Compose definitions for containerized deployment.
- `documentation/` – Project documentation for usage, deployment, and architecture.
- `PCS.code-workspace` – VS Code multi-root workspace configuration for this project.
- `README.md` – Top-level project overview and basic instructions.
- `requirements.txt` – Python dependencies required by the application.
- `scripts/` – Helper scripts to start the app in different environments.
- `templates/` – Jinja2 HTML templates used by the web frontend.
- `uploads/` – Directory for user-uploaded files (images, media, receipts).
- `__pycache__/` – Python bytecode cache generated automatically at runtime.

## codes/ (Core Backend Package)

- `codes/pcs-crypto.py` – Implements the custom PCS blockchain, blocks, and transaction logic with persistence integration.
- `codes/pcs-profiles.py` – Manages user and charity/receiver profile objects, including profile-specific business logic.
- `codes/pcs-wallet.py` – Handles PCS wallet balances, transfers, summaries, and related wallet utilities.
- `codes/pcs-website.py` – Main FastAPI web frontend application (routes, templates, sessions, inspectors, donations).
- `codes/pcs_ai.py` – Security AI and risk assessment engine (login/request analysis, anomaly detection, ML models).
- `codes/pcs_persistence.py` – Central persistence layer for JSON-backed storage under the `data/` directory.
- `codes/perfectcharitysystem.py` – Core FastAPI API (JSON endpoints for health, profiles, blockchain, donations, etc.).

## config/

- `config/apache.conf` – Apache HTTPD configuration used when running behind Apache (reverse proxy, SSL, vhost).
- `config/config.py` – Application configuration (environment flags, secrets, admin credentials, paths).
- `config/robots.txt` – Robots file controlling how search engines crawl the public-facing site.

## data/

- `data/.gitkeep` – Empty file to ensure the `data/` folder exists in Git.
- `data/blockchain.json` – Persistent JSON storage for the PCS blockchain and all transaction history.
- `data/inspector_coin_additions.json` – Audit log of inspector adjustments and coin additions.
- `data/users.json` – Persistent JSON storage for all user accounts, roles, profiles, and state.
- `data/ml_models/` – Stored machine-learning model files used by `codes/pcs_ai.py`.

### data/ml_models/

- `data/ml_models/anomaly_detector.pkl` – Trained anomaly detection model for suspicious behavior.
- `data/ml_models/feature_scaler.pkl` – Feature scaling/normalization model used before feeding ML models.
- `data/ml_models/ip_reputation.pkl` – IP reputation / risk model for identifying risky IP addresses.
- `data/ml_models/threat_classifier.pkl` – Classification model for categorizing detected threats.

## docker/

- `docker/docker-compose.prod.yml` – Production Docker Compose stack (Apache + PCS web service with volumes).
- `docker/docker-compose.yml` – Default/development Docker Compose stack for local or non-prod use.
- `docker/Dockerfile` – Base Docker image for running PCS in a container (non-prod/general usage).
- `docker/Dockerfile.prod` – Production-optimized Docker image definition (Gunicorn + Uvicorn workers, health checks).

## documentation/

- `documentation/deployment.md` – Deployment guide and quick start for running PCS locally or on servers.
- `documentation/implementation.md` – Implementation summary and architecture overview of the PCS system.
- `documentation/information.md` – High-level system description, features, roles, and API outline.
- `documentation/production.md` – Detailed production deployment guide (Docker, SSL, backups, monitoring).
- `documentation/filepurpose.md` – This file: explanation of the purpose of each file and major folder.

## scripts/

- `scripts/start.bat` – Windows helper script to start the PCS web application.
- `scripts/start.sh` – Linux/macOS helper script to start the PCS web application.

## templates/ (HTML Views)

- `templates/blockchain.html` – Blockchain explorer view showing blocks and transactions on the PCS chain.
- `templates/directory.html` – Public directory listing charity organizations and receivers by country.
- `templates/donate_pcs.html` – Donation flow page for donating PCS within the system.
- `templates/donate_project.html` – Donation page for contributing to specific projects.
- `templates/external_services.html` – Page showing integrations or links to external services.
- `templates/index.html` – Landing/home page for the PCS website.
- `templates/inspector_add_coins.html` – Inspector interface to add or adjust PCS coins.
- `templates/inspector_create_receiver.html` – Inspector form for creating verified receiver accounts.
- `templates/inspector_edit_user.html` – Inspector page to edit user details and flags.
- `templates/inspector_locations.html` – Inspector dashboard showing geographic distribution of users.
- `templates/inspector_users.html` – Inspector dashboard listing users with filters and actions.
- `templates/inspector_user_detail.html` – Detailed inspector view for a single user, including history.
- `templates/login.html` – Login page for donors, receivers, and inspectors.
- `templates/my_purchases.html` – User view of their PCS purchases/donations history.
- `templates/notifications.html` – In-app notifications center page.
- `templates/profile.html` – Authenticated user profile management page.
- `templates/profile_inspector.html` – Inspector profile and control panel.
- `templates/profile_public.html` – Public profile view for a user/charity.
- `templates/profile_public_seo.html` – SEO-optimized public profile variant for search engines.
- `templates/projects_list.html` – Page listing projects that can receive donations.
- `templates/purchase_crypto.html` – Purchase PCS (crypto) page.
- `templates/purchase_crypto_detail.html` – Detailed view of a specific PCS purchase.
- `templates/rankings.html` – Leaderboard / rankings page (e.g., top donors or charities).
- `templates/register.html` – Registration page for new donor accounts.
- `templates/search.html` – Search page to find users, charities, or receivers.
- `templates/sell_crypto.html` – Page for receivers to sell PCS back to donors.
- `templates/upload_media.html` – UI for uploading general media assets.
- `templates/upload_picture.html` – UI for uploading profile pictures.
- `templates/view_project.html` – Detailed view for a single project.

## uploads/

- `uploads/.gitkeep` – Placeholder file to ensure the `uploads/` directory exists in Git; actual uploaded files are created at runtime.
