# Perfect Charity System (PCS)

A blockchain-based charity donation platform with transparent transaction tracking, zero fees, and complete accountability.

**Watch Perfect Charity System logical flow**: https://youtu.be/m-OlfJgl8mY?si=rd03imjPiaXsr0o3

---

## 🚀 Quick Start - How to Run the Server

### **First Time Setup:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yuhisern7/perfectcharitysystem.git
   cd perfectcharitysystem
   ```

2. **Create and activate virtual environment:**
   
   **Windows:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```
   
   **Linux/Mac:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   
   **Windows:**
   ```bash
   pip install -r requirements.txt
   ```
   
   **Linux/Mac:**
   ```bash
   pip3 install -r requirements.txt
   ```

### **Running the Server:**

### **Windows:**
```bash
# Method 1: Using startup script (easiest)
start.bat

# Method 2: Direct command
python pcs-website.py
```

### **Linux/Mac:**
```bash
# Method 1: Using startup script (easiest)
./start.sh

# Method 2: Direct command
python3 pcs-website.py
```

### **Access the Application:**
- **URL:** http://localhost:8000
- **Windows users:** If localhost doesn't work, use http://127.0.0.1:8000
- **Alternative:** If 0.0.0.0:8000 fails, try http://127.0.0.1:8000
- **Default Admin Login:** `admin` / `admin`

### **Stop the Server:**
Press **Ctrl+C** in the terminal

---

## Overview
PCS is the world's first non-profiting charity system with zero transaction fees and complete transparency through blockchain technology.

---

## 🎯 Core Advantages

### 1. **Zero Transaction Fees (100% Direct Impact)**
- **No payment processing fees** - Traditional charities lose 2-5% to credit card processors
- **No platform fees** - Unlike GoFundMe (2.9% + $0.30), PCS charges 0%
- **No administrative overhead** - Every dollar donated reaches the intended recipient
- **Direct peer-to-peer transfers** - No intermediaries taking cuts

**Impact:** If you donate $1,000, the recipient receives the full $1,000 worth of value.

---

### 2. **Complete Blockchain Transparency**
- **Immutable audit trail** - Every transaction permanently recorded
- **Public blockchain explorer** - Anyone can verify where money went
- **Real-time tracking** - Donors see their impact immediately
- **Law enforcement access** - Inspectors can audit all transactions
- **No hidden costs** - All expenses visible on the blockchain

**Benefit:** Donors gain confidence knowing exactly where their contributions go.

---

### 3. **"Dead Coin" Design (Anti-Speculation)**
PCS cryptocurrency is designed to have **zero external value**:
- ❌ Cannot be traded on exchanges
- ❌ Cannot be withdrawn to external wallets
- ❌ No market speculation or price volatility
- ✅ Only purpose: Track charitable giving
- ✅ Pure utility token for transparency

**Result:** Eliminates fraud, market manipulation, and speculation - focusing solely on charity.

---

### 4. **Monthly Credit System**
- **Receivers & Charities:** Automatically receive $10,000 PCS/month
- **No upfront capital needed** - Start helping immediately
- **Guaranteed liquidity** - Always have "inventory" to sell
- **Circular economy** - Receivers continuously receive monthly credits to sell to donors

**Advantage:** Creates a sustainable, self-replenishing donation ecosystem.

---

### 5. **Direct Value Transfer with Blockchain Proof**

**How Donations Work:**
```
Donor pays receiver/charity real money (bank transfer, PayPal, cash, etc.)
    ↓
Receiver confirms payment and transfers PCS cryptocurrency to donor
    ↓
PCS stays permanently in donor's wallet as proof of donation
    ↓
Blockchain records the transaction transparently
    ↓
Receiver gets monthly credit refills to continue helping others
```

**Innovation:** Donors accumulate PCS as permanent, transparent proof of their charitable giving.

---

### 6. **Proof-Based Trust System**

**Secure Purchase Request Workflow:**
1. **Donor creates request** → Status: "pending"
2. **Receiver approves** → Status: "approved" + provides payment details
3. **Donor uploads payment proof** → Status: "proof_submitted"
4. **Receiver confirms receipt** → Status: "completed" + PCS transferred
5. **Notification system** → Real-time updates at every step

**Benefits:**
- No escrow services needed
- Dispute resolution through evidence
- Both parties protected
- Full audit trail maintained

---

### 8. **Gamified Donor Recognition System**

**Ranking & Leaderboard Features:**
- **Country rankings** - Top 1000 donors per country
- **Worldwide rankings** - Top 1000 donors globally
- **Merit-based revelation** - Rankings only shown after first successful donation
- **Anti-gaming protection** - Ranks beyond top 1000 are hidden
- **Stable sorting** - Mathematically sound ranking with tie-breaking
- **Visual badges** - 🥇🥈🥉 medals for top 3 positions

**Ranking Logic:**
```
1. Only donors with completed donations are ranked
2. Sorted by total donated (highest to lowest)
3. Ties broken alphabetically by user ID for stability
4. Only top 1000 ranks revealed (Country & Worldwide)
5. Rank 0 = Not ranked or beyond top 1000
```

**Benefits:**
- Encourages charitable giving through recognition
- Prevents spam accounts from appearing in rankings
- Maintains exclusivity and achievement value
- Creates healthy competition among donors
- Protects privacy of smaller contributors

---

### 9. **Inspector Oversight (Law Enforcement Integration)**

**DISA STIG Level 3 Security Implementation:**
- **Account lockout** after 3 failed login attempts
- **Session timeouts** for security
- **Security event logging** - Full audit trail
- **Ban management** - Inspectors can block fraudulent users
- **Geographic tracking** - Monitor distribution by country/state
- **User management** - Complete oversight of all accounts
- **AI Security Protection** - Real-time threat detection and blocking
  - Automatic IP blocking for malicious activity
  - Attack type detection (SQL injection, XSS, DDoS, etc.)
  - Failed login attempt monitoring
  - Geolocation tracking for law enforcement
    - City, Region, Country for each attack
    - ISP and organization identification
    - GPS coordinates for mapping
    - ASN and timezone data
- **Manual Coin Addition** - Inspector intervention capabilities
  - Add PCS coins to receiver/charity accounts for emergency relief
  - Amount validation (0.01 - 1,000,000 PCS per transaction)
  - Mandatory reason documentation for all additions
  - Complete audit trail logged to `data/inspector_coin_additions.json`
  - Prevents additions to banned accounts for fraud prevention
  - Success/error feedback with transaction confirmation

**Inspector Coin Addition Workflow:**
```
1. Inspector logs in and navigates to "Add PCS Coins"
2. Searches and selects target receiver/charity account
3. Enters amount (validated: 0.01 - 1,000,000 PCS)
4. Provides mandatory reason for the addition
5. Confirms transaction
6. System validates:
   - User role (must be receiver or charity_org)
   - Account status (not banned)
   - Amount range (within limits)
7. Coins added to account + Blockchain record created
8. Audit log entry saved with:
   - Timestamp, Inspector ID, Target user
   - Amount, Old/New balance, Reason
9. Success message displayed with new balance
```

**Accountability:** Ensures system integrity, legal compliance, emergency response capabilities, and law enforcement cooperation with complete transparency and attacker geolocation tracking.

---

### 10. **Direct Donor-Receiver Connection**

**Traditional Charity Flow:**
```
Donor → Payment Processor (3%) 
      → Charity Platform (5%) 
      → Charity Overhead (20-30%)
      → Final Recipient (60-70% of original)
```

**PCS Flow:**
```
Donor → Receiver (100%)
          ↓
      PCS transferred to donor as permanent proof
          ↓
      Blockchain Record (transparent)
```

**Efficiency Gain:** 30-40% more value reaches those in need.

---

### 11. **Multi-Role System**

**Four Distinct User Types:**
- **Donors** - Purchase PCS from receivers/charities (purchasing IS the donation)
- **Receivers** - Verified individuals in need who sell PCS for real money
- **Charity Organizations** - Registered non-profits who sell PCS for real money
- **Inspectors** - Law enforcement oversight

**Control:** Each role has appropriate permissions and capabilities.

---

### 12. **Multi-Currency Bridge**
- Accept payments in **any currency** worldwide
- No currency exchange fees
- PCS standardizes tracking across all payment methods
- Receivers choose their preferred payment method
- Global accessibility without barriers

---

### 13. **Profile-Based Transparency**

**Every profile includes:**
- Personal story and introduction
- Photo and media galleries
- Location (country, state, city)
- Bank account verification
- Promotes multiple payment gateways
- Project descriptions
- Complete donation history
- Blockchain transaction records

**Trust:** Donors see exactly who they're helping and verify legitimacy.

---

### 14. **Public SEO-Optimized Profiles (New!)**

**Worldwide Discoverability:**
- **No login required** - Charity organizations and receivers are publicly accessible
- **Search engine friendly** - Profiles indexed by Google, Bing, and other search engines
- **Direct URL access** - Share profiles via `/public/{username}` links
- **SEO optimization** - Rich meta tags, Open Graph, Twitter Cards, Schema.org structured data
- **Public directory** - Browse all charities and receivers at `/directory`
- **Sitemap generation** - Dynamic XML sitemap for search engines
- **Robots.txt** - Configured for optimal search engine crawling

**Key Features:**
```
🔍 Search Engine Indexing:
- Google-friendly meta descriptions
- Open Graph tags for social media sharing
- Twitter Card integration
- Schema.org JSON-LD structured data
- Canonical URLs for SEO

🌍 Public Access Points:
- /public/{username} - Individual profile pages (no login)
- /directory - Complete charity and receiver directory
- /sitemap.xml - Dynamic sitemap for search engines
- /robots.txt - Search crawler instructions

📊 Directory Features:
- Browse by country
- Charity organizations and receivers listed separately
- Profile previews with photos and introductions
- Total statistics (charities, receivers)
- Mobile-responsive design
```

**SEO Benefits:**
- Charity organizations appear in Google search results
- Receivers can be found by name worldwide
- Social media sharing with rich previews
- Better discoverability for fundraising
- Increased donor reach through organic search
- Professional web presence for charities

**Example URLs:**
- Profile: `https://perfectcharitysystem.org/public/RedCross`
- Directory: `https://perfectcharitysystem.org/directory`
- Sitemap: `https://perfectcharitysystem.org/sitemap.xml`

**Privacy Control:**
- Only charity_org and receiver profiles are publicly accessible
- Donor profiles remain login-protected
- Inspector profiles are not public

**Impact:** Charities and receivers gain worldwide visibility through search engines, dramatically increasing their reach and donation potential.

---

## 💡 Real-World Example

### Traditional Charity Donation: $1,000
```
$1,000 donation
  - $30 (Credit card fee)
  - $50 (Platform fee)
  - $200 (Charity overhead)
  ___________________________
  = $720 reaches recipient (72%)
```

### PCS Donation: $1,000
```
$1,000 sent to receiver
  - $0 (No fees)
  - $0 (No platform charges)
  - $0 (No overhead)
  ___________________________
  = $1,000 reaches recipient (100%)

PLUS:
  ✓ Blockchain record created
  ✓ Complete transparency
  ✓ Permanent audit trail
```

---

## 🔒 Security Features (OWASP & DISA STIG Level 3 Compliant)

**OWASP Top 10 (2021) Compliance:**

- **A01 - Broken Access Control**
  - Role-based access control (RBAC) for all user types
  - Session management with automatic timeout
  - Session token regeneration on login
  
- **A02 - Cryptographic Failures**
  - SHA-256 password hashing
  - HTTPS enforcement in production (Strict-Transport-Security)
  - Secure session encryption
  
- **A03 - Injection**
  - Input sanitization for all user inputs
  - SQL injection prevention (file-based storage)
  - XSS prevention via HTML escaping
  - Content Security Policy headers
  
- **A04 - Insecure Design**
  - Secure architecture with separation of concerns
  - Battle-hardened AI threat detection (100+ attack signatures)
  - Defense in depth security layers
  
- **A05 - Security Misconfiguration**
  - Comprehensive security headers
  - X-Frame-Options (clickjacking prevention)
  - X-Content-Type-Options (MIME sniffing prevention)
  - Permissions-Policy (browser feature restrictions)
  
- **A06 - Vulnerable Components**
  - Minimal dependencies
  - FastAPI framework (actively maintained)
  - Regular security updates
  
- **A07 - Authentication Failures**
  - Account lockout after 3 failed attempts
  - Brute force detection
  - Multi-factor authentication ready
  - Session timeout (30 minutes)
  
- **A08 - Data Integrity Failures**
  - Blockchain immutability
  - Atomic file operations
  - Data validation on all inputs
  
- **A09 - Security Logging Failures**
  - Complete audit trail for all actions
  - Security event logging
  - Failed login tracking
  - IP address logging
  
- **A10 - Server-Side Request Forgery**
  - URL validation and sanitization
  - Protocol whitelisting (HTTP/HTTPS only)
  - Request pattern monitoring

**Additional Security:**
- Account lockout - Prevents brute force attacks
- Referrer-Policy - Limits information leakage
- Password hashing - SHA-256 encryption
- Battle-hardened AI - Real-time attack prevention with 100+ signatures

---

## 🌍 Global Impact Potential

### Traditional Charity Sector Issues:
- ❌ High overhead costs (15-40%)
- ❌ Lack of transparency
- ❌ Donor distrust
- ❌ Payment processing fees
- ❌ Currency exchange losses
- ❌ Limited accountability

### PCS Solutions:
- ✅ Zero overhead costs
- ✅ Complete blockchain transparency
- ✅ Verified recipient profiles
- ✅ Zero transaction fees
- ✅ Multi-currency support
- ✅ Inspector oversight with security monitoring

---

## 📊 Key Metrics

| Metric | Traditional Charity | PCS |
|--------|-------------------|-----|
| **Transaction Fees** | 2-5% | 0% |
| **Platform Fees** | 3-8% | 0% |
| **Transparency** | Quarterly reports | Real-time blockchain |
| **Donor to Recipient** | 60-85% | 100% |
| **Fraud Prevention** | Manual audits | AI + Inspector oversight + Attack blocking |
| **Security Monitoring** | Periodic reviews | Real-time AI threat detection and blocking |
| **Emergency Response** | Slow/bureaucratic | Inspector coin addition (instant) |
| **Audit Trail** | Limited/delayed | Complete blockchain + Inspector logs |
| **Global Access** | Limited | Unlimited |
| **Currency Support** | Usually single | Any currency |
| **Withdrawal Speed** | Days/weeks | Immediate approval |

---

## 🎯 The Circular Economy Advantage

**How PCS Creates Infinite Value from Finite Currency:**

1. Receiver gets 10,000 PCS monthly credit
2. Donor purchases PCS crypto from the receivers or from charity organizations
3. The PCS coins are permanently in the donor's profile for life, so everyone can view each donation and the total donations
4. Process repeats infinitely

**Result:** Receivers continuously receive monthly credits to sell, while donors accumulate PCS as permanent proof of their charitable contributions with complete transparency at zero cost.

---

## 🚀 Why PCS is Revolutionary

1. **First truly non-profit charity platform** - Zero fees, zero profit motive
2. **Blockchain transparency** without cryptocurrency speculation
3. **Circular economy model** - Infinite value from finite tokens
4. **Direct impact** - 100% of donations reach recipients
5. **Global accessibility** - Works with any payment method
6. **Law enforcement friendly** - Full inspector oversight
7. **DISA STIG compliant** - Military-grade security
8. **Emergency response ready** - Inspector coin addition for disaster relief
9. **Complete accountability** - Every action logged and auditable
10. **SEO-optimized public profiles** - Charities and receivers discoverable via Google search
11. **Global directory** - Centralized listing of all verified charities and receivers

---

## 📞 Perfect For

- ✅ Individual donors seeking transparency
- ✅ Verified recipients in need
- ✅ Registered charity organizations
- ✅ Law enforcement agencies
- ✅ Governments monitoring aid distribution
- ✅ International relief efforts
- ✅ Community-based giving programs
- ✅ Corporate social responsibility initiatives

---

## 💪 Bottom Line

**PCS delivers what traditional charities promise but rarely achieve:**
- 100% of donations reaching those in need
- Complete transparency of every transaction
- Zero fees or hidden costs
- Verifiable impact through blockchain
- Global accessibility without barriers
- Security and fraud prevention
- Real-time threat detection and automatic blocking
- Emergency response capabilities through inspector intervention
- Complete audit trail for all transactions and administrative actions

**The result:** More money helping more people with complete accountability and military-grade security.

---

*Perfect Charity System - Where every dollar counts, and every transaction is transparent.*
