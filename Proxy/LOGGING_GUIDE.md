# Proxy Logging System

## Overview
A comprehensive logging system has been implemented to track the complete authentication flow through the AITM proxy. All logs are written to `Proxy/logs/` with timestamped filenames.

## Log File Location
```
Proxy/logs/proxy-YYYY-MM-DDTHH-mm-ss-SSSZ.log
```

## Log Events Tracked

### Session Management
- **SESSION_CREATED** - When a new victim session is started
- **SESSION_CREATED_LOGIN** - When a session is created at the login endpoint
- **ENDPOINT_PERSONAL** - When /p endpoint is accessed
- **ENDPOINT_PERSONAL_REDIRECT** - When redirecting from /p to /login

### Request Flow
- **PROXY_REQUEST** - All outgoing requests to Microsoft
  - Protocol, hostname, path, method
  - Body length, session ID
  - Navigation request flag

- **SERVICE_WORKER_REQUEST** - Requests coming from the service worker
  - URL being requested
  - Method type
  - Source/destination hostnames

### Authentication & Passwords
- **FORM_SUBMIT** - Password/form submissions
  - Target URL (should be proxy domain)
  - HTTP method (POST)
  - Body preview (first 200 chars)

- **PASSWORD_RESPONSE** - Response after password submission
  - HTTP status code
  - Location header (if redirect)
  - Content-Type

### Redirects
- **REDIRECT_INTERNAL** - Redirects being followed internally
  - Redirect status code (301/302)
  - From/To URLs
  - Session ID

- **REDIRECT_DETECTED** - Any redirect found
  - Status, source, destination
  - Whether it will be followed internally

### Response Processing
- **RESPONSE** - All responses from Microsoft
  - Status code
  - URL that was requested
  - Location header
  - Content-Type and length

- **CLIENT_RESPONSE** - Final response sent to browser
  - Status code
  - Content-Type
  - Whether it contains a location header
  - The location if present

### Cookie Management
- **COOKIE_CAPTURE** - When cookies are extracted from responses
  - Number of cookies captured
  - Source hostname
  - Target (proxy hostname)

## How to Read the Logs

Each log line follows this format:
```
[TIMESTAMP] [CATEGORY] Message | {JSON details}
```

Example:
```
[2026-07-20T12:24:59.383Z] [ENDPOINT_PERSONAL_REDIRECT] Redirecting to personal login endpoint | {"fromURL":"/p?Amethyst=Sachiel1&Chamuel=Azrael1","toURL":"/login?...redirect_urI=https%3A%2F%2Flogin.live.com%2F","clientIP":"::ffff:127.0.0.1"}
```

## Debugging the /p Endpoint Redirect Issue

### Expected Flow for /p Endpoint (Personal)
1. User accesses `/p?Amethyst=...&Chamuel=...`
2. Logs: **ENDPOINT_PERSONAL** - Initial access
3. Logs: **ENDPOINT_PERSONAL_REDIRECT** - Redirect to /login with redirect_urI=login.live.com
4. Logs: **LOGIN_ENDPOINT** - /login endpoint receives request
5. Logs: **SESSION_CREATED_LOGIN** - New session created for login.live.com
6. Browser follows redirect, requests login page again with session cookie
7. Logs: **PROXY_REQUEST** - Request for login.live.com home page
8. Logs: **RESPONSE** - Microsoft responds with 200 (login form HTML)
9. Logs: **CLIENT_RESPONSE** - Proxy sends HTML to browser
10. User enters email/password
11. Browser POSTs password form
12. Logs: **FORM_SUBMIT** - Password submission detected
13. Logs: **PROXY_REQUEST** - Request to Microsoft's ppsecure/post.srf
14. Logs: **PASSWORD_RESPONSE** - Response from Microsoft
15. Logs: **REDIRECT_INTERNAL** or **REDIRECT_DETECTED** - If Microsoft returns redirect
16. Logs: **CLIENT_RESPONSE** - What's sent back to browser

### Critical Section to Monitor
If /p redirects to real login.live.com instead of staying on proxy, look for:
1. Is the **FORM_SUBMIT** going to proxy domain or absolute login.live.com?
2. What **PASSWORD_RESPONSE** does Microsoft send?
3. Are there **REDIRECT_INTERNAL** entries that aren't being properly handled?
4. What does **CLIENT_RESPONSE** show after password submission?

## Key Differences Between /p and /c

### Personal (/p) - Expected behavior
- redirect_urI = https://login.live.com/
- SESSION hostname should be "login.live.com"
- Form should POST to proxy domain (relative URLs)

### Corporate (/c) - Working correctly
- redirect_urI = https://login.microsoftonline.com/
- SESSION hostname should be "login.microsoftonline.com"
- Form POSTs to proxy domain correctly

## Analyzing Password Authentication Failure

The password authentication is the critical step where the /p endpoint redirects to the real login.live.com. To debug this:

1. Find all **PASSWORD_RESPONSE** entries in the logs
2. Check the status code - should not be a 302 to login.live.com
3. Look at preceding **FORM_SUBMIT** entry
4. Check if form data is being sent to proxy or real Microsoft
5. Compare with /c endpoint logs to see the difference

## Commands to View Logs

PowerShell:
```powershell
$logDir = "C:\Users\palmo\Documents\TOOLS\New pROJECT\PDF360\Proxy\logs"
Get-ChildItem $logDir -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Select-Object FullName
Get-Content "PATH_TO_LOG_FILE" -Tail 100  # Last 100 lines
```

Bash:
```bash
ls -lah "C:/Users/palmo/Documents/TOOLS/New pROJECT/PDF360/Proxy/logs/" | head -1
tail -n 100 "PATH_TO_LOG_FILE"
```

## Next Steps for Testing

1. Kill existing servers
2. Start proxy with `npm run start:all`
3. Access /p endpoint: `http://127.0.0.1:3001/p?Amethyst=Sachiel1&Chamuel=Azrael1`
4. Check logs for **ENDPOINT_PERSONAL_REDIRECT** event
5. Get the log file path from the latest entry
6. Watch logs in real-time as you interact with login form
7. Compare /p logs with /c logs to identify differences
