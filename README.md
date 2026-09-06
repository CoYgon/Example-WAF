# NOVA WAF V3

NOVA WAF is an open-source application-layer Web Application Firewall for Node.js and Express.

It provides:

- Rate limiting
- Threat scoring
- SQL injection detection
- XSS detection
- Path traversal detection
- Command injection detection
- Scanner detection
- Suspicious path detection
- IP whitelist
- CIDR blacklist
- Temporary bans
- Security event logging
- Real-time dashboard
- Request IDs
- Helmet security headers
- Environment-based configuration
- Admin API protection

## Requirements

Node.js 20+

## Installation

Clone the repository:

git clone https://github.com/YOUR_USERNAME/nova-waf.git

cd nova-waf

Install dependencies:

npm install

Create environment configuration:

copy .env.example .env

Start:

npm start

Open:

http://localhost:3000

## Development

npm run dev

## Production

Set:

NODE_ENV=production

and configure a strong ADMIN_TOKEN.

Then:

npm start

## Docker

docker compose up -d --build

Dashboard:

http://localhost:3000

Health:

http://localhost:3000/health

## Configuration

Configuration is controlled through environment variables.

WINDOW_MS

Rate-limit window.

MAX_REQUESTS_PER_WINDOW

Maximum requests allowed inside the window.

SOFT_THRESHOLD

Score required for a soft ban.

HARD_THRESHOLD

Score required for a hard ban.

CRITICAL_THRESHOLD

Score required for a critical ban.

WHITELIST_IPS

Comma-separated IP addresses.

Example:

WHITELIST_IPS=127.0.0.1,::1

BLACKLIST_CIDRS

Comma-separated IPv4 CIDR networks.

Example:

BLACKLIST_CIDRS=203.0.113.0/24

TRUST_PROXY

Set to true only when the application is behind a trusted reverse proxy.

ADMIN_TOKEN

Token required by the admin API.

## API

GET /health

Returns application health information.

GET /api/dashboard

Returns WAF statistics.

GET /api/events

Returns security events.

GET /api/test-status

Returns the current client's security profile.

POST /api/test-reset

Resets the current client's profile.

POST /api/admin/reset-all

Requires:

X-Admin-Token: YOUR_ADMIN_TOKEN

Clears all in-memory WAF state.

## Security

NOVA WAF is an application-layer WAF.

It is not a replacement for:

- Network firewalls
- DDoS mitigation
- CDN protection
- Reverse proxies
- Operating-system hardening
- Secure application development
- Authentication and authorization

For production deployments, place the application behind a trusted reverse proxy/CDN and use HTTPS.

Do not expose the admin API without setting ADMIN_TOKEN.

## Important

The default storage is in-memory.

Restarting the process clears:

- IP profiles
- threat scores
- temporary bans
- event history

For distributed production deployments, a shared datastore such as Redis should be used.

## License

MIT