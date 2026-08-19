# ColdCloud Backend

Follow-up automation backend — Express + MongoDB + Twilio + Claude AI.

---

## Files

```
server.js      ← Main Express app — all routes
models.js      ← MongoDB schemas (User, Lead, Message)
sequence.js    ← Sequence engine (trigger steps, schedule next, cron processor)
twilio.js      ← Twilio send functions (SMS, WhatsApp, call)
ai.js          ← AI message generation (Claude) with template fallback
middleware.js  ← JWT auth middleware
.env.example   ← Copy to .env and fill in your values
```

---

## Quick start (local)

```bash
# 1. Install dependencies
npm install

# 2. Copy and fill in environment variables
cp .env.example .env

# 3. Start the server
npm run dev        # development (auto-restart)
npm start          # production
```

Server runs on http://localhost:3001

---

## Environment variables

| Variable | Where to get it |
|---|---|
| `MONGODB_URI` | mongodb.com → free cluster → Connect |
| `JWT_SECRET` | Any random 32+ character string |
| `TWILIO_ACCOUNT_SID` | twilio.com/console |
| `TWILIO_AUTH_TOKEN` | twilio.com/console |
| `TWILIO_PHONE_NUMBER` | Twilio → Phone Numbers → Buy |
| `TWILIO_WHATSAPP_NUMBER` | Twilio → Messaging → WhatsApp Sandbox |
| `ANTHROPIC_API_KEY` | console.anthropic.com → API keys |
| `CRON_SECRET` | Any random string |
| `FRONTEND_URL` | URL of your deployed frontend (for CORS) |

---

## API routes

### Auth
```
POST   /auth/signup     { email, password, name, company }
POST   /auth/login      { email, password }
GET    /auth/me         → current user (requires token)
```

### Leads
```
GET    /leads           → list all leads (auth)
POST   /leads           { name, phone, context, notes, channels } → add + start sequence
PATCH  /leads/:id       { status, notes, context } → update lead
DELETE /leads/:id       → delete lead + messages
```

### Messages
```
GET    /messages        → activity log (auth)
POST   /messages/send   { leadId, channel, body } → send one message now
POST   /messages/generate { leadId, step, channel } → preview AI message
```

### Dashboard
```
GET    /dashboard       → stats, chart data, recent activity
```

### Sequence
```
GET    /sequence        → get sequence config
PATCH  /sequence        { config } → save sequence config
```

### Settings
```
PATCH  /settings        { name, company, bizDesc }
```

### Webhooks (Twilio posts here when lead replies)
```
POST   /webhooks/sms
POST   /webhooks/whatsapp
```

### Cron
```
POST   /cron/process    Header: x-cron-secret: <CRON_SECRET>
```

---

## Connecting Twilio webhooks

1. Go to twilio.com/console → Phone Numbers → your number
2. Under **Messaging** → A message comes in → set to:
   ```
   https://your-backend.railway.app/webhooks/sms
   ```
3. For WhatsApp sandbox → Messaging → WhatsApp → Sandbox settings:
   ```
   When a message comes in: https://your-backend.railway.app/webhooks/whatsapp
   ```

---

## Deploy to Railway (recommended — free tier)

```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login
railway login

# 3. Create project
railway init

# 4. Add environment variables
railway variables set MONGODB_URI="..." JWT_SECRET="..." TWILIO_ACCOUNT_SID="..." ...

# 5. Deploy
railway up
```

Your backend URL will be something like:
`https://coldcloud-backend-production.up.railway.app`

---

## Deploy to Render (alternative — free tier)

1. Push code to a GitHub repo
2. Go to render.com → New Web Service → connect your repo
3. Build command: `npm install`
4. Start command: `npm start`
5. Add all environment variables in the Render dashboard

---

## Connecting the frontend

In `coldcloud-v3.html`, find `sendViaAPI()` and update the backend URL:

```javascript
const BACKEND_URL = 'https://your-backend.railway.app'
```

The frontend will then send real messages through your backend.

---

## Setting up the external cron (for scheduled follow-ups)

The server runs an in-process cron every hour. For more reliability, also set up an external cron:

**Railway:** Add a cron job in the Railway dashboard:
- Schedule: `0 * * * *` (every hour)
- Command: `curl -X POST https://your-backend.railway.app/cron/process -H "x-cron-secret: YOUR_CRON_SECRET"`

**Vercel:** Add to `vercel.json`:
```json
{
  "crons": [{ "path": "/cron/process", "schedule": "0 * * * *" }]
}
```
