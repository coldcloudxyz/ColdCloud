# ColdCloud — Complete Project

Follow-up automation for businesses. Automatically send WhatsApp, SMS, and phone call follow-ups to convert more leads.

---

## Project structure

```
coldcloud-complete/
├── app/
│   └── index.html          ← Full SaaS app (auth, dashboard, leads, sequences, settings)
├── backend/
│   ├── server.js            ← Express server — all API routes
│   ├── models.js            ← MongoDB schemas (User, Lead, Message)
│   ├── sequence.js          ← Sequence engine + cron processor
│   ├── twilio.js            ← SMS, WhatsApp, call sending
│   ├── ai.js                ← Claude AI message personalisation
│   ├── middleware.js        ← JWT auth middleware
│   ├── package.json
│   ├── .env.example         ← Copy to .env and fill in your values
│   └── README.md            ← Backend setup + deploy instructions
└── landing/
    ├── index.html           ← Marketing landing page
    ├── styles/main.css
    ├── scripts/main.js
    └── assets/
```

---

## Quick start

### 1. Run the backend

```bash
cd backend
cp .env.example .env
# Fill in MONGODB_URI, JWT_SECRET, TWILIO_*, ANTHROPIC_API_KEY
npm install
npm run dev
```

Backend runs on http://localhost:3001

### 2. Open the app

Open `app/index.html` in your browser — or serve it with any static file server:

```bash
cd app
npx serve .
```

In `app/index.html`, set your backend URL at the top of the `<script>`:

```javascript
const BACKEND_URL = 'http://localhost:3001'
```

### 3. Open the landing page

Open `landing/index.html` in your browser. Update all `href="app.html"` links to point to your deployed app URL.

---

## Environment variables (backend/.env)

| Variable | Where to get it |
|---|---|
| `MONGODB_URI` | mongodb.com → free cluster |
| `JWT_SECRET` | Any random 32+ character string |
| `TWILIO_ACCOUNT_SID` | twilio.com/console |
| `TWILIO_AUTH_TOKEN` | twilio.com/console |
| `TWILIO_PHONE_NUMBER` | Twilio → Phone Numbers |
| `TWILIO_WHATSAPP_NUMBER` | Twilio → WhatsApp Sandbox |
| `ANTHROPIC_API_KEY` | console.anthropic.com |
| `CRON_SECRET` | Any random string |
| `FRONTEND_URL` | URL of your deployed app (for CORS) |

---

## Deploy

### Backend → Railway (free tier)
```bash
cd backend
npm install -g @railway/cli
railway login
railway init
railway variables set MONGODB_URI="..." JWT_SECRET="..." # etc.
railway up
```

### App + Landing → Vercel or Netlify
Drag and drop `app/` and `landing/` folders into vercel.com or netlify.com.

Or with Vercel CLI:
```bash
cd app && vercel
cd ../landing && vercel
```

### After deploy
1. Set `BACKEND_URL` in `app/index.html` to your Railway backend URL
2. Set `FRONTEND_URL` in backend `.env` to your Vercel app URL
3. Configure Twilio webhooks to point to `https://your-backend.railway.app/webhooks/sms` and `/webhooks/whatsapp`

---

## Demo login

The app includes a built-in demo account:
- **Email:** `demo@coldcloud.io`
- **Password:** `demo1234`

---

## What works now (without backend)

- Full UI — login, signup, dashboard, leads, sequences, settings
- Per-user data in localStorage
- Phone validation, duplicate detection
- CSV import
- Sequence config
- Lead detail panel with edit
- Opt-out handling
- Message simulation (shows as "simulated" in activity log)

## What works after connecting the backend

- Real SMS via Twilio
- Real WhatsApp via Twilio sandbox
- Real phone calls via Twilio
- AI-personalised messages via Claude
- Replies appear automatically via Twilio webhooks
- Scheduled follow-ups run 24/7 even when browser is closed
- Data persists in MongoDB across all devices
