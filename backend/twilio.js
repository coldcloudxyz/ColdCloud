// ─────────────────────────────────────────────────────────────────
// Twilio helper — uses per-user credentials when available,
// falls back to environment variables (admin/shared account)
// ─────────────────────────────────────────────────────────────────
const twilio = require('twilio')

// Cache clients by SID so we don't recreate for every message
const clientCache = {}

function getClient(creds = {}) {
  const sid   = creds.sid   || process.env.TWILIO_ACCOUNT_SID
  const token = creds.token || process.env.TWILIO_AUTH_TOKEN

  if (!sid || !token) {
    throw new Error('Twilio credentials not configured. Add your Account SID and Auth Token in Settings.')
  }

  const key = sid
  if (!clientCache[key]) {
    clientCache[key] = twilio(sid, token)
  }
  return clientCache[key]
}

async function sendSMS(to, body, creds = {}) {
  const c    = getClient(creds)
  const from = creds.phone || process.env.TWILIO_PHONE_NUMBER
  if (!from) throw new Error('No sender phone number configured. Add your Twilio phone number in Settings.')
  const msg = await c.messages.create({ body, from, to })
  return msg.sid
}

async function sendWhatsApp(to, body, creds = {}) {
  const c    = getClient(creds)
  const fromRaw = creds.wa || creds.phone || process.env.TWILIO_WHATSAPP_NUMBER || process.env.TWILIO_PHONE_NUMBER
  if (!fromRaw) throw new Error('No WhatsApp number configured. Add your Twilio phone number in Settings.')
  const from = fromRaw.startsWith('whatsapp:') ? fromRaw : `whatsapp:${fromRaw}`
  const toWa = to.startsWith('whatsapp:')      ? to      : `whatsapp:${to}`
  const msg  = await c.messages.create({ body, from, to: toWa })
  return msg.sid
}

async function makeCall(to, body, creds = {}) {
  const c    = getClient(creds)
  const from = creds.phone || process.env.TWILIO_PHONE_NUMBER
  if (!from) throw new Error('No caller phone number configured. Add your Twilio phone number in Settings.')
  const safeBody = body.replace(/[<>&"']/g, ' ')
  const twiml = `<Response>
  <Say voice="Polly.Joanna" rate="90%">${safeBody}</Say>
  <Pause length="1"/>
  <Say voice="Polly.Joanna" rate="90%">Press 1 to speak with us, or simply reply to our message. Have a great day.</Say>
  <Gather numDigits="1" timeout="5"/>
</Response>`
  const call = await c.calls.create({ twiml, to, from })
  return call.sid
}

async function send(channel, to, body, creds = {}) {
  switch (channel) {
    case 'sms':      return { sid: await sendSMS(to, body, creds),      channel }
    case 'whatsapp': return { sid: await sendWhatsApp(to, body, creds), channel }
    case 'call':     return { sid: await makeCall(to, body, creds),     channel }
    default: throw new Error(`Unknown channel: ${channel}`)
  }
}

// Check if credentials (user or env) are usable
function hasCredentials(creds = {}) {
  const sid   = creds.sid   || process.env.TWILIO_ACCOUNT_SID
  const token = creds.token || process.env.TWILIO_AUTH_TOKEN
  const phone = creds.phone || process.env.TWILIO_PHONE_NUMBER
  return !!(sid && token && phone)
}

// Validate Twilio webhook signature
function validateWebhook(req) {
  const token     = process.env.TWILIO_AUTH_TOKEN
  const signature = req.headers['x-twilio-signature'] || ''
  const url       = `${process.env.FRONTEND_URL || 'https://your-domain.com'}${req.originalUrl}`
  if (!token) return false
  return twilio.validateRequest(token, signature, url, req.body)
}

module.exports = { send, sendSMS, sendWhatsApp, makeCall, hasCredentials, validateWebhook }
