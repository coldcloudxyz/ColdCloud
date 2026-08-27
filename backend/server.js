'use strict'
require('dotenv').config()

const express       = require('express')
const cors          = require('cors')
const helmet        = require('helmet')
const bcrypt        = require('bcryptjs')
const jwt           = require('jsonwebtoken')
const cron          = require('node-cron')
const rateLimit     = require('express-rate-limit')
const mongoSanitize = require('express-mongo-sanitize')
const { query, getOne, getMany, isConnected } = require('./db')
const { authMiddleware }                      = require('./middleware')
const { send, hasCredentials, validateWebhook } = require('./twilio')
const { generateMessage }                     = require('./ai')
const { triggerStep, processScheduledFollowUps } = require('./sequence')

const app  = express()
app.set('trust proxy', 1)
const PORT = process.env.PORT || 3001

// ── Security ──────────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }))

const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(',').map(o => o.trim()).filter(Boolean)
  : []

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true)
    if (!allowedOrigins.length) return cb(new Error('CORS: FRONTEND_URL not set'), false)
    if (allowedOrigins.includes(origin)) return cb(null, true)
    return cb(new Error(`CORS: ${origin} not allowed`), false)
  },
  credentials: true,
}))

app.use('/webhooks', express.urlencoded({ extended: false }))
app.use(express.json({ limit: '50kb' }))
app.use(mongoSanitize({ replaceWith: '_' }))

// ── Rate limiting ─────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 15, standardHeaders: true, legacyHeaders: false, message: { ok: false, error: 'Too many attempts — try again in 15 minutes' } })
const apiLimiter  = rateLimit({ windowMs: 60*1000, max: 120, standardHeaders: true, legacyHeaders: false, message: { ok: false, error: 'Too many requests' } })
app.use(['/leads','/messages','/dashboard','/sequence','/settings'], apiLimiter)

// ── DB guard ─────────────────────────────────────────────────
async function requireDB(req, res, next) {
  const ok = await isConnected()
  if (!ok) return res.status(503).json({ ok: false, error: 'Database unavailable — try again shortly' })
  next()
}

// ── Helpers ──────────────────────────────────────────────────
function escape(str) {
  return String(str || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&').substring(0, 100)
}
function row2user(r) {
  if (!r) return null
  return {
    id: r.id, email: r.email, name: r.name, company: r.company,
    bizDesc: r.biz_desc, senderName: r.sender_name, senderPhone: r.sender_phone,
    senderEmail: r.sender_email, signOff: r.sign_off,
    twilioSid: r.twilio_sid, twilioPhone: r.twilio_phone, twilioWa: r.twilio_wa,
    twilioMode: r.twilio_mode || 'shared', twilioConfigured: !!(r.twilio_sid && r.twilio_phone),
    customMessages: r.custom_messages || '{}',
    sequenceConfig: r.sequence_config || {},
    createdAt: r.created_at,
  }
}
function row2lead(r) {
  if (!r) return null
  return {
    _id: r.id, id: r.id, userId: r.user_id,
    name: r.name, phone: r.phone, context: r.context,
    notes: r.notes, business: r.business,
    channels: r.channels || ['whatsapp','sms','call'],
    status: r.status, currentStep: r.current_step,
    nextFollowUpAt: r.next_follow_up_at, totalSent: r.total_sent,
    repliedAt: r.replied_at, convertedAt: r.converted_at, optedOutAt: r.opted_out_at,
    createdAt: r.created_at,
  }
}
function row2msg(r) {
  if (!r) return null
  return {
    _id: r.id, id: r.id, userId: r.user_id, leadId: r.lead_id,
    leadName: r.lead_name, type: r.type, direction: r.direction,
    body: r.body, status: r.status, deliveryStatus: r.delivery_status,
    twilioSid: r.twilio_sid, step: r.step, errorMessage: r.error_message,
    createdAt: r.created_at,
  }
}

// ── Health ────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const db = await isConnected()
  res.json({
    ok: true, ts: new Date().toISOString(),
    db: db ? 'connected' : 'disconnected',
    ai: !!process.env.OPENROUTER_API_KEY,
    twilio: !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN),
  })
})

// ═══════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════
app.post('/auth/signup', authLimiter, requireDB, async (req, res) => {
  try {
    const { email, password, name, company } = req.body
    if (!email || !password || !name)
      return res.status(400).json({ ok: false, error: 'email, password, and name are required' })
    if (password.length < 8)
      return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters' })
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ ok: false, error: 'Invalid email address' })

    const existing = await getOne('SELECT id FROM users WHERE email=$1', [email.toLowerCase().trim()])
    if (existing) return res.status(409).json({ ok: false, error: 'An account with this email already exists' })

    const hash = await bcrypt.hash(password, 12)
    const user = await getOne(
      'INSERT INTO users (email, password, name, company) VALUES ($1,$2,$3,$4) RETURNING *',
      [email.toLowerCase().trim(), hash, name.trim(), (company||'').trim()]
    )
    const token = jwt.sign({ userId: user.id, email: user.email, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.status(201).json({ ok: true, token, user: row2user(user) })
  } catch (err) {
    console.error('[Signup]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

app.post('/auth/login', authLimiter, requireDB, async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password)
      return res.status(400).json({ ok: false, error: 'Email and password are required' })
    const user = await getOne('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()])
    if (!user) return res.status(401).json({ ok: false, error: 'Incorrect email or password' })
    const valid = await bcrypt.compare(password, user.password)
    if (!valid) return res.status(401).json({ ok: false, error: 'Incorrect email or password' })
    const token = jwt.sign({ userId: user.id, email: user.email, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' })
    res.json({ ok: true, token, user: row2user(user) })
  } catch (err) {
    console.error('[Login]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

app.post('/auth/forgot-password', authLimiter, requireDB, async (req, res) => {
  try {
    const { email } = req.body
    if (!email) return res.status(400).json({ ok: false, error: 'Email is required' })
    const user = await getOne('SELECT id, email FROM users WHERE email=$1', [email.toLowerCase().trim()])
    if (user) console.log(`[Auth] Password reset requested: ${user.email}`)
    res.json({ ok: true })
  } catch (err) { res.status(500).json({ ok: false, error: 'Server error' }) }
})

app.get('/auth/me', authMiddleware, requireDB, async (req, res) => {
  try {
    const user = await getOne('SELECT * FROM users WHERE id=$1', [req.user.userId])
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' })
    res.json({ ok: true, user: row2user(user) })
  } catch (err) { res.status(500).json({ ok: false, error: 'Server error' }) }
})

// ═══════════════════════════════════════════
// LEADS
// ═══════════════════════════════════════════
app.get('/leads', authMiddleware, requireDB, async (req, res) => {
  try {
    const { status, search } = req.query
    let sql = 'SELECT * FROM leads WHERE user_id=$1'
    const params = [req.user.userId]
    if (status && status !== 'all') { sql += ` AND status=$${params.length+1}`; params.push(status) }
    if (search) {
      const s = '%' + escape(search) + '%'
      sql += ` AND (name ILIKE $${params.length+1} OR phone ILIKE $${params.length+2})`
      params.push(s, s)
    }
    sql += ' ORDER BY created_at DESC LIMIT 1000'
    const rows = await getMany(sql, params)
    res.json({ ok: true, leads: rows.map(row2lead) })
  } catch (err) {
    console.error('[GET /leads]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

app.post('/leads', authMiddleware, requireDB, async (req, res) => {
  try {
    const { name, phone, context, notes, business, channels } = req.body
    if (!name || !phone || !context)
      return res.status(400).json({ ok: false, error: 'name, phone, and context are required' })
    const cleanPhone = phone.replace(/[\s\-\(\)]/g, '')
    if (!/^\+?[0-9]{7,15}$/.test(cleanPhone))
      return res.status(400).json({ ok: false, error: 'Invalid phone number — include country code' })
    const dup = await getOne(
      `SELECT id FROM leads WHERE user_id=$1 AND phone ILIKE $2 AND status IN ('active','replied')`,
      [req.user.userId, '%' + cleanPhone.replace('+','') + '%']
    )
    if (dup) return res.status(409).json({ ok: false, error: 'A lead with this phone number is already active' })
    const ch = Array.isArray(channels) ? channels.filter(c => ['whatsapp','sms','call'].includes(c)) : ['whatsapp','sms','call']
    const lead = await getOne(
      `INSERT INTO leads (user_id, name, phone, context, notes, business, channels)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.user.userId, name.trim(), phone.trim(), context.trim(), (notes||'').substring(0,500), (business||'').substring(0,200), ch]
    )
    // Fire step 1 async
    triggerStep(row2lead(lead), 1).catch(e => console.error('[triggerStep]', e.message))
    res.status(201).json({ ok: true, lead: row2lead(lead) })
  } catch (err) {
    console.error('[POST /leads]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

app.patch('/leads/:id', authMiddleware, requireDB, async (req, res) => {
  try {
    const lead = await getOne('SELECT * FROM leads WHERE id=$1 AND user_id=$2', [req.params.id, req.user.userId])
    if (!lead) return res.status(404).json({ ok: false, error: 'Lead not found' })
    const allowed = ['active','replied','converted','completed','unsubscribed']
    if (req.body.status && !allowed.includes(req.body.status))
      return res.status(400).json({ ok: false, error: 'Invalid status' })
    const sets = []; const vals = []
    const set = (col, val) => { vals.push(val); sets.push(`${col}=$${vals.length}`) }
    if (req.body.notes   !== undefined) set('notes',   String(req.body.notes).substring(0,500))
    if (req.body.context !== undefined) set('context', String(req.body.context).substring(0,2000))
    if (req.body.status  !== undefined) {
      set('status', req.body.status)
      if (req.body.status === 'unsubscribed') { set('opted_out_at', 'NOW()'); set('next_follow_up_at', null) }
      if (req.body.status === 'converted')    { set('converted_at', 'NOW()'); set('next_follow_up_at', null) }
    }
    if (!sets.length) return res.json({ ok: true, lead: row2lead(lead) })
    vals.push(req.params.id)
    const updated = await getOne(`UPDATE leads SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`, vals)
    if (req.body.status === 'unsubscribed') {
      await query(
        `INSERT INTO messages (user_id, lead_id, lead_name, type, direction, body, status, step)
         VALUES ($1,$2,$3,'reply','inbound','STOP — opted out','received',$4)`,
        [req.user.userId, req.params.id, lead.name, lead.current_step]
      )
    }
    res.json({ ok: true, lead: row2lead(updated) })
  } catch (err) {
    console.error('[PATCH /leads]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

app.delete('/leads/:id', authMiddleware, requireDB, async (req, res) => {
  try {
    const lead = await getOne('DELETE FROM leads WHERE id=$1 AND user_id=$2 RETURNING id', [req.params.id, req.user.userId])
    if (!lead) return res.status(404).json({ ok: false, error: 'Lead not found' })
    res.json({ ok: true })
  } catch (err) {
    console.error('[DELETE /leads]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

// ═══════════════════════════════════════════
// MESSAGES
// ═══════════════════════════════════════════
app.get('/messages', authMiddleware, requireDB, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit)||50, 200)
    let sql = 'SELECT * FROM messages WHERE user_id=$1'
    const params = [req.user.userId]
    if (req.query.leadId) { sql += ` AND lead_id=$2`; params.push(req.query.leadId) }
    sql += ` ORDER BY created_at DESC LIMIT $${params.length+1}`
    params.push(limit)
    const rows = await getMany(sql, params)
    res.json({ ok: true, messages: rows.map(row2msg) })
  } catch (err) {
    console.error('[GET /messages]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

app.post('/messages/send', authMiddleware, requireDB, async (req, res) => {
  try {
    const { leadId, channel, body } = req.body
    if (!leadId || !channel || !body)
      return res.status(400).json({ ok: false, error: 'leadId, channel, and body are required' })
    if (!['whatsapp','sms','call'].includes(channel))
      return res.status(400).json({ ok: false, error: 'Invalid channel' })
    const lead = await getOne('SELECT * FROM leads WHERE id=$1 AND user_id=$2', [leadId, req.user.userId])
    if (!lead) return res.status(404).json({ ok: false, error: 'Lead not found' })
    const user = await getOne('SELECT * FROM users WHERE id=$1', [req.user.userId])
    // Always use user's own Twilio credentials
    if (!user.twilio_sid || !user.twilio_token || !user.twilio_phone) {
      return res.status(400).json({ ok: false, error: 'Please add your Twilio credentials in Settings before sending messages.' })
    }
    const creds = { sid: user.twilio_sid, token: user.twilio_token, phone: user.twilio_phone||'', wa: user.twilio_wa||'' }
    const msg = await getOne(
      `INSERT INTO messages (user_id, lead_id, lead_name, type, direction, body, status, step)
       VALUES ($1,$2,$3,$4,'outbound',$5,'queued',0) RETURNING *`,
      [req.user.userId, lead.id, lead.name, channel, String(body).substring(0,1600)]
    )
    const result = await send(channel, lead.phone, body, creds)
    await query(`UPDATE messages SET status='sent', twilio_sid=$1 WHERE id=$2`, [result.sid, msg.id])
    res.json({ ok: true, message: row2msg(msg), sid: result.sid })
  } catch (err) {
    console.error('[POST /messages/send]', err.message)
    res.status(500).json({ ok: false, error: err.message })
  }
})

app.post('/messages/generate', authMiddleware, requireDB, async (req, res) => {
  try {
    const { leadId, step, channel, senderName, senderPhone, signOff } = req.body
    if (!step || !channel)
      return res.status(400).json({ ok: false, error: 'step and channel are required' })
    const user = await getOne('SELECT * FROM users WHERE id=$1', [req.user.userId])
    // Use lead context if leadId provided, otherwise use generic context
    let leadName = 'there', context = 'your product or service', notes = ''
    if (leadId && leadId !== 'preview') {
      const lead = await getOne('SELECT * FROM leads WHERE id=$1 AND user_id=$2', [leadId, req.user.userId])
      if (lead) { leadName = lead.name; context = lead.context; notes = lead.notes || '' }
    }
    const body = await generateMessage({
      leadName, context, notes,
      step: Number(step), channel,
      bizName:     user?.company || user?.name,
      bizDesc:     user?.biz_desc || '',
      senderName:  senderName  || user?.sender_name  || user?.name?.split(' ')[0] || '',
      senderPhone: senderPhone || user?.sender_phone || '',
      signOff:     signOff     || user?.sign_off     || '',
    })
    res.json({ ok: true, body })
  } catch (err) {
    console.error('[POST /messages/generate]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

// ═══════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════
app.get('/dashboard', authMiddleware, requireDB, async (req, res) => {
  try {
    const uid = req.user.userId
    const [counts, sent, replies, recent, overtime, channels] = await Promise.all([
      getMany(`SELECT status, COUNT(*) FROM leads WHERE user_id=$1 GROUP BY status`, [uid]),
      getOne(`SELECT COUNT(*) FROM messages WHERE user_id=$1 AND direction='outbound' AND status IN ('sent','delivered')`, [uid]),
      getOne(`SELECT COUNT(*) FROM messages WHERE user_id=$1 AND direction='inbound'`, [uid]),
      getMany(`SELECT * FROM messages WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`, [uid]),
      getMany(`SELECT DATE(created_at) as _id, COUNT(*) as count FROM leads WHERE user_id=$1 AND created_at >= NOW()-INTERVAL '7 days' GROUP BY DATE(created_at) ORDER BY _id`, [uid]),
      getMany(`SELECT type as _id, COUNT(*) as count FROM messages WHERE user_id=$1 AND direction='outbound' GROUP BY type`, [uid]),
    ])
    const c = {}; counts.forEach(r => c[r.status] = parseInt(r.count))
    const totalLeads     = Object.values(c).reduce((a,b) => a+b, 0)
    const repliedLeads   = c.replied   || 0
    const convertedLeads = c.converted || 0
    const replyRate = totalLeads > 0 ? Math.round(((repliedLeads+convertedLeads)/totalLeads)*100) : 0
    res.json({
      ok: true,
      stats: {
        totalLeads, activeLeads: c.active||0, repliedLeads, convertedLeads,
        completedLeads: c.completed||0,
        totalSent:    parseInt(sent?.count||0),
        totalReplies: parseInt(replies?.count||0),
        replyRate, conversionRate: totalLeads>0?Math.round((convertedLeads/totalLeads)*100):0,
      },
      leadsOverTime:    overtime.map(r=>({_id:r._id,count:parseInt(r.count)})),
      channelBreakdown: channels.map(r=>({_id:r._id,count:parseInt(r.count)})),
      recentMessages:   recent.map(row2msg),
    })
  } catch (err) {
    console.error('[GET /dashboard]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

// ═══════════════════════════════════════════
// SEQUENCE
// ═══════════════════════════════════════════
app.get('/sequence', authMiddleware, requireDB, async (req, res) => {
  try {
    const user = await getOne('SELECT sequence_config, custom_messages FROM users WHERE id=$1', [req.user.userId])
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' })
    let customMessages = {}
    try { customMessages = JSON.parse(user.custom_messages || '{}') } catch(e) {}
    res.json({ ok: true, config: user.sequence_config, customMessages })
  } catch (err) { res.status(500).json({ ok: false, error: 'Server error' }) }
})

app.patch('/sequence', authMiddleware, requireDB, async (req, res) => {
  try {
    const { config, customMessages } = req.body
    if (!config) return res.status(400).json({ ok: false, error: 'config is required' })
    const validCh = ['whatsapp','sms','call']
    for (const k of ['step1','step2','step3','step4']) {
      const s = config[k]; if (!s) continue
      if (s.channel && !validCh.includes(s.channel))
        return res.status(400).json({ ok: false, error: `Invalid channel for ${k}` })
    }
    const sets = ['sequence_config=$1']; const vals = [config]
    if (customMessages && typeof customMessages === 'object') {
      sets.push(`custom_messages=$${vals.length+1}`)
      vals.push(JSON.stringify(customMessages).substring(0,10000))
    }
    vals.push(req.user.userId)
    await query(`UPDATE users SET ${sets.join(',')} WHERE id=$${vals.length}`, vals)
    res.json({ ok: true })
  } catch (err) { res.status(500).json({ ok: false, error: 'Server error' }) }
})

// ═══════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════
app.patch('/settings', authMiddleware, requireDB, async (req, res) => {
  try {
    const { name, company, bizDesc, senderName, senderPhone, senderEmail, signOff,
            twilioSid, twilioToken, twilioPhone, twilioWa, twilioMode, customMessages } = req.body
    const sets = []; const vals = []
    const set = (col, val) => { vals.push(val); sets.push(`${col}=$${vals.length}`) }
    if (name        !== undefined) set('name',         String(name).trim().substring(0,100))
    if (company     !== undefined) set('company',      String(company).trim().substring(0,200))
    if (bizDesc     !== undefined) set('biz_desc',     String(bizDesc).trim().substring(0,500))
    if (senderName  !== undefined) set('sender_name',  String(senderName).trim().substring(0,100))
    if (senderPhone !== undefined) set('sender_phone', String(senderPhone).trim().substring(0,30))
    if (senderEmail !== undefined) set('sender_email', String(senderEmail).trim().substring(0,200))
    if (signOff     !== undefined) set('sign_off',     String(signOff).trim().substring(0,200))
    if (twilioSid   !== undefined) set('twilio_sid',   String(twilioSid).trim().substring(0,50))
    if (twilioPhone !== undefined) set('twilio_phone', String(twilioPhone).trim().substring(0,30))
    if (twilioWa    !== undefined) set('twilio_wa',    String(twilioWa).trim().substring(0,40))
    if (twilioToken && !twilioToken.startsWith('•')) set('twilio_token', String(twilioToken).trim().substring(0,100))
    if (twilioMode  !== undefined && ['own'].includes(twilioMode)) set('twilio_mode', twilioMode)
    if (customMessages !== undefined) set('custom_messages', JSON.stringify(customMessages).substring(0,10000))
    if (!sets.length) return res.json({ ok: true })
    vals.push(req.user.userId)
    const user = await getOne(`UPDATE users SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`, vals)
    res.json({ ok: true, user: row2user(user) })
  } catch (err) {
    console.error('[PATCH /settings]', err.message)
    res.status(500).json({ ok: false, error: 'Server error' })
  }
})

// ═══════════════════════════════════════════
// WEBHOOKS
// ═══════════════════════════════════════════
app.post('/webhooks/sms', async (req, res) => {
  try {
    if (!validateWebhook(req)) return res.status(403).send('<Response/>')
    await handleReply(req.body.From||'', req.body.Body||'', 'sms')
    res.set('Content-Type','text/xml').send('<Response/>')
  } catch (err) { console.error('[Webhook/SMS]', err.message); res.status(500).send('<Response/>') }
})
app.post('/webhooks/whatsapp', async (req, res) => {
  try {
    if (!validateWebhook(req)) return res.status(403).send('<Response/>')
    await handleReply((req.body.From||'').replace('whatsapp:',''), req.body.Body||'', 'whatsapp')
    res.set('Content-Type','text/xml').send('<Response/>')
  } catch (err) { console.error('[Webhook/WA]', err.message); res.status(500).send('<Response/>') }
})

async function handleReply(fromPhone, body, channel) {
  if (!fromPhone || !body) return
  const clean   = fromPhone.replace(/[\s\-\(\)]/g,'')
  const pattern = '%' + clean.replace('+','') + '%'
  const lead = await getOne(
    `SELECT * FROM leads WHERE phone ILIKE $1 AND status IN ('active','replied')`,
    [pattern]
  )
  if (!lead) return console.warn(`[Webhook] No active lead for ${fromPhone}`)
  const lower = body.trim().toLowerCase()
  if (['stop','unsubscribe','cancel','quit','end'].includes(lower)) {
    await query(`UPDATE leads SET status='unsubscribed', opted_out_at=NOW(), next_follow_up_at=NULL WHERE id=$1`, [lead.id])
  } else {
    if (lead.status === 'active') {
      await query(`UPDATE leads SET status='replied', replied_at=NOW(), next_follow_up_at=NULL WHERE id=$1`, [lead.id])
    } else {
      await query(`UPDATE leads SET next_follow_up_at=NULL WHERE id=$1`, [lead.id])
    }
  }
  await query(
    `INSERT INTO messages (user_id, lead_id, lead_name, type, direction, body, status, delivery_status, step)
     VALUES ($1,$2,$3,'reply','inbound',$4,'received','received',$5)`,
    [lead.user_id, lead.id, lead.name, body.trim().substring(0,1600), lead.current_step]
  )
  console.log(`[Webhook] ${lead.name} replied via ${channel}`)
}

// ═══════════════════════════════════════════
// CRON
// ═══════════════════════════════════════════
app.post('/cron/process', async (req, res) => {
  if (req.headers['x-cron-secret'] !== process.env.CRON_SECRET)
    return res.status(403).json({ ok: false, error: 'Forbidden' })
  try {
    const result = await processScheduledFollowUps()
    res.json({ ok: true, ...result })
  } catch (err) { res.status(500).json({ ok: false, error: 'Server error' }) }
})

cron.schedule('0 * * * *', async () => {
  const db = await isConnected()
  if (!db) return
  console.log('[Cron] Running follow-up check...')
  try {
    const r = await processScheduledFollowUps()
    console.log(`[Cron] processed: ${r.processed}, errors: ${r.errors}`)
  } catch (err) { console.error('[Cron]', err.message) }
})

// ── Error handlers ────────────────────────
app.use((req, res) => res.status(404).json({ ok: false, error: 'Route not found' }))
app.use((err, req, res, next) => {
  if (err.message?.startsWith('CORS')) return res.status(403).json({ ok: false, error: 'Not allowed' })
  console.error('[Unhandled]', err.message)
  res.status(500).json({ ok: false, error: 'Server error' })
})

// ── Start ─────────────────────────────────
app.listen(PORT, () => {
  console.log('─'.repeat(50))
  console.log(`[Server] ColdCloud — port ${PORT}`)
  console.log(`[Server] DB:     ${process.env.DATABASE_URL ? '✓ Supabase URI set' : '✗ DATABASE_URL missing'}`)
  console.log(`[Server] CORS:   ${process.env.FRONTEND_URL || '⚠  not set'}`)
  console.log(`[Server] Twilio: ${(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) ? '✓' : '✗'}`)
  console.log(`[Server] AI:     ${process.env.OPENROUTER_API_KEY ? '✓ OpenRouter' : '✗ templates only'}`)
  console.log('─'.repeat(50))
})
