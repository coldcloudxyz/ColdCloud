// ─────────────────────────────────────────────────────────────
// Sequence engine — triggers steps, schedules next, cron processor
// Uses Supabase (PostgreSQL) via pg
// ─────────────────────────────────────────────────────────────
const { query, getOne, getMany } = require('./db')
const { send }                   = require('./twilio')
const { generateMessage }        = require('./ai')

async function triggerStep(lead, stepNum) {
  const user = await getOne('SELECT * FROM users WHERE id=$1', [lead.userId])
  if (!user) throw new Error('User not found for lead ' + lead.id)

  const cfg = user.sequence_config || {}
  const stepCfg = cfg['step' + stepNum]

  if (!stepCfg || !stepCfg.enabled) {
    await scheduleNext(lead, user, stepNum)
    return null
  }

  const channel = (lead.channels || []).includes(stepCfg.channel)
    ? stepCfg.channel
    : (lead.channels || [])[0]

  if (!channel) {
    await markCompleted(lead)
    return null
  }

  // Check for user custom message first
  let body
  try {
    const cm = JSON.parse(user.custom_messages || '{}')
    const key = 'step' + stepNum + '_' + channel
    if (cm[key] && cm[key].trim()) {
      const fn = (lead.name || '').split(' ')[0]
      body = cm[key]
        .replace(/\{name\}/gi,    fn)
        .replace(/\{context\}/gi, (lead.context || '').substring(0, 70))
        .replace(/\{company\}/gi, user.company || '')
        .replace(/\{phone\}/gi,   user.sender_phone || '')
    }
  } catch(e) {}

  // Fall back to AI/template
  if (!body) {
    body = await generateMessage({
      leadName:    lead.name,
      context:     lead.context,
      notes:       lead.notes,
      step:        stepNum,
      channel,
      bizName:     user.company || user.name,
      bizDesc:     user.biz_desc || '',
      senderName:  user.sender_name  || user.name?.split(' ')[0] || '',
      senderPhone: user.sender_phone || '',
      signOff:     user.sign_off     || '',
    })
  }

  // Save message record
  const msg = await getOne(
    `INSERT INTO messages (user_id, lead_id, lead_name, type, direction, body, status, step)
     VALUES ($1,$2,$3,$4,'outbound',$5,'queued',$6) RETURNING *`,
    [lead.userId, lead.id, lead.name, channel, body, stepNum]
  )

  // Pick Twilio credentials
  // Always use user's own Twilio credentials
  if (!user.twilio_sid || !user.twilio_token || !user.twilio_phone) {
    console.warn(`[Sequence] User ${user.id} has no Twilio credentials — skipping`)
    return null
  }
  const creds = {
    sid:   user.twilio_sid,
    token: user.twilio_token,
    phone: user.twilio_phone || '',
    wa:    user.twilio_wa    || '',
  }

  // Send
  try {
    const result = await send(channel, lead.phone, body, creds)
    await query(`UPDATE messages SET status='sent', delivery_status='sent', twilio_sid=$1 WHERE id=$2`, [result.sid, msg.id])
    await query(`UPDATE leads SET current_step=$1, total_sent=total_sent+1 WHERE id=$2`, [stepNum, lead.id])
    console.log(`[Sequence] Step ${stepNum} sent via ${channel} to ${lead.name} — SID: ${result.sid}`)
  } catch (err) {
    await query(`UPDATE messages SET status='failed', delivery_status='failed', error_message=$1 WHERE id=$2`, [err.message, msg.id])
    await query(`UPDATE leads SET current_step=$1 WHERE id=$2`, [stepNum, lead.id])
    console.error(`[Sequence] Step ${stepNum} FAILED for ${lead.name}:`, err.message)
  }

  // Update lead step and schedule next
  const updatedLead = await getOne('SELECT * FROM leads WHERE id=$1', [lead.id])
  await scheduleNext({ ...lead, currentStep: stepNum, current_step: stepNum }, user, stepNum)

  return msg
}

async function scheduleNext(lead, user, currentStep) {
  const nextNum = currentStep + 1
  if (nextNum > 4) { await markCompleted(lead); return }

  const cfg     = user.sequence_config || {}
  const nextCfg = cfg['step' + nextNum]
  if (!nextCfg || !nextCfg.enabled) {
    await scheduleNext(lead, user, nextNum); return
  }

  const delay = nextCfg.delayDays || 0
  const next  = new Date()
  next.setDate(next.getDate() + delay)
  await query(`UPDATE leads SET next_follow_up_at=$1 WHERE id=$2`, [next.toISOString(), lead.id])
}

async function markCompleted(lead) {
  await query(`UPDATE leads SET status='completed', next_follow_up_at=NULL WHERE id=$1 AND status='active'`, [lead.id])
}

async function processScheduledFollowUps() {
  const due = await getMany(
    `SELECT * FROM leads WHERE status='active' AND next_follow_up_at <= NOW() AND current_step < 4`
  )
  console.log(`[Cron] ${due.length} lead(s) due`)
  let processed = 0, errors = 0
  for (const lead of due) {
    try {
      const l = {
        id: lead.id, _id: lead.id, userId: lead.user_id,
        name: lead.name, phone: lead.phone, context: lead.context,
        notes: lead.notes, channels: lead.channels,
        currentStep: lead.current_step, status: lead.status,
      }
      await triggerStep(l, lead.current_step + 1)
      processed++
    } catch (err) {
      console.error(`[Cron] Error lead ${lead.id}:`, err.message)
      errors++
    }
  }
  return { processed, errors }
}

module.exports = { triggerStep, processScheduledFollowUps }
