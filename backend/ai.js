'use strict'
const axios = require('axios')

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions'
const MODEL          = 'openrouter/free'

const STEP_TONE = {
  1: 'This is the very first contact. Be warm, human, zero pressure. Introduce yourself naturally. Never sound like a sales pitch.',
  2: 'They have not replied yet. Send a gentle, brief reminder. Stay friendly. One soft nudge, nothing more.',
  3: 'Still no reply. Create real urgency — limited time, limited availability. Be assertive but never pushy or rude.',
  4: 'This is the absolute last message. Be honest about it. No guilt trips. Give them a clear easy way to respond or opt out. Warm, respectful sign-off.',
}

const CHANNEL_RULES = {
  whatsapp: {
    label:       'WhatsApp message',
    instruction: 'Write like a real person texting on WhatsApp. Casual, warm, conversational. 1-2 emojis only if they feel 100% natural. Max 100 words. Short paragraphs or single lines. Never sound corporate.',
    constraint:  'Output must be under 100 words. No subject line. No labels. No quotes.',
  },
  sms: {
    label:       'SMS text message',
    instruction: 'Write an SMS. Hard limit: 160 characters total including spaces. Ultra short. One sentence if possible. Zero emojis. Plain text only. One clear action at the end.',
    constraint:  'Output MUST be under 160 characters. Count every character. No emojis. No labels.',
  },
  call: {
    label:       'voicemail script',
    instruction: 'Write a voicemail script spoken out loud by a real person. Natural speech rhythm. No emojis, no symbols, no bullet points, no punctuation that sounds odd spoken. Max 55 words. Sound like a real human, not a robot.',
    constraint:  'Output must be under 55 words. Written to be spoken aloud. No labels or headers.',
  },
}

const OPENERS = [
  'Start with a question.',
  'Jump straight to the point, no fluff.',
  'Open by referencing what you know about their situation.',
  'Lead with something you can offer them specifically.',
  'Acknowledge their likely busy schedule first.',
  'Open with the lead name and make it feel personal.',
  'Use a very short punchy first sentence.',
  'Sound like you genuinely remembered this person.',
  'Start mid-thought, like continuing a real conversation.',
  'Express genuine curiosity about their situation.',
]

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)] }
function uid()     { return Math.random().toString(36).slice(2, 8) }

async function callAI(systemPrompt, userPrompt, temperature) {
  const response = await axios.post(
    OPENROUTER_URL,
    {
      model:       MODEL,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: userPrompt   },
      ],
      max_tokens:  400,
      temperature,
      top_p:       0.95,
      presence_penalty:  0.6,
      frequency_penalty: 0.6,
    },
    {
      headers: {
        'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
        'Content-Type':  'application/json',
        'HTTP-Referer':  process.env.FRONTEND_URL || 'https://coldcloud.io',
        'X-Title':       'ColdCloud',
      },
      timeout: 25000,
    }
  )
  return response.data?.choices?.[0]?.message?.content?.trim() || ''
}

async function generateMessage({ leadName, context, notes, step, channel, bizName, bizDesc, senderName, senderPhone, signOff }) {
  const apiKey    = process.env.OPENROUTER_API_KEY
  const firstName = (leadName || 'there').split(' ')[0]
  const sender    = senderName || bizName || 'the team'
  const intro     = (signOff || sender) + (bizName ? ' from ' + bizName : '')
  const cbNote    = senderPhone ? `They can reach you at ${senderPhone}.` : ''
  const ch        = CHANNEL_RULES[channel] || CHANNEL_RULES.sms
  const tone      = STEP_TONE[step]        || STEP_TONE[1]
  const opener    = pick(OPENERS)
  const seed      = uid()

  if (!apiKey) {
    console.error('[AI] OPENROUTER_API_KEY is not set — cannot generate message')
    throw new Error('AI not configured: OPENROUTER_API_KEY missing')
  }

  const systemPrompt = `You are a world-class sales copywriter specialising in follow-up outreach.
You write ${ch.label} messages that feel 100% human, never templated or robotic.
${ch.instruction}
STRICT OUTPUT RULES:
- Return ONLY the message text itself
- No explanations, no labels, no subject lines, no quotes around the message
- Every single message you write must be UNIQUE and DIFFERENT from anything you have written before
- ${ch.constraint}`

  const userPrompt = `Write a unique ${ch.label} follow-up message. Request ID: ${seed}

LEAD: ${firstName}
STEP: ${step} of 4
TONE GOAL: ${tone}
SENDER: ${intro}
${bizDesc   ? `BUSINESS: ${bizDesc}`              : ''}
CONTEXT: ${context}
${notes     ? `NOTES: ${notes}`                    : ''}
${cbNote    ? `CALLBACK: ${cbNote}`                : ''}

STYLE DIRECTION FOR THIS SPECIFIC MESSAGE: ${opener}

Sign off naturally as "${sender}".
This message must be completely different from any other follow-up message.
${ch.constraint}
Output the message now:`

  // Try up to 2 times with increasing temperature for variation
  const temperatures = [0.9, 1.1]
  for (let attempt = 0; attempt < temperatures.length; attempt++) {
    try {
      const text = await callAI(systemPrompt, userPrompt, temperatures[attempt])
      if (text && text.length > 10) {
        console.log(`[AI] ✓ ${channel} step ${step} for ${firstName} — attempt ${attempt + 1} (${text.length} chars)`)
        return text
      }
      console.warn(`[AI] Empty response on attempt ${attempt + 1}, retrying...`)
    } catch (err) {
      const status = err.response?.status
      const detail = err.response?.data?.error?.message || err.message
      console.error(`[AI] OpenRouter error attempt ${attempt + 1} (${status || 'network'}): ${detail}`)
      if (attempt === temperatures.length - 1) throw new Error(`AI generation failed: ${detail}`)
    }
  }

  throw new Error('AI generation failed after all attempts')
}

module.exports = { generateMessage }
