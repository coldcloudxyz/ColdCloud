const mongoose = require('mongoose')

// ─── User ───────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name:     { type: String, required: true, trim: true },
  company:  { type: String, trim: true },
  bizDesc:      { type: String, trim: true },
  senderName:   { type: String, trim: true },
  senderPhone:  { type: String, trim: true },
  senderEmail:  { type: String, trim: true },
  signOff:      { type: String, trim: true },
  // Twilio credentials — stored per user so each user sends from their own number
  twilioSid:    { type: String, trim: true },
  twilioToken:  { type: String, select: false }, // excluded from normal queries for security
  twilioPhone:  { type: String, trim: true },
  twilioWa:     { type: String, trim: true },
  customMessages: { type: String, default: '{}' }, // JSON string of per-step custom messages
  twilioMode:   { type: String, enum: ['shared', 'own'], default: 'shared' },
  sequenceConfig: {
    step1: { enabled: { type: Boolean, default: true }, delayDays: { type: Number, default: 0  }, channel: { type: String, default: 'whatsapp' } },
    step2: { enabled: { type: Boolean, default: true }, delayDays: { type: Number, default: 3  }, channel: { type: String, default: 'sms'      } },
    step3: { enabled: { type: Boolean, default: true }, delayDays: { type: Number, default: 5  }, channel: { type: String, default: 'call'     } },
    step4: { enabled: { type: Boolean, default: true }, delayDays: { type: Number, default: 7  }, channel: { type: String, default: 'whatsapp' } },
  },
}, { timestamps: true })

// ─── Lead ───────────────────────────────────────────────────
const LeadSchema = new mongoose.Schema({
  userId:          { type: mongoose.Types.ObjectId, ref: 'User', required: true, index: true },
  name:            { type: String, required: true, trim: true },
  phone:           { type: String, required: true, trim: true },
  context:         { type: String, required: true },
  notes:           { type: String, default: '' },
  business:        { type: String, default: '' },
  channels:        { type: [String], enum: ['whatsapp','sms','call'], default: ['whatsapp','sms','call'] },
  status:          { type: String, enum: ['active','replied','converted','completed','unsubscribed'], default: 'active', index: true },
  currentStep:     { type: Number, default: 0 },
  nextFollowUpAt:  { type: Date, index: true },
  totalSent:       { type: Number, default: 0 },
  repliedAt:       { type: Date },
  convertedAt:     { type: Date },
  optedOutAt:      { type: Date },
}, { timestamps: true })

LeadSchema.index({ userId: 1, status: 1 })
LeadSchema.index({ nextFollowUpAt: 1, status: 1 })

// ─── Message ─────────────────────────────────────────────────
const MessageSchema = new mongoose.Schema({
  userId:         { type: mongoose.Types.ObjectId, ref: 'User', required: true, index: true },
  leadId:         { type: mongoose.Types.ObjectId, ref: 'Lead', required: true, index: true },
  leadName:       { type: String, required: true },
  type:           { type: String, enum: ['whatsapp','sms','call','reply'], required: true },
  direction:      { type: String, enum: ['outbound','inbound'], required: true },
  body:           { type: String, required: true },
  status:         { type: String, enum: ['queued','sent','delivered','failed','received'], default: 'queued' },
  deliveryStatus: { type: String, default: 'queued' },
  twilioSid:      { type: String },
  step:           { type: Number, default: 0 },
  errorMessage:   { type: String },
}, { timestamps: true })

MessageSchema.index({ userId: 1, createdAt: -1 })
MessageSchema.index({ leadId:  1, createdAt: -1 })

module.exports = {
  User:    mongoose.models.User    || mongoose.model('User',    UserSchema),
  Lead:    mongoose.models.Lead    || mongoose.model('Lead',    LeadSchema),
  Message: mongoose.models.Message || mongoose.model('Message', MessageSchema),
}
