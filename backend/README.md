# ColdCloud API — Cloudflare Worker + D1

This directory contains the new ColdCloud backend. The legacy Express/Postgres/Mongo/Twilio backend has been removed.

## Architecture

Frontend → Cloudflare Worker → Cloudflare D1

WhatsApp, scheduling, AI and message delivery will be added as separate layers after the persistent core is verified.

## Files

- worker.js — API and authentication
- schema.sql — D1 schema
- wrangler.toml — Worker + D1 configuration
- package.json — Wrangler scripts

## Deploy

From backend/:

```bash
npm install
npx wrangler login
npx wrangler d1 execute coldcloud --remote --file=schema.sql
npx wrangler secret put JWT_SECRET
npx wrangler deploy
```

The D1 database configured in wrangler.toml is the existing ColdCloud database.

## Current API

GET /api/health
POST /api/auth/signup
POST /api/auth/login
GET /api/me
GET /api/business
PUT /api/business
GET /api/leads
POST /api/leads
GET /api/leads/:id
PATCH /api/leads/:id
DELETE /api/leads/:id
GET /api/sequences
POST /api/sequences
GET /api/automations
POST /api/automations
GET /api/activity

Authenticated routes use Authorization: Bearer <token>.
