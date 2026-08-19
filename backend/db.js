// ─────────────────────────────────────────────────────────────
// Supabase / PostgreSQL connection using pg Pool
// ─────────────────────────────────────────────────────────────
const { Pool } = require('pg')

let pool = null

function getPool() {
  if (!pool) {
    const uri = process.env.DATABASE_URL
    if (!uri) {
      console.warn('[DB] ⚠️  DATABASE_URL not set — running without database')
      return null
    }
    pool = new Pool({
      connectionString: uri,
      ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    })
    pool.on('error', (err) => console.error('[DB] Pool error:', err.message))
  }
  return pool
}

async function query(sql, params = []) {
  const p = getPool()
  if (!p) throw new Error('Database not connected')
  const client = await p.connect()
  try {
    const result = await client.query(sql, params)
    return result
  } finally {
    client.release()
  }
}

async function getOne(sql, params = []) {
  const r = await query(sql, params)
  return r.rows[0] || null
}

async function getMany(sql, params = []) {
  const r = await query(sql, params)
  return r.rows
}

async function isConnected() {
  try {
    await query('SELECT 1')
    return true
  } catch {
    return false
  }
}

module.exports = { query, getOne, getMany, isConnected, getPool }
