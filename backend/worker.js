const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "Content-Type, Authorization",
  "access-control-allow-methods": "GET,POST,PATCH,PUT,DELETE,OPTIONS"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...CORS }
  });

const uid = () => crypto.randomUUID();
const now = () => new Date().toISOString();

async function read(req) {
  try { return await req.json(); } catch { return {}; }
}

function b64u(s) {
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function unb64(s) {
  return atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
}

async function jwt(payload, secret) {
  const h = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64u(JSON.stringify(payload));
  const data = h + "." + p;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );
  return data + "." + b64u(String.fromCharCode(...new Uint8Array(sig)));
}

async function userFrom(req, env) {
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer /, "");
  if (!token || !env.JWT_SECRET) return null;

  try {
    const [h, p, s] = token.split(".");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const ok = await crypto.subtle.verify(
      "HMAC",
      key,
      Uint8Array.from(unb64(s), c => c.charCodeAt(0)),
      new TextEncoder().encode(h + "." + p)
    );
    const payload = JSON.parse(unb64(p));
    return ok && payload.exp > Date.now() / 1000 ? payload : null;
  } catch {
    return null;
  }
}

async function passwordHash(password, saltBytes = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 120000, hash: "SHA-256" },
    key,
    256
  );
  return {
    salt: btoa(String.fromCharCode(...saltBytes)),
    hash: btoa(String.fromCharCode(...new Uint8Array(bits)))
  };
}

async function passwordVerify(password, salt, expectedHash) {
  try {
    const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
    const result = await passwordHash(password, saltBytes);
    return result.hash === expectedHash;
  } catch {
    return false;
  }
}

async function tableColumns(env, table) {
  const rows = (await env.DB.prepare("PRAGMA table_info(" + table + ")").all()).results || [];
  return new Set(rows.map(r => r.name));
}

async function tableExists(env, table) {
  const row = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
  ).bind(table).first();
  return !!row;
}

async function firstExistingTable(env, names) {
  for (const name of names) {
    if (await tableExists(env, name)) return name;
  }
  return null;
}

function pickValue(input, aliases) {
  for (const key of aliases) {
    if (input[key] !== undefined && input[key] !== null) return input[key];
  }
  return undefined;
}

async function insertDynamic(env, table, data) {
  const cols = await tableColumns(env, table);
  const entries = Object.entries(data).filter(([k, v]) => cols.has(k) && v !== undefined);
  if (!entries.length) throw new Error("No compatible columns for " + table);

  const names = entries.map(([k]) => k);
  const placeholders = names.map(() => "?").join(",");
  const values = entries.map(([, v]) => v);
  const sql = "INSERT INTO " + table + " (" + names.join(",") + ") VALUES (" + placeholders + ")";
  await env.DB.prepare(sql).bind(...values).run();
}

async function updateDynamic(env, table, data, whereSql, whereValues) {
  const cols = await tableColumns(env, table);
  const entries = Object.entries(data).filter(([k, v]) => cols.has(k) && v !== undefined);
  if (!entries.length) return;
  const sets = entries.map(([k]) => k + "=?").join(",");
  await env.DB.prepare(
    "UPDATE " + table + " SET " + sets + " WHERE " + whereSql
  ).bind(...entries.map(([, v]) => v), ...whereValues).run();
}

async function ensureWorkspace(env, userId) {
  const existing = await env.DB.prepare(
    "SELECT * FROM workspaces WHERE owner_user_id=? ORDER BY created_at LIMIT 1"
  ).bind(userId).first();

  if (existing) return existing;

  const workspace = {
    id: uid(),
    owner_user_id: userId,
    name: "My Workspace",
    created_at: now(),
    updated_at: now()
  };
  await insertDynamic(env, "workspaces", workspace);
  return await env.DB.prepare("SELECT * FROM workspaces WHERE id=?").bind(workspace.id).first();
}

function leadOut(row) {
  if (!row) return null;
  const fullName = row.name || "";
  const parts = fullName.trim().split(/\s+/);
  return {
    id: row.id,
    _id: row.id,
    workspaceId: row.workspace_id,
    name: row.name || "",
    firstName: parts[0] || "",
    lastName: parts.slice(1).join(" "),
    company: row.company || "",
    title: row.title || "",
    businessType: row.business_type || "",
    email: row.email || "",
    phone: row.phone || "",
    website: row.website || "",
    industry: row.industry || "",
    location: row.location || "",
    source: row.source || "",
    interest: row.interest || "",
    notes: row.notes || "",
    status: row.status || "new",
    whatsappOptIn: !!row.whatsapp_opt_in,
    whatsappOptOut: !!row.whatsapp_opt_out,
    lastInboundAt: row.last_inbound_at || null,
    sequencePaused: !!row.sequence_paused,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

async function getWorkspaceLead(env, workspaceId, leadId) {
  return await env.DB.prepare(
    "SELECT * FROM leads WHERE id=? AND workspace_id=?"
  ).bind(leadId, workspaceId).first();
}

async function logActivity(env, workspaceId, leadId, text) {
  if (!(await tableExists(env, "activities"))) return;
  const cols = await tableColumns(env, "activities");
  const data = {
    id: uid(),
    workspace_id: workspaceId,
    lead_id: leadId,
    text,
    message: text,
    type: "system",
    created_at: now(),
    updated_at: now()
  };
  const entries = Object.entries(data).filter(([k, v]) => cols.has(k) && v !== undefined);
  if (!entries.length) return;
  await insertDynamic(env, "activities", Object.fromEntries(entries));
}

async function ensureBuiltInSequence(env, workspaceId) {
  if (!(await tableExists(env, "sequences"))) return null;

  const cols = await tableColumns(env, "sequences");
  let sequence = await env.DB.prepare(
    "SELECT * FROM sequences WHERE workspace_id=? ORDER BY created_at LIMIT 1"
  ).bind(workspaceId).first();

  if (!sequence) {
    const data = {
      id: uid(),
      workspace_id: workspaceId,
      name: "Cold Lead Recovery",
      is_builtin: 1,
      enabled: 1,
      status: "active",
      created_at: now(),
      updated_at: now()
    };
    await insertDynamic(env, "sequences", data);
    sequence = await env.DB.prepare("SELECT * FROM sequences WHERE id=?").bind(data.id).first();
  }

  return sequence;
}

async function getWorkspaceSequence(env, workspaceId, sequenceId) {
  if (!sequenceId || !(await tableExists(env, "sequences"))) return null;
  return await env.DB.prepare(
    "SELECT * FROM sequences WHERE id=? AND workspace_id=? LIMIT 1"
  ).bind(sequenceId, workspaceId).first();
}

async function ensureDefaults(env, workspaceId) {
  await ensureBuiltInSequence(env, workspaceId);

  if (await tableExists(env, "automations")) {
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM automations WHERE workspace_id=?"
    ).bind(workspaceId).first();

    if (!Number(count?.n || 0)) {
      const defaults = [
        ["New Lead → Start Sequence", "New lead added", "Start sequence"],
        ["Lead Replies → Pause Sequence", "Lead replies on WhatsApp", "Pause sequence"],
        ["No Reply → Continue Sequence", "Lead does not reply", "Continue sequence"],
        ["Opt-out → Stop Automation", "Lead says stop / opts out", "Stop all follow-ups"],
        ["Interested Lead → Mark Hot", "Lead shows positive intent", "Mark lead as hot"]
      ];

      for (const [name, trigger, action] of defaults) {
        await insertDynamic(env, "automations", {
          id: uid(),
          workspace_id: workspaceId,
          name,
          trigger_text: trigger,
          action_text: action,
          trigger,
          action,
          enabled: 1,
          is_builtin: 1,
          created_at: now(),
          updated_at: now()
        });
      }
    }
  }
}

async function businessTable(env) {
  return await firstExistingTable(env, [
    "business_profiles",
    "business_information",
    "workspace_business_profiles"
  ]);
}

async function sequenceOutput(env, sequence) {
  if (!sequence) return null;
  const result = { ...sequence, steps: [] };

  const stepTable = await firstExistingTable(env, [
    "sequence_steps",
    "lead_sequence_steps"
  ]);

  if (stepTable) {
    const cols = await tableColumns(env, stepTable);
    if (cols.has("sequence_id")) {
      result.steps = (await env.DB.prepare(
        "SELECT * FROM " + stepTable + " WHERE sequence_id=? ORDER BY " +
        (cols.has("position") ? "position" : "created_at")
      ).bind(sequence.id).all()).results || [];
    }
  }

  return result;
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      const url = new URL(req.url);
      const path = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);

      if (path.join("/") === "health") {
        const dbOk = !!(await env.DB.prepare("SELECT 1 AS ok").first());
        return json({ ok: true, service: "coldcloud-api", database: dbOk });
      }

      if (path[0] === "auth" && path[1] === "signup" && req.method === "POST") {
        const body = await read(req);
        const email = String(body.email || "").trim().toLowerCase();
        const name = String(body.name || "").trim();
        const password = String(body.password || "");

        if (!name || !email || password.length < 8) {
          return json({ ok: false, error: "Name, email and 8+ character password are required" }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE email=?"
        ).bind(email).first();

        if (existing) return json({ ok: false, error: "Email already exists" }, 409);

        const pw = await passwordHash(password);
        const userId = uid();

        await insertDynamic(env, "users", {
          id: userId,
          email,
          password_hash: pw.hash,
          password_salt: pw.salt,
          name,
          created_at: now(),
          updated_at: now()
        });

        const workspace = await ensureWorkspace(env, userId);
        await ensureDefaults(env, workspace.id);

        const token = await jwt(
          { sub: userId, email, exp: Date.now() / 1000 + 604800 },
          env.JWT_SECRET
        );

        return json({
          ok: true,
          token,
          user: { id: userId, email, name },
          workspace
        }, 201);
      }

      if (path[0] === "auth" && path[1] === "login" && req.method === "POST") {
        const body = await read(req);
        const email = String(body.email || "").trim().toLowerCase();
        const user = await env.DB.prepare(
          "SELECT * FROM users WHERE email=?"
        ).bind(email).first();

        if (!user) return json({ ok: false, error: "Incorrect email or password" }, 401);

        const valid = user.password_salt
          ? await passwordVerify(body.password || "", user.password_salt, user.password_hash)
          : false;

        if (!valid) return json({ ok: false, error: "Incorrect email or password" }, 401);

        const workspace = await ensureWorkspace(env, user.id);
        await ensureDefaults(env, workspace.id);

        const token = await jwt(
          { sub: user.id, email: user.email, exp: Date.now() / 1000 + 604800 },
          env.JWT_SECRET
        );

        return json({
          ok: true,
          token,
          user: { id: user.id, email: user.email, name: user.name },
          workspace
        });
      }

      const authUser = await userFrom(req, env);
      if (!authUser) return json({ ok: false, error: "Unauthorized" }, 401);

      const workspace = await ensureWorkspace(env, authUser.sub);
      await ensureDefaults(env, workspace.id);

      if (path[0] === "me" || (path[0] === "auth" && path[1] === "me")) {
        const user = await env.DB.prepare(
          "SELECT id,email,name,created_at,updated_at FROM users WHERE id=?"
        ).bind(authUser.sub).first();
        return json({ ok: true, user, workspace });
      }

      if (path[0] === "business") {
        const table = await businessTable(env);
        if (!table) return json({ ok: true, businessInfo: null });

        if (req.method === "GET") {
          const cols = await tableColumns(env, table);
          const ownerCol = cols.has("workspace_id") ? "workspace_id" : "user_id";
          const row = await env.DB.prepare(
            "SELECT * FROM " + table + " WHERE " + ownerCol + "=? LIMIT 1"
          ).bind(ownerCol === "workspace_id" ? workspace.id : authUser.sub).first();

          return json({ ok: true, businessInfo: row || null });
        }

        if (req.method === "PUT") {
          const body = await read(req);
          const cols = await tableColumns(env, table);
          const ownerCol = cols.has("workspace_id") ? "workspace_id" : "user_id";
          const ownerId = ownerCol === "workspace_id" ? workspace.id : authUser.sub;
          const existing = await env.DB.prepare(
            "SELECT * FROM " + table + " WHERE " + ownerCol + "=? LIMIT 1"
          ).bind(ownerId).first();

          const data = { ...body, [ownerCol]: ownerId, updated_at: now() };

          if (existing) {
            await updateDynamic(env, table, data, ownerCol + "=?", [ownerId]);
          } else {
            data.id = uid();
            data.created_at = now();
            await insertDynamic(env, table, data);
          }

          return json({ ok: true });
        }
      }

      if (path[0] === "leads" && req.method === "GET" && !path[1]) {
        const rows = (await env.DB.prepare(
          "SELECT * FROM leads WHERE workspace_id=? ORDER BY created_at DESC"
        ).bind(workspace.id).all()).results || [];

        return json({ ok: true, leads: rows.map(leadOut) });
      }

      if (path[0] === "leads" && req.method === "POST") {
        const body = await read(req);
        const firstName = String(
          pickValue(body, ["firstName", "first_name", "name"]) || ""
        ).trim();
        const lastName = String(pickValue(body, ["lastName", "last_name"]) || "").trim();
        const phone = String(body.phone || "").replace(/[\s\-()]/g, "");
        const email = String(body.email || "").trim();

        if (!firstName || !/^[+0-9]{7,15}$/.test(phone)) {
          return json({ ok: false, error: "First name and valid phone are required" }, 400);
        }

        const duplicate = await env.DB.prepare(
          "SELECT id FROM leads WHERE workspace_id=? AND phone=? LIMIT 1"
        ).bind(workspace.id, phone).first();

        if (duplicate) return json({ ok: false, error: "Lead already exists" }, 409);

        const sequence = await ensureBuiltInSequence(env, workspace.id);

        const leadId = uid();
        const lead = {
          id: leadId,
          workspace_id: workspace.id,
          name: [firstName, lastName].filter(Boolean).join(" "),
          company: body.company || "",
          title: body.title || "",
          business_type: body.businessType || body.business_type || "",
          email,
          phone,
          website: body.website || "",
          industry: body.industry || "",
          location: body.location || "",
          source: body.source || "",
          interest: body.interest || "",
          notes: body.notes || "",
          status: "new",
          whatsapp_opt_in: body.whatsappOptIn ? 1 : 0,
          whatsapp_opt_in_at: body.whatsappOptIn ? now() : null,
          whatsapp_opt_in_source: body.whatsappOptInSource || null,
          whatsapp_opt_out: 0,
          sequence_paused: 0,
          created_at: now(),
          updated_at: now()
        };

        await insertDynamic(env, "leads", lead);
        await logActivity(env, workspace.id, leadId, "Lead added: " + lead.name);

        return json({ ok: true, lead: leadOut(await getWorkspaceLead(env, workspace.id, leadId)) }, 201);
      }

      if (path[0] === "leads" && path[1] && req.method === "GET") {
        const lead = await getWorkspaceLead(env, workspace.id, path[1]);
        return lead
          ? json({ ok: true, lead: leadOut(lead) })
          : json({ ok: false, error: "Lead not found" }, 404);
      }

      if (path[0] === "leads" && path[1] && req.method === "PATCH") {
        const existing = await getWorkspaceLead(env, workspace.id, path[1]);
        if (!existing) return json({ ok: false, error: "Lead not found" }, 404);

        const body = await read(req);
        const firstName = body.firstName ?? body.first_name;
        const lastName = body.lastName ?? body.last_name;

        const data = {
          name: firstName !== undefined
            ? [String(firstName).trim(), String(lastName || "").trim()].filter(Boolean).join(" ")
            : undefined,
          company: body.company,
          title: body.title,
          business_type: body.businessType ?? body.business_type,
          email: body.email,
          phone: body.phone ? String(body.phone).replace(/[\s\-()]/g, "") : undefined,
          website: body.website,
          industry: body.industry,
          location: body.location,
          source: body.source,
          interest: body.interest,
          notes: body.notes,
          status: body.status,
          whatsapp_opt_in: body.whatsappOptIn === undefined ? undefined : (body.whatsappOptIn ? 1 : 0),
          whatsapp_opt_in_at: body.whatsappOptIn ? (existing.whatsapp_opt_in_at || now()) : undefined,
          whatsapp_opt_in_source: body.whatsappOptInSource,
          whatsapp_opt_out: body.whatsappOptOut === undefined ? undefined : (body.whatsappOptOut ? 1 : 0),
          sequence_paused: body.sequencePaused === undefined ? undefined : (body.sequencePaused ? 1 : 0),
          updated_at: now()
        };

        await updateDynamic(env, "leads", data, "id=? AND workspace_id=?", [path[1], workspace.id]);
        await logActivity(env, workspace.id, path[1], "Lead updated");

        return json({
          ok: true,
          lead: leadOut(await getWorkspaceLead(env, workspace.id, path[1]))
        });
      }

      if (path[0] === "leads" && path[1] && req.method === "DELETE") {
        const existing = await getWorkspaceLead(env, workspace.id, path[1]);
        if (!existing) return json({ ok: false, error: "Lead not found" }, 404);

        await env.DB.prepare(
          "DELETE FROM leads WHERE id=? AND workspace_id=?"
        ).bind(path[1], workspace.id).run();

        return json({ ok: true });
      }

      if (path[0] === "sequences" && req.method === "GET") {
        if (!(await tableExists(env, "sequences"))) return json({ ok: true, sequences: [] });

        const rows = (await env.DB.prepare(
          "SELECT * FROM sequences WHERE workspace_id=? ORDER BY created_at"
        ).bind(workspace.id).all()).results || [];

        const sequences = [];
        for (const row of rows) sequences.push(await sequenceOutput(env, row));
        return json({ ok: true, sequences });
      }

      if (path[0] === "sequences" && req.method === "POST") {
        if (!(await tableExists(env, "sequences"))) {
          return json({ ok: false, error: "Sequences table is unavailable" }, 500);
        }

        const body = await read(req);
        const sequenceId = uid();
        await insertDynamic(env, "sequences", {
          id: sequenceId,
          workspace_id: workspace.id,
          name: String(body.name || "New Sequence").trim(),
          is_builtin: 0,
          enabled: 1,
          status: "active",
          created_at: now(),
          updated_at: now()
        });

        const stepTable = await firstExistingTable(env, ["sequence_steps", "lead_sequence_steps"]);
        if (stepTable && Array.isArray(body.steps)) {
          const cols = await tableColumns(env, stepTable);
          for (let i = 0; i < body.steps.length; i++) {
            const step = body.steps[i] || {};
            const data = {
              id: uid(),
              sequence_id: sequenceId,
              position: i + 1,
              day: Number(step.day) || 0,
              delay_days: Number(step.day) || 0,
              channel: "WhatsApp",
              enabled: step.enabled === false ? 0 : 1,
              ai_instructions: step.aiInstructions || "",
              created_at: now(),
              updated_at: now()
            };
            if (cols.has("step_order")) data.step_order = i + 1;
            await insertDynamic(env, stepTable, data);
          }
        }

        return json({ ok: true, id: sequenceId }, 201);
      }

      if (path[0] === "sequences" && path[1] && req.method === "PATCH") {
        if (!(await tableExists(env, "sequences"))) return json({ ok: false, error: "Sequences table is unavailable" }, 500);
        const existing = await getWorkspaceSequence(env, workspace.id, path[1]);
        if (!existing) return json({ ok: false, error: "Sequence not found" }, 404);

        const body = await read(req);
        const data = {
          name: body.name,
          enabled: body.active === undefined ? undefined : (body.active ? 1 : 0),
          status: body.active === undefined ? undefined : (body.active ? "active" : "disabled"),
          updated_at: now()
        };
        await updateDynamic(env, "sequences", data, "id=? AND workspace_id=?", [path[1], workspace.id]);

        const stepTable = await firstExistingTable(env, ["sequence_steps", "lead_sequence_steps"]);
        if (stepTable && Array.isArray(body.steps)) {
          const cols = await tableColumns(env, stepTable);
          if (cols.has("sequence_id")) {
            await env.DB.prepare("DELETE FROM " + stepTable + " WHERE sequence_id=?").bind(path[1]).run();
            for (let i = 0; i < body.steps.length; i++) {
              const step = body.steps[i] || {};
              await insertDynamic(env, stepTable, {
                id: uid(),
                sequence_id: path[1],
                position: i + 1,
                step_order: i + 1,
                day: Number(step.day) || 0,
                delay_days: Number(step.day) || 0,
                channel: "WhatsApp",
                enabled: step.enabled === false ? 0 : 1,
                ai_instructions: step.aiInstructions || "",
                template_id: step.templateId || "",
                created_at: now(),
                updated_at: now()
              });
            }
          }
        }
        return json({ ok: true, sequence: await sequenceOutput(env, await getWorkspaceSequence(env, workspace.id, path[1])) });
      }

      if (path[0] === "sequences" && path[1] && req.method === "DELETE") {
        const existing = await getWorkspaceSequence(env, workspace.id, path[1]);
        if (!existing) return json({ ok: false, error: "Sequence not found" }, 404);
        if (existing.is_builtin) return json({ ok: false, error: "Built-in sequence cannot be deleted" }, 400);

        await env.DB.prepare("DELETE FROM sequences WHERE id=? AND workspace_id=?").bind(path[1], workspace.id).run();
        return json({ ok: true });
      }

      if (path[0] === "automations" && req.method === "GET") {
        if (!(await tableExists(env, "automations"))) return json({ ok: true, automations: [] });

        const rows = (await env.DB.prepare(
          "SELECT * FROM automations WHERE workspace_id=? ORDER BY created_at"
        ).bind(workspace.id).all()).results || [];

        return json({ ok: true, automations: rows });
      }

      if (path[0] === "automations" && req.method === "POST") {
        if (!(await tableExists(env, "automations"))) {
          return json({ ok: false, error: "Automations table is unavailable" }, 500);
        }

        const body = await read(req);
        const sequenceId = body.sequenceId || null;

        // Never accept a sequence from another workspace.
        if (sequenceId && !(await getWorkspaceSequence(env, workspace.id, sequenceId))) {
          return json({ ok: false, error: "Sequence not found in this workspace" }, 404);
        }

        const id = uid();
        await insertDynamic(env, "automations", {
          id,
          workspace_id: workspace.id,
          name: body.name || "New Automation",
          trigger_text: body.trigger || body.triggerText || "",
          action_text: body.action || body.actionText || "",
          trigger: body.trigger || "",
          action: body.action || "",
          sequence_id: sequenceId,
          enabled: body.enabled === false ? 0 : 1,
          is_builtin: 0,
          created_at: now(),
          updated_at: now()
        });

        return json({ ok: true, id }, 201);
      }

      if (path[0] === "activity" && req.method === "GET") {
        if (!(await tableExists(env, "activities"))) return json({ ok: true, activities: [] });

        const cols = await tableColumns(env, "activities");
        const ownerCol = cols.has("workspace_id") ? "workspace_id" : null;

        if (!ownerCol) return json({ ok: true, activities: [] });

        const rows = (await env.DB.prepare(
          "SELECT * FROM activities WHERE workspace_id=? ORDER BY created_at DESC LIMIT 200"
        ).bind(workspace.id).all()).results || [];

        return json({ ok: true, activities: rows });
      }

      return json({ ok: false, error: "Not found" }, 404);
    } catch (error) {
      console.error("ColdCloud Worker error:", error);
      return json({ ok: false, error: "Server error" }, 500);
    }
  }
};
