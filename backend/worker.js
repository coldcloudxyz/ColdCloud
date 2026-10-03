const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "Content-Type, Authorization, X-Dev-Key",
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
    { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return {
    salt: btoa(String.fromCharCode(...saltBytes)),
    hash: btoa(String.fromCharCode(...new Uint8Array(bits)))
  };
}

async function encryptSecret(value, secret) {
  const keyBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(secret || "")));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(String(value))
  );
  const enc = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return enc(iv) + "." + enc(ciphertext);
}

async function decryptSecret(value, secret) {
  const [ivB64, dataB64] = String(value || "").split(".");
  if (!ivB64 || !dataB64) throw new Error("Invalid encrypted secret");
  const dec = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const keyBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(secret || "")));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: dec(ivB64) }, key, dec(dataB64));
  return new TextDecoder().decode(plain);
}

async function verifyGoogleIdToken(idToken, env) {
  const parts=String(idToken||"").split(".");
  if(parts.length!==3) throw new Error("Invalid Google credential");
  let header,payload;
  try{header=JSON.parse(unb64(parts[0]));payload=JSON.parse(unb64(parts[1]));}catch{throw new Error("Invalid Google credential");}
  const issuer=String(payload.iss||"");
  const audience=String(payload.aud||"");
  const clientId=String(env.GOOGLE_CLIENT_ID||"");
  if(!clientId) throw new Error("Google Sign-In is not configured on ColdCloud");
  if(!["https://accounts.google.com","accounts.google.com"].includes(issuer)) throw new Error("Invalid Google issuer");
  if(audience!==clientId) throw new Error("Invalid Google audience");
  if(payload.email_verified!==true) throw new Error("Google email is not verified");
  if(!payload.sub||!payload.email) throw new Error("Google account information is incomplete");
  const exp=Number(payload.exp||0), nowSec=Math.floor(Date.now()/1000);
  if(!exp||exp<nowSec) throw new Error("Google credential has expired");
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),8000);
  let jwksRes;
  try{
    jwksRes=await fetch("https://www.googleapis.com/oauth2/v3/certs",{signal:controller.signal});
  }catch(err){
    throw new Error(err?.name==="AbortError"?"Google signing-key request timed out":"Could not reach Google signing keys");
  }finally{
    clearTimeout(timer);
  }
  if(!jwksRes.ok) throw new Error("Could not load Google signing keys");
  const jwks=await jwksRes.json();
  const jwk=(jwks.keys||[]).find(k=>k.kid===header.kid);
  if(!jwk) throw new Error("Google signing key not found");
  const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
  const signature=Uint8Array.from(unb64(parts[2]),c=>c.charCodeAt(0));
  const valid=await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,signature,new TextEncoder().encode(parts[0]+"."+parts[1]));
  if(!valid) throw new Error("Invalid Google credential signature");
  return payload;
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
    sequenceId: row.sequence_id || "",
    sequenceProgress: Number(row.sequence_progress || 0),
    sequencePlan: row.sequence_plan ? (()=>{try{return JSON.parse(row.sequence_plan)}catch{return []}})() : [],
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
  try {
    await insertDynamic(env, "activities", Object.fromEntries(entries));
  } catch (err) {
    console.warn("Activity logging skipped:", err?.message || err);
  }
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

      const automationCols = await tableColumns(env, "automations");
      for (const [name, trigger, action] of defaults) {
        const data = {
          id: uid(),
          workspace_id: workspaceId,
          name,
          trigger_text: trigger,
          action_text: action,
          trigger,
          action,
          trigger_type: trigger,
          action_type: action,
          config_json: JSON.stringify({ trigger, action }),
          enabled: 1,
          active: 1,
          is_builtin: 1,
          created_at: now(),
          updated_at: now()
        };

        // The current D1 schema uses trigger_type/action_type/active,
        // while older builds used trigger/action/enabled. insertDynamic
        // keeps only columns that actually exist.
        await insertDynamic(env, "automations", data);
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

async function getBusinessInfoForWorkspace(env, workspaceId, userId) {
  const table = await businessTable(env);
  if (!table) return {};
  const cols = await tableColumns(env, table);
  const ownerCol = cols.has("workspace_id") ? "workspace_id" : "user_id";
  return await env.DB.prepare("SELECT * FROM " + table + " WHERE " + ownerCol + "=? LIMIT 1")
    .bind(ownerCol === "workspace_id" ? workspaceId : userId).first() || {};
}

const REQUIRED_BUSINESS_FIELDS = ["name","type","description","offer","target","market","problem","difference","goal","tone","rules"];

function missingBusinessFields(info) {
  return REQUIRED_BUSINESS_FIELDS.filter(k => !String(info?.[k] || "").trim());
}

async function requireBusinessInfo(env, workspaceId, userId) {
  const info = await getBusinessInfoForWorkspace(env, workspaceId, userId);
  return { info, missing: missingBusinessFields(info) };
}

function recoveryWindowOpen(lead) {
  if (!lead?.last_inbound_at) return false;
  const t = Date.parse(lead.last_inbound_at);
  return Number.isFinite(t) && (Date.now() - t) >= 0 && (Date.now() - t) < 24 * 60 * 60 * 1000;
}

function parseLeadPlan(row) {
  if (!row?.sequence_plan) return [];
  try { const plan = JSON.parse(row.sequence_plan); return Array.isArray(plan) ? plan : []; } catch { return []; }
}

async function generateAutomaticReply(env, workspaceId, lead, businessInfo, step) {
  if (!env.OPENAI_API_KEY) throw new Error("AI is not configured");
  const messages = (await env.DB.prepare(
    "SELECT direction,body,created_at FROM messages WHERE workspace_id=? AND lead_id=? ORDER BY created_at DESC LIMIT 12"
  ).bind(workspaceId, lead.id).all()).results || [];
  const model = env.OPENAI_MODEL || "gpt-5.6-luna";
  const input = [
    "Write the next ColdCloud lead-recovery WhatsApp message.",
    "This is an automatic follow-up, not a chatbot greeting.",
    "Use only facts in the business and lead context. Never invent price, discount, result, guarantee, policy, credential, availability, or other business facts.",
    "Keep it concise, natural and human. No markdown. Do not mention that AI wrote it.",
    "If the lead has replied previously, use the conversation context. If there is no reply, make this a useful recovery follow-up rather than repeating the same message.",
    "Respect the business tone and rules.",
    step?.aiInstructions ? "STEP INSTRUCTIONS: " + String(step.aiInstructions) : "",
    "BUSINESS:", JSON.stringify({
      name:businessInfo.name || "", type:businessInfo.type || "", description:businessInfo.description || "",
      offer:businessInfo.offer || "", target:businessInfo.target || "", market:businessInfo.market || "",
      problem:businessInfo.problem || "", difference:businessInfo.difference || "", goal:businessInfo.goal || "",
      tone:businessInfo.tone || "", rules:businessInfo.rules || ""
    }),
    "LEAD:", JSON.stringify({
      name:lead.name || "", company:lead.company || "", interest:lead.interest || "",
      businessType:lead.business_type || "", source:lead.source || "", notes:lead.notes || ""
    }),
    "RECENT CONVERSATION:", JSON.stringify(messages.reverse())
  ].filter(Boolean).join("\n");

  const res = await fetch("https://api.openai.com/v1/responses", {
    method:"POST",
    headers:{"content-type":"application/json","authorization":"Bearer "+env.OPENAI_API_KEY},
    body:JSON.stringify({
      model,
      input:[
        {role:"system",content:"You are ColdCloud's automatic lead-recovery assistant. Produce one truthful WhatsApp message."},
        {role:"user",content:input}
      ],
      max_output_tokens:500,
      store:false
    })
  });
  const data=await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data?.error?.message || "AI reply failed");
  const text=String(data?.output_text || (data?.output||[]).flatMap(x=>x.content||[]).find(x=>x.type==="output_text")?.text || "").trim();
  if(!text) throw new Error("AI returned an empty message");
  return text;
}


function parseAIJson(data) {
  if (typeof data?.output_text === "string" && data.output_text.trim()) {
    try { return JSON.parse(data.output_text); } catch {}
  }
  const text=(data?.output||[]).flatMap(x=>x.content||[]).find(x=>x.type==="output_text")?.text||"";
  try { return JSON.parse(text); } catch { return null; }
}

function hardOptOut(text) {
  return /^(stop|unsubscribe|cancel|end|quit|remove me|do not message|don't message|dont message|no more messages)\b/i.test(String(text||"").trim());
}

function requestsHuman(text) {
  return /\b(human|real person|agent|representative|sales person|salesperson|call me|speak to someone|talk to someone)\b/i.test(String(text||""));
}

async function logAIEvent(env,data) {
  if(!(await tableExists(env,"ai_events"))) return;
  try{
    await insertDynamic(env,"ai_events",{
      id:uid(),workspace_id:data.workspaceId||null,lead_id:data.leadId||null,
      provider_message_id:data.providerMessageId||null,event_type:data.eventType||"conversation",
      action:data.action||null,intent:data.intent||null,confidence:data.confidence??null,
      summary:data.summary||null,reply_text:data.replyText||null,status:data.status||"ok",
      error_text:data.error||null,created_at:now()
    });
  }catch(err){ console.warn("AI event logging skipped:",err?.message||err); }
}

async function claimAIMessage(env,workspaceId,leadId,providerMessageId) {
  if(!(await tableExists(env,"ai_message_locks"))) return true;
  try{
    await env.DB.prepare(
      "INSERT INTO ai_message_locks (provider_message_id,workspace_id,lead_id,status,created_at,updated_at) VALUES (?,?,?,?,?,?)"
    ).bind(providerMessageId,workspaceId,leadId,"processing",now(),now()).run();
    return true;
  }catch{ return false; }
}

async function finishAIMessage(env,providerMessageId,status,errorText="") {
  if(!(await tableExists(env,"ai_message_locks"))) return;
  try{
    await env.DB.prepare(
      "UPDATE ai_message_locks SET status=?,error_text=?,updated_at=? WHERE provider_message_id=?"
    ).bind(status,errorText,now(),providerMessageId).run();
  }catch{}
}

async function generateConversationDecision(env,workspaceId,lead,businessInfo) {
  if(!env.OPENAI_API_KEY) throw new Error("AI is not configured");
  const messages=(await env.DB.prepare(
    "SELECT direction,body,created_at FROM messages WHERE workspace_id=? AND lead_id=? ORDER BY created_at DESC LIMIT 24"
  ).bind(workspaceId,lead.id).all()).results||[];
  const model=env.OPENAI_MODEL||"gpt-5.6-luna";
  const prompt=[
    "Decide the best next action in this active WhatsApp sales conversation and, only when appropriate, write the reply.",
    "The newest inbound message is the customer's current message.",
    "Primary goal: help the customer truthfully and move the conversation toward the business goal without pressure.",
    "Never invent prices, discounts, stock, guarantees, results, policies, credentials, delivery times, appointments, or product facts.",
    "If the answer is not supported by the supplied business facts or conversation, ask one concise clarifying question instead of guessing.",
    "Keep a reply short and natural for WhatsApp. Usually 1-3 sentences. No markdown. Do not mention AI, prompts, automation, or ColdCloud.",
    "Do not keep selling if the customer clearly opts out, asks not to be contacted, or is clearly not interested.",
    "Choose handoff when the customer explicitly requests a human or the request needs a person/business decision not supported by the supplied facts.",
    "Use lead_status only as a light CRM signal: interested for clear interest, hot for strong buying intent, won only when the conversation explicitly confirms a completed purchase/conversion, lost only for explicit rejection/opt-out.",
    "BUSINESS:",JSON.stringify({
      name:businessInfo.name||"",type:businessInfo.type||"",description:businessInfo.description||"",
      offer:businessInfo.offer||"",target:businessInfo.target||"",market:businessInfo.market||"",
      problem:businessInfo.problem||"",difference:businessInfo.difference||"",goal:businessInfo.goal||"",
      tone:businessInfo.tone||"",rules:businessInfo.rules||"",extra:businessInfo.extra||""
    }),
    "LEAD:",JSON.stringify({
      name:lead.name||"",company:lead.company||"",interest:lead.interest||"",
      businessType:lead.business_type||"",source:lead.source||"",notes:lead.notes||"",status:lead.status||""
    }),
    "RECENT CONVERSATION:",JSON.stringify(messages.reverse())
  ].join("\n");

  const res=await fetch("https://api.openai.com/v1/responses",{
    method:"POST",
    headers:{"content-type":"application/json","authorization":"Bearer "+env.OPENAI_API_KEY},
    body:JSON.stringify({
      model,
      input:[
        {role:"system",content:"You are ColdCloud's conversation brain for a business WhatsApp inbox. Make safe, truthful sales-conversation decisions."},
        {role:"user",content:prompt}
      ],
      text:{format:{
        type:"json_schema",name:"coldcloud_conversation_decision",strict:true,
        schema:{
          type:"object",additionalProperties:false,
          properties:{
            action:{type:"string",enum:["reply","handoff","stop","no_reply"]},
            intent:{type:"string",enum:["greeting","general_question","pricing","product_interest","objection","purchase_intent","support","not_interested","opt_out","human_request","other"]},
            sentiment:{type:"string",enum:["positive","neutral","negative"]},
            lead_status:{type:"string",enum:["new","contacted","interested","hot","won","lost"]},
            confidence:{type:"number"},
            reply:{type:"string"},
            summary:{type:"string"},
            extracted_interest:{type:"string"}
          },
          required:["action","intent","sentiment","lead_status","confidence","reply","summary","extracted_interest"]
        }
      }},
      max_output_tokens:700,
      store:false
    })
  });
  const data=await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data?.error?.message||"AI conversation decision failed");
  const decision=parseAIJson(data);
  if(!decision||!["reply","handoff","stop","no_reply"].includes(decision.action)) throw new Error("AI returned an invalid conversation decision");
  decision.reply=String(decision.reply||"").trim().slice(0,1200);
  decision.summary=String(decision.summary||"").trim().slice(0,1000);
  decision.extracted_interest=String(decision.extracted_interest||"").trim().slice(0,300);
  decision.confidence=Math.max(0,Math.min(1,Number(decision.confidence)||0));
  if(decision.action==="reply"&&!decision.reply) throw new Error("AI chose reply but returned no message");
  return decision;
}

async function handleInboundConversationAI(env,workspace,lead) {
  if(!workspace?.id||!lead?.id) return;
  await new Promise(resolve=>setTimeout(resolve,1800));

  const latest=await env.DB.prepare(
    "SELECT * FROM messages WHERE workspace_id=? AND lead_id=? AND direction='in' ORDER BY created_at DESC LIMIT 1"
  ).bind(workspace.id,lead.id).first();
  if(!latest?.provider_message_id) return;

  const claimed=await claimAIMessage(env,workspace.id,lead.id,latest.provider_message_id);
  if(!claimed) return;

  try{
    const currentLead=await env.DB.prepare("SELECT * FROM leads WHERE id=? AND workspace_id=? LIMIT 1")
      .bind(lead.id,workspace.id).first();
    if(!currentLead) { await finishAIMessage(env,latest.provider_message_id,"ignored","Lead not found"); return; }
    if(Number(currentLead.whatsapp_opt_out||0)) { await finishAIMessage(env,latest.provider_message_id,"ignored","Lead opted out"); return; }

    const latestText=String(latest.body||"").trim();
    if(hardOptOut(latestText)){
      await updateDynamic(env,"leads",{
        whatsapp_opt_out:1,sequence_paused:1,status:"lost",next_follow_up_at:null,updated_at:now()
      },"id=? AND workspace_id=?",[currentLead.id,workspace.id]);
      await logActivity(env,workspace.id,currentLead.id,"Lead opted out — AI and recovery stopped");
      await logAIEvent(env,{workspaceId:workspace.id,leadId:currentLead.id,providerMessageId:latest.provider_message_id,eventType:"conversation",action:"stop",intent:"opt_out",confidence:1,summary:"Explicit opt-out detected",status:"ok"});
      await finishAIMessage(env,latest.provider_message_id,"completed","");
      return;
    }

    if(requestsHuman(latestText)){
      await updateDynamic(env,"leads",{sequence_paused:1,status:"contacted",next_follow_up_at:null,updated_at:now()},"id=? AND workspace_id=?",[currentLead.id,workspace.id]);
      await logActivity(env,workspace.id,currentLead.id,"Human handoff requested — AI paused");
      await logAIEvent(env,{workspaceId:workspace.id,leadId:currentLead.id,providerMessageId:latest.provider_message_id,eventType:"conversation",action:"handoff",intent:"human_request",confidence:1,summary:"Customer explicitly requested a human",status:"ok"});
      await finishAIMessage(env,latest.provider_message_id,"completed","");
      return;
    }

    const business=await getBusinessInfoForWorkspace(env,workspace.id,workspace.owner_user_id);
    const missing=missingBusinessFields(business);
    if(missing.length) throw new Error("Business information is incomplete: "+missing.join(", "));

    const alreadySent=await env.DB.prepare(
      "SELECT id FROM messages WHERE workspace_id=? AND lead_id=? AND direction='out' AND created_at>? LIMIT 1"
    ).bind(workspace.id,currentLead.id,latest.created_at).first();
    if(alreadySent){ await finishAIMessage(env,latest.provider_message_id,"ignored","A newer outbound message already exists"); return; }

    const decision=await generateConversationDecision(env,workspace.id,currentLead,business);

    const allowedStatuses=new Set(["new","contacted","interested","hot","won","lost"]);
    const updates={sequence_paused:1,next_follow_up_at:null,updated_at:now()};
    if(allowedStatuses.has(decision.lead_status)) updates.status=decision.lead_status;
    if(decision.extracted_interest&&!String(currentLead.interest||"").trim()) updates.interest=decision.extracted_interest;
    if(decision.action==="stop"){
      updates.whatsapp_opt_out=decision.intent==="opt_out"?1:Number(currentLead.whatsapp_opt_out||0);
      updates.status=decision.intent==="opt_out"||decision.intent==="not_interested"?"lost":(updates.status||"contacted");
    }
    await updateDynamic(env,"leads",updates,"id=? AND workspace_id=?",[currentLead.id,workspace.id]);

    await logAIEvent(env,{
      workspaceId:workspace.id,leadId:currentLead.id,providerMessageId:latest.provider_message_id,
      eventType:"conversation",action:decision.action,intent:decision.intent,confidence:decision.confidence,
      summary:decision.summary,replyText:decision.reply,status:"ok"
    });

    if(decision.action==="reply"){
      await sendAutomaticWhatsApp(env,workspace,{...currentLead,...updates},"text",decision.reply,null,null);
      await logActivity(env,workspace.id,currentLead.id,"AI replied on WhatsApp · "+decision.intent);
    }else if(decision.action==="handoff"){
      await logActivity(env,workspace.id,currentLead.id,"AI requested human handoff · "+decision.intent);
    }else if(decision.action==="stop"){
      await logActivity(env,workspace.id,currentLead.id,"AI stopped the conversation · "+decision.intent);
    }else{
      await logActivity(env,workspace.id,currentLead.id,"AI chose not to reply · "+decision.intent);
    }

    await finishAIMessage(env,latest.provider_message_id,"completed","");
  }catch(err){
    const message=String(err?.message||err);
    await logAIEvent(env,{workspaceId:workspace.id,leadId:lead.id,providerMessageId:latest.provider_message_id,eventType:"conversation",action:"error",status:"error",error:message});
    await finishAIMessage(env,latest.provider_message_id,"failed",message);
    await logActivity(env,workspace.id,lead.id,"AI reply failed — needs attention");
    throw err;
  }
}

function templateVariableValues(template, lead) {
  const keys=[];
  String(template?.body_text || "").replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g,(_,key)=>{ if(!keys.includes(key)) keys.push(key); return _; });
  return keys.map(key=>{
    if(key==="name") return String(lead.name||"");
    if(key==="company") return String(lead.company||"");
    if(key==="interest") return String(lead.interest||"");
    return "";
  });
}

async function sendAutomaticWhatsApp(env, workspace, lead, type, text, templateId, sequenceStepId) {
  const connection=await env.DB.prepare("SELECT * FROM whatsapp_connections WHERE workspace_id=? AND status='connected' LIMIT 1").bind(workspace.id).first();
  if(!connection?.access_token_encrypted || !connection?.phone_number_id) throw new Error("Connect a WhatsApp Business number first");
  const to=String(lead.phone||"").replace(/[^+0-9]/g,"");
  if(!/^\+[1-9]\d{6,14}$/.test(to)) throw new Error("Lead phone must be in international format");
  const token=await decryptSecret(connection.access_token_encrypted,env.JWT_SECRET||env.META_APP_SECRET);
  let payload, sentText=String(text||"").trim();
  if(type==="template"){
    const template=await env.DB.prepare("SELECT * FROM whatsapp_templates WHERE id=? AND workspace_id=? LIMIT 1").bind(templateId,workspace.id).first();
    if(!template) throw new Error("Follow-up template not found");
    if(String(template.provider_status||"").toLowerCase()!=="approved") throw new Error("Follow-up template is not approved");
    const values=templateVariableValues(template,lead);
    if(values.some(v=>!v.trim())) throw new Error("A template variable is missing");
    payload={messaging_product:"whatsapp",to,type:"template",template:{
      name:String(template.provider_template_name||""),language:{code:String(template.language||"en_US")},
      components:values.length?[{type:"body",parameters:values.map(v=>({type:"text",text:v}))}]:[]
    }};
    sentText=String(template.body_text||"").replace(/\{\{\s*name\s*\}\}/gi,lead.name||"").replace(/\{\{\s*company\s*\}\}/gi,lead.company||"").replace(/\{\{\s*interest\s*\}\}/gi,lead.interest||"");
  }else{
    if(!sentText) throw new Error("Message text is required");
    payload={messaging_product:"whatsapp",to,type:"text",text:{preview_url:false,body:sentText}};
  }
  const graphVersion=env.META_GRAPH_VERSION||"v25.0";
  const metaRes=await fetch("https://graph.facebook.com/"+graphVersion+"/"+encodeURIComponent(connection.phone_number_id)+"/messages",{
    method:"POST",headers:{"content-type":"application/json",Authorization:"Bearer "+token},body:JSON.stringify(payload)
  });
  const metaJson=await metaRes.json().catch(()=>({}));
  if(!metaRes.ok) throw new Error(metaJson?.error?.message||"WhatsApp could not send the message");
  const providerMessageId=String(metaJson?.messages?.[0]?.id||"");
  const createdAt=now();
  if(await tableExists(env,"messages")){
    try{ await insertDynamic(env,"messages",{
      id:uid(),workspace_id:workspace.id,user_id:workspace.owner_user_id,lead_id:lead.id,
      direction:"out",channel:"WhatsApp",body:sentText,status:"sent",provider_message_id:providerMessageId,
      sequence_step_id:sequenceStepId||null,created_at:createdAt
    }); }catch(err){ console.warn("Automatic message log skipped:",err?.message||err); }
  }
  await updateDynamic(env,"leads",{last_outbound_at:createdAt,updated_at:createdAt},"id=? AND workspace_id=?",[lead.id,workspace.id]);
  await logActivity(env,workspace.id,lead.id,"Automatic WhatsApp recovery message sent");
  return {providerMessageId,sentText};
}

async function runRecoveryForWorkspace(env, workspace) {
  if(!workspace?.id || !(await tableExists(env,"leads"))) return {checked:0,sent:0,skipped:0};
  const rows=(await env.DB.prepare(
    "SELECT * FROM leads WHERE workspace_id=? AND sequence_id IS NOT NULL AND COALESCE(sequence_paused,0)=0 AND COALESCE(whatsapp_opt_out,0)=0 AND next_follow_up_at IS NOT NULL AND next_follow_up_at<=? ORDER BY next_follow_up_at LIMIT 25"
  ).bind(workspace.id,now()).all()).results || [];
  let sent=0,skipped=0;
  for(const row of rows){
    try{
      const latestInbound=await env.DB.prepare("SELECT created_at FROM messages WHERE workspace_id=? AND lead_id=? AND direction='in' ORDER BY created_at DESC LIMIT 1").bind(workspace.id,row.id).first();
      if(latestInbound?.created_at && (!row.last_outbound_at || Date.parse(latestInbound.created_at)>Date.parse(row.last_outbound_at))){
        await updateDynamic(env,"leads",{sequence_paused:1,status:"contacted",next_follow_up_at:null,updated_at:now()},"id=? AND workspace_id=?",[row.id,workspace.id]);
        skipped++; continue;
      }
      const plan=parseLeadPlan(row);
      const progress=Number(row.sequence_progress||0);
      const step=plan[progress];
      if(!step){
        await updateDynamic(env,"leads",{next_follow_up_at:null,sequence_paused:1,updated_at:now()},"id=? AND workspace_id=?",[row.id,workspace.id]);
        skipped++; continue;
      }
      if(step.enabled===false || step.status==="skipped"){
        const nextIndex=progress+1, next=plan[nextIndex];
        await updateDynamic(env,"leads",{sequence_progress:nextIndex,next_follow_up_at:next?new Date(Date.now()+Math.max(0,Number(next.day||0)-Number(step.day||0))*86400000).toISOString():null,updated_at:now()},"id=? AND workspace_id=?",[row.id,workspace.id]);
        skipped++; continue;
      }
      const lead=leadOut(row);
      if(!lead.whatsappOptIn) throw new Error("WhatsApp opt-in is required");
      const business=await getBusinessInfoForWorkspace(env,workspace.id,workspace.owner_user_id);
      let result;
      if(recoveryWindowOpen(lead)){
        const aiText=await generateAutomaticReply(env,workspace.id,row,business,step);
        result=await sendAutomaticWhatsApp(env,workspace,row,"text",aiText,null,step.id||null);
      }else{
        if(!step.templateId) throw new Error("No approved follow-up template is assigned to this step");
        result=await sendAutomaticWhatsApp(env,workspace,row,"template","",step.templateId,step.id||null);
      }
      const nextIndex=progress+1, next=plan[nextIndex], stepDay=Number(step.day||0), nextDay=next?Number(next.day||0):null;
      const nextAt=next?new Date(Date.now()+Math.max(0,nextDay-stepDay)*86400000).toISOString():null;
      const updatedPlan=plan.map((x,i)=>i===progress?{...x,status:"sent",sentAt:now(),providerMessageId:result.providerMessageId}:x);
      await updateDynamic(env,"leads",{sequence_progress:nextIndex,sequence_plan:JSON.stringify(updatedPlan),next_follow_up_at:nextAt,status:"followup",updated_at:now(),...(next?{}:{sequence_paused:1})},"id=? AND workspace_id=?",[row.id,workspace.id]);
      sent++;
    }catch(err){
      console.warn("Recovery send skipped for lead",row.id,err?.message||err);
      await updateDynamic(env,"leads",{next_follow_up_at:new Date(Date.now()+30*60000).toISOString(),updated_at:now()},"id=? AND workspace_id=?",[row.id,workspace.id]);
      skipped++;
    }
  }
  return {checked:rows.length,sent,skipped};
}

async function runRecoveryScheduler(env) {
  if(!(await tableExists(env,"workspaces"))) return;
  const workspaces=(await env.DB.prepare("SELECT * FROM workspaces ORDER BY created_at").all()).results||[];
  for(const workspace of workspaces) {
    try { await runRecoveryForWorkspace(env,workspace); } catch(err){ console.warn("Workspace recovery scheduler failed:",workspace.id,err?.message||err); }
  }
}

async function handleWhatsAppWebhook(req,env,ctx) {
  const url=new URL(req.url);
  if(req.method==="GET"){
    const mode=url.searchParams.get("hub.mode"), token=url.searchParams.get("hub.verify_token"), challenge=url.searchParams.get("hub.challenge");
    if(mode==="subscribe" && token && token===env.WHATSAPP_VERIFY_TOKEN) return new Response(challenge||"",{status:200});
    return new Response("Forbidden",{status:403});
  }
  if(req.method!=="POST") return json({ok:false,error:"Method not allowed"},405);
  const body=await read(req), entries=Array.isArray(body.entry)?body.entry:[];
  for(const entry of entries){
    for(const change of (entry.changes||[])){
      const value=change.value||{}, phoneNumberId=String(value.metadata?.phone_number_id||"");
      if(!phoneNumberId) continue;
      const connection=await env.DB.prepare("SELECT * FROM whatsapp_connections WHERE phone_number_id=? AND status='connected' LIMIT 1").bind(phoneNumberId).first();
      if(!connection) continue;
      for(const message of (value.messages||[])){
        const providerMessageId=String(message.id||"");
        if(!providerMessageId) continue;
        const duplicate=await env.DB.prepare("SELECT id FROM messages WHERE provider_message_id=? LIMIT 1").bind(providerMessageId).first();
        if(duplicate) continue;
        const from=String(message.from||"").replace(/[^0-9]/g,"");
        if(!from) continue;
        const leads=(await env.DB.prepare("SELECT * FROM leads WHERE workspace_id=?").bind(connection.workspace_id).all()).results||[];
        const lead=leads.find(x=>String(x.phone||"").replace(/[^0-9]/g,"")===from);
        if(!lead) continue;
        const bodyText=message.text?.body||message.button?.text||message.interactive?.button_reply?.title||message.interactive?.list_reply?.title||"[WhatsApp message]";
        const createdAt=now();
        if(await tableExists(env,"messages")){
          try{
            await insertDynamic(env,"messages",{id:uid(),workspace_id:connection.workspace_id,user_id:connection.workspace_id,lead_id:lead.id,direction:"in",channel:"WhatsApp",body:String(bodyText),status:"received",provider_message_id:providerMessageId,created_at:createdAt});
          }catch(err){console.warn("Inbound message log skipped:",err?.message||err);}
        }
        await updateDynamic(env,"leads",{last_inbound_at:createdAt,sequence_paused:1,status:"contacted",next_follow_up_at:null,updated_at:createdAt},"id=? AND workspace_id=?",[lead.id,connection.workspace_id]);
        await logActivity(env,connection.workspace_id,lead.id,"Lead replied on WhatsApp — recovery sequence paused");
        const workspace=await env.DB.prepare("SELECT * FROM workspaces WHERE id=? LIMIT 1").bind(connection.workspace_id).first();
        if(workspace && ctx?.waitUntil) ctx.waitUntil(handleInboundConversationAI(env,workspace,lead).catch(err=>console.warn("AI conversation reply failed:",err?.message||err)));
      }
    }
  }
  return json({ok:true});
}


export default {
  async scheduled(event, env, ctx) { ctx.waitUntil(runRecoveryScheduler(env)); },

  async fetch(req, env, ctx) {
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

      if (path[0] === "auth" && path[1] === "google" && path[2] === "config" && req.method === "GET") {
        return json({ok:true,clientId:env.GOOGLE_CLIENT_ID||""});
      }

      if (path[0] === "auth" && path[1] === "google" && req.method === "POST") {
        const body=await read(req);
        try{
          const claims=await verifyGoogleIdToken(body.credential,env);
          const email=String(claims.email).trim().toLowerCase();
          const googleSub=String(claims.sub);
          let user=await env.DB.prepare("SELECT * FROM users WHERE google_sub=? LIMIT 1").bind(googleSub).first();
          if(!user) user=await env.DB.prepare("SELECT * FROM users WHERE email=? LIMIT 1").bind(email).first();
          if(user){
            if(!user.google_sub) await updateDynamic(env,"users",{google_sub:googleSub,avatar_url:String(claims.picture||"")},"id=?",[user.id]);
          }else{
            const userId=uid();
            await insertDynamic(env,"users",{
              id:userId,email,password_hash:"",password_salt:"",name:String(claims.name||claims.given_name||email.split("@")[0]),
              google_sub:googleSub,avatar_url:String(claims.picture||""),created_at:now(),updated_at:now()
            });
            user=await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(userId).first();
          }
          const workspace=await ensureWorkspace(env,user.id);
          await ensureDefaults(env,workspace.id);
          const token=await jwt({sub:user.id,email:user.email,exp:Date.now()/1000+604800},env.JWT_SECRET);
          return json({ok:true,token,user:{id:user.id,email:user.email,name:user.name,avatarUrl:user.avatar_url||""},workspace});
        }catch(err){return json({ok:false,error:err?.message||"Google sign-in failed"},401)}
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

      if (path[0] === "auth" && path[1] === "change-password" && req.method === "POST") {
        const authUser = await userFrom(req, env);
        if (!authUser?.sub) return json({ ok: false, error: "Unauthorized" }, 401);

        const body = await read(req);
        const currentPassword = String(body.currentPassword || "");
        const newPassword = String(body.newPassword || "");
        if (newPassword.length < 8) {
          return json({ ok: false, error: "New password must be at least 8 characters." }, 400);
        }

        const user = await env.DB.prepare(
          "SELECT id,password_hash,password_salt FROM users WHERE id=? LIMIT 1"
        ).bind(authUser.sub).first();
        if (!user) return json({ ok: false, error: "User account not found" }, 404);
        if (!user.password_salt || !(await passwordVerify(currentPassword, user.password_salt, user.password_hash))) {
          return json({ ok: false, error: "Current password is incorrect." }, 400);
        }

        const pw = await passwordHash(newPassword);
        await env.DB.prepare(
          "UPDATE users SET password_hash=?,password_salt=?,updated_at=? WHERE id=?"
        ).bind(pw.hash,pw.salt,now(),authUser.sub).run();

        return json({ ok: true, message: "Password changed successfully." });
      }

      if (path[0] === "auth" && path[1] === "delete-account" && req.method === "DELETE") {
        const authUser = await userFrom(req, env);
        if (!authUser?.sub) return json({ ok: false, error: "Unauthorized" }, 401);

        const body = await read(req);
        const password = String(body.password || "");
        const user = await env.DB.prepare(
          "SELECT id,password_hash,password_salt FROM users WHERE id=? LIMIT 1"
        ).bind(authUser.sub).first();
        if (!user) return json({ ok: false, error: "User account not found" }, 404);
        if (!user.password_salt || !(await passwordVerify(password, user.password_salt, user.password_hash))) {
          return json({ ok: false, error: "Password is incorrect." }, 400);
        }

        const workspace = await env.DB.prepare(
          "SELECT id FROM workspaces WHERE owner_user_id=? ORDER BY created_at LIMIT 1"
        ).bind(authUser.sub).first();

        const workspaceId = workspace?.id || "";
        const workspaceTables = [
          "messages","conversations","activities","whatsapp_templates","whatsapp_connections",
          "leads","sequence_steps","automations","sequences","business_profiles"
        ];

        for (const table of workspaceTables) {
          if (!(await tableExists(env, table))) continue;
          const cols = await tableColumns(env, table);
          try {
            if (cols.has("workspace_id") && workspaceId) {
              await env.DB.prepare("DELETE FROM "+table+" WHERE workspace_id=?").bind(workspaceId).run();
            } else if (cols.has("user_id")) {
              await env.DB.prepare("DELETE FROM "+table+" WHERE user_id=?").bind(authUser.sub).run();
            }
          } catch (err) {
            console.warn("Account cleanup skipped for "+table+":",err?.message||err);
          }
        }

        if (workspaceId && await tableExists(env,"workspaces")) {
          await env.DB.prepare("DELETE FROM workspaces WHERE id=?").bind(workspaceId).run();
        }
        await env.DB.prepare("DELETE FROM users WHERE id=?").bind(authUser.sub).run();

        return json({ ok: true, deleted: true });
      }

      if (path[0] === "auth" && path[1] === "me" && req.method === "GET") {
        const authUser = await userFrom(req, env);
        if (!authUser?.sub) {
          return json({ ok: false, error: "Unauthorized" }, 401);
        }

        const user = await env.DB.prepare(
          "SELECT id,email,name,avatar_url,created_at,updated_at FROM users WHERE id=? LIMIT 1"
        ).bind(authUser.sub).first();

        if (!user) {
          return json({ ok: false, error: "User account not found" }, 401);
        }

        const workspace = await ensureWorkspace(env, user.id);
        await ensureDefaults(env, workspace.id);

        return json({
          ok: true,
          user: {
            id: user.id,
            email: user.email,
            name: user.name || "",
            avatarUrl: user.avatar_url || ""
          },
          workspace
        });
      }

      if (path[0] === "dev" && path[1] === "session" && req.method === "POST") {
        const devKey = req.headers.get("X-Dev-Key") || "";
        if (!env.DEV_BOOTSTRAP_KEY || devKey !== env.DEV_BOOTSTRAP_KEY) {
          return json({ ok: false, error: "Unauthorized" }, 401);
        }

        const devEmail = "dev@usecoldcloud.xyz";
        let user = await env.DB.prepare(
          "SELECT * FROM users WHERE email=? LIMIT 1"
        ).bind(devEmail).first();

        if (!user) {
          const pw = await passwordHash(crypto.randomUUID());
          const userId = uid();
          await insertDynamic(env, "users", {
            id: userId,
            email: devEmail,
            password_hash: pw.hash,
            password_salt: pw.salt,
            name: "ColdCloud Developer",
            created_at: now(),
            updated_at: now()
          });
          user = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(userId).first();
        }

        const workspace = await ensureWorkspace(env, user.id);
        await ensureDefaults(env, workspace.id);

        const token = await jwt(
          { sub: user.id, email: user.email, exp: Date.now() / 1000 + 2592000, dev: true },
          env.JWT_SECRET
        );

        return json({
          ok: true,
          token,
          user: { id: user.id, email: user.email, name: user.name },
          workspace
        });
      }

      if (path[0] === "whatsapp" && path[1] === "webhook") return await handleWhatsAppWebhook(req, env, ctx);

      const authUser = await userFrom(req, env);
      if (!authUser) return json({ ok: false, error: "Unauthorized" }, 401);

      const workspace = await ensureWorkspace(env, authUser.sub);
      await ensureDefaults(env, workspace.id);

      const businessOpen = path[0] === "business" ||
        path[0] === "me" ||
        path[0] === "auth" ||
        (path[0] === "whatsapp" && ["config","status","connect"].includes(path[1])) ||
        (path[0] === "ai" && path[1] === "status");
      if (!businessOpen) {
        const businessCheck = await requireBusinessInfo(env, workspace.id, authUser.sub);
        if (businessCheck.missing.length) {
          return json({
            ok: false,
            error: "Business Information is required before using ColdCloud.",
            code: "BUSINESS_INFO_REQUIRED",
            missing: businessCheck.missing
          }, 428);
        }
      }

      if (path[0] === "whatsapp" && path[1] === "config" && req.method === "GET") {
        return json({
          ok: true,
          appId: env.META_APP_ID || "",
          configId: env.META_CONFIG_ID || "",
          graphVersion: env.META_GRAPH_VERSION || "v25.0",
          hasMetaAccessToken: !!String(env.META_ACCESS_TOKEN || "").trim(),
          // Development-only Meta test assets. These are IDs, not secrets.
          testWabaId: env.DEV_MODE === "true" ? "1095462349574167" : "",
          testPhoneNumberId: env.DEV_MODE === "true" ? "1345653985287953" : ""
        });
      }

      if (path[0] === "whatsapp" && path[1] === "status" && req.method === "GET") {
        if (!(await tableExists(env, "whatsapp_connections"))) {
          return json({ ok: true, connected: false });
        }
        const row = await env.DB.prepare(
          "SELECT id,waba_id,phone_number_id,business_id,display_phone_number,verified_name,status,created_at,updated_at FROM whatsapp_connections WHERE workspace_id=? LIMIT 1"
        ).bind(workspace.id).first();
        return json({
          ok: true,
          connected: !!row && row.status === "connected",
          connection: row || null
        });
      }

      if (path[0] === "whatsapp" && path[1] === "connect" && req.method === "POST") {
        if (!(await tableExists(env, "whatsapp_connections"))) {
          return json({ ok: false, error: "WhatsApp connection storage is not installed yet" }, 500);
        }

        const body = await read(req);
        const code = String(body.code || "").trim();
        const suppliedToken = String(body.accessToken || "").trim();
        const configuredToken = String(env.META_ACCESS_TOKEN || "").trim();
        const wabaId = String(body.wabaId || "").trim();
        const phoneNumberId = String(body.phoneNumberId || "").trim();
        const businessId = String(body.businessId || "").trim();

        // Normal Embedded Signup uses an authorization code. For Meta's
        // test-account flow, allow a server-side access token stored as a
        // Cloudflare Secret so the token never reaches the browser.
        if (code && (!env.META_APP_ID || !env.META_APP_SECRET)) {
          return json({ ok: false, error: "Meta WhatsApp OAuth is not configured on ColdCloud" }, 503);
        }
        if (!code && !suppliedToken && !configuredToken) {
          return json({ ok: false, error: "WhatsApp signup did not return an authorization code or access token" }, 400);
        }

        const graphVersion = env.META_GRAPH_VERSION || "v25.0";
        let accessToken = suppliedToken || configuredToken;

        if (code) {
          const params = new URLSearchParams({
            client_id: env.META_APP_ID,
            client_secret: env.META_APP_SECRET,
            code
          });
          if (env.META_REDIRECT_URI) params.set("redirect_uri", env.META_REDIRECT_URI);

          const tokenRes = await fetch(
            "https://graph.facebook.com/" + graphVersion + "/oauth/access_token",
            { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: params }
          );
          const tokenJson = await tokenRes.json();
          if (!tokenRes.ok || !tokenJson.access_token) {
            return json({
              ok: false,
              error: tokenJson?.error?.message || "Meta authorization exchange failed"
            }, 400);
          }
          accessToken = tokenJson.access_token;
        }

        // Meta's Embedded Signup session message normally provides the WABA ID.
        // If the browser message is missed, recover it from the returned user token.
        let resolvedWabaId = wabaId;
        if (!resolvedWabaId && accessToken) {
          const appAccessToken = env.META_APP_ID + "|" + env.META_APP_SECRET;
          const debugRes = await fetch(
            "https://graph.facebook.com/" + graphVersion + "/debug_token?input_token=" + encodeURIComponent(accessToken),
            { headers: { Authorization: "Bearer " + appAccessToken } }
          );
          const debugJson = await debugRes.json().catch(() => ({}));
          const granular = Array.isArray(debugJson?.data?.granular_scopes) ? debugJson.data.granular_scopes : [];
          const waScope = granular.find(x => x.scope === "whatsapp_business_management");
          resolvedWabaId = String(waScope?.target_ids?.[0] || "").trim();
        }

        if (!resolvedWabaId) {
          return json({ ok: false, error: "Meta authorized ColdCloud, but no WhatsApp Business Account was returned. Please reconnect and finish the WhatsApp setup." }, 400);
        }

        let resolvedPhoneNumberId = phoneNumberId;
        if (!resolvedPhoneNumberId) {
          const phonesRes = await fetch(
            "https://graph.facebook.com/" + graphVersion + "/" + encodeURIComponent(resolvedWabaId) +
            "/phone_numbers?fields=id,display_phone_number,verified_name&access_token=" + encodeURIComponent(accessToken)
          );
          const phonesJson = await phonesRes.json().catch(() => ({}));
          resolvedPhoneNumberId = String(phonesJson?.data?.[0]?.id || "").trim();
        }

        let phone = null;
        if (resolvedPhoneNumberId) {
          const phoneRes = await fetch(
            "https://graph.facebook.com/" + graphVersion + "/" + encodeURIComponent(resolvedPhoneNumberId) +
            "?fields=id,display_phone_number,verified_name&access_token=" + encodeURIComponent(accessToken)
          );
          if (phoneRes.ok) phone = await phoneRes.json();
        }

        const subscribeRes = await fetch(
          "https://graph.facebook.com/" + graphVersion + "/" + encodeURIComponent(resolvedWabaId) + "/subscribed_apps",
          {
            method: "POST",
            headers: { Authorization: "Bearer " + accessToken }
          }
        );
        if (!subscribeRes.ok) {
          const subscribeJson = await subscribeRes.json().catch(() => ({}));
          return json({
            ok: false,
            error: subscribeJson?.error?.message || "Could not subscribe ColdCloud to the WhatsApp Business Account"
          }, 400);
        }

        const encryptedToken = await encryptSecret(accessToken, env.JWT_SECRET || env.META_APP_SECRET);
        const existing = await env.DB.prepare(
          "SELECT id FROM whatsapp_connections WHERE workspace_id=? LIMIT 1"
        ).bind(workspace.id).first();

        const data = {
          id: existing?.id || uid(),
          workspace_id: workspace.id,
          waba_id: resolvedWabaId,
          phone_number_id: resolvedPhoneNumberId || phone?.id || null,
          business_id: businessId || null,
          display_phone_number: phone?.display_phone_number || null,
          verified_name: phone?.verified_name || null,
          access_token_encrypted: encryptedToken,
          status: "connected",
          updated_at: now()
        };

        if (existing) {
          await updateDynamic(env, "whatsapp_connections", data, "id=? AND workspace_id=?", [existing.id, workspace.id]);
        } else {
          data.created_at = now();
          await insertDynamic(env, "whatsapp_connections", data);
        }

        await logActivity(env, workspace.id, null, "WhatsApp connected");
        return json({
          ok: true,
          connected: true,
          connection: {
            wabaId: resolvedWabaId,
            phoneNumberId: data.phone_number_id,
            displayPhoneNumber: data.display_phone_number,
            verifiedName: data.verified_name
          }
        });
      }

      if (path[0] === "whatsapp" && path[1] === "send" && req.method === "POST") {
        const body = await read(req);
        const leadId = String(body.leadId || "").trim();
        const type = String(body.type || "text").toLowerCase();
        const text = String(body.text || "").trim();
        if (!leadId) return json({ok:false,error:"Lead is required."},400);
        if (type === "text" && !text) return json({ok:false,error:"Message text is required."},400);

        const lead = await getWorkspaceLead(env, workspace.id, leadId);
        if (!lead) return json({ok:false,error:"Lead not found."},404);

        if (!(await tableExists(env,"whatsapp_connections"))) {
          return json({ok:false,error:"WhatsApp connection storage is not installed yet."},500);
        }
        const connection = await env.DB.prepare(
          "SELECT * FROM whatsapp_connections WHERE workspace_id=? AND status='connected' LIMIT 1"
        ).bind(workspace.id).first();
        if (!connection?.access_token_encrypted || !connection?.phone_number_id) {
          return json({ok:false,error:"Connect a WhatsApp Business number first."},400);
        }

        const graphVersion = env.META_GRAPH_VERSION || "v25.0";
        const token = await decryptSecret(
          connection.access_token_encrypted,
          env.JWT_SECRET || env.META_APP_SECRET
        );
        const to = String(lead.phone || "").replace(/[^+0-9]/g,"");
        if (!/^\+[1-9]\d{6,14}$/.test(to)) {
          return json({ok:false,error:"Lead phone must be in international format, for example +919876543210."},400);
        }

        let payload;
        let sentText = text;
        let templateId = null;

        if (type === "template") {
          templateId = String(body.templateId || "").trim();
          if (!templateId) return json({ok:false,error:"Approved WhatsApp template is required."},400);
          if (!(await tableExists(env,"whatsapp_templates"))) {
            return json({ok:false,error:"Template storage is not installed yet."},500);
          }
          const template = await env.DB.prepare(
            "SELECT * FROM whatsapp_templates WHERE id=? AND workspace_id=? LIMIT 1"
          ).bind(templateId,workspace.id).first();
          if (!template) return json({ok:false,error:"Follow-up template not found."},404);
          if (String(template.provider_status||"").toLowerCase() !== "approved") {
            return json({ok:false,error:"This follow-up is not approved by WhatsApp yet."},400);
          }

          const values = Array.isArray(body.variables) ? body.variables.map(v=>String(v ?? "")) : [];
          const variableMap = {};
          let n = 0;
          String(template.body_text || "").replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_,key) => {
            if (!variableMap[key]) variableMap[key] = String(++n);
            return _;
          });
          const ordered = Object.entries(variableMap).sort((a,c)=>Number(a[1])-Number(c[1])).map(([key]) => {
            if (body.variableValues && body.variableValues[key] !== undefined) return String(body.variableValues[key] ?? "");
            if (key === "name") return String(lead.name || "");
            if (key === "company") return String(lead.company || "");
            if (key === "interest") return String(lead.interest || "");
            return "";
          });
          if (ordered.some(v=>!v.trim())) return json({ok:false,error:"A template variable is missing."},400);

          payload = {
            messaging_product:"whatsapp",
            to,
            type:"template",
            template:{
              name:String(template.provider_template_name || ""),
              language:{code:String(template.language || "en_US")},
              components: ordered.length ? [{
                type:"body",
                parameters:ordered.map(v=>({type:"text",text:v}))
              }] : []
            }
          };
          sentText = String(template.body_text || "").replace(/\{\{\s*name\s*\}\}/gi,lead.name||"").replace(/\{\{\s*company\s*\}\}/gi,lead.company||"").replace(/\{\{\s*interest\s*\}\}/gi,lead.interest||"");
        } else {
          payload = {
            messaging_product:"whatsapp",
            to,
            type:"text",
            text:{preview_url:false,body:text}
          };
        }

        const metaRes = await fetch(
          "https://graph.facebook.com/"+graphVersion+"/"+encodeURIComponent(connection.phone_number_id)+"/messages",
          {
            method:"POST",
            headers:{"content-type":"application/json",Authorization:"Bearer "+token},
            body:JSON.stringify(payload)
          }
        );
        const metaJson = await metaRes.json().catch(()=>({}));
        if (!metaRes.ok) {
          return json({ok:false,error:metaJson?.error?.message||"WhatsApp could not send the message."},400);
        }

        const providerMessageId = String(metaJson?.messages?.[0]?.id || "");
        const createdAt = now();

        if (await tableExists(env,"messages")) {
          try {
            await insertDynamic(env,"messages",{
              id:uid(),workspace_id:workspace.id,user_id:authUser.sub,lead_id:leadId,
              conversation_id:body.conversationId || null,direction:"out",channel:"WhatsApp",
              body:sentText,status:"sent",provider_message_id:providerMessageId,
              sequence_step_id:body.sequenceStepId || null,created_at:createdAt
            });
          } catch(err) { console.warn("Message log skipped:",err?.message||err); }
        }

        await updateDynamic(env,"leads",{last_outbound_at:createdAt,updated_at:createdAt},"id=? AND workspace_id=?",[leadId,workspace.id]);
        await logActivity(env,workspace.id,leadId,"WhatsApp message sent to "+(lead.name||"lead"));

        return json({ok:true,messageId:providerMessageId,to,type,text:sentText});
      }

      if (path[0] === "ai" && path[1] === "status" && req.method === "GET") {
        const business=await requireBusinessInfo(env,workspace.id,authUser.sub);
        const whatsapp=await env.DB.prepare(
          "SELECT id,status,phone_number_id,display_phone_number,verified_name FROM whatsapp_connections WHERE workspace_id=? LIMIT 1"
        ).bind(workspace.id).first();
        const recentAI=(await tableExists(env,"ai_events"))
          ? await env.DB.prepare("SELECT action,intent,status,error_text,created_at FROM ai_events WHERE workspace_id=? ORDER BY created_at DESC LIMIT 5").bind(workspace.id).all()
          : {results:[]};
        return json({
          ok:true,
          ai:{
            configured:!!env.OPENAI_API_KEY,
            model:env.OPENAI_MODEL||"gpt-5.6-luna",
            businessReady:business.missing.length===0,
            missingBusinessFields:business.missing,
            whatsappConnected:!!(whatsapp&&whatsapp.status==="connected"),
            whatsapp:whatsapp?{
              status:whatsapp.status,
              displayPhoneNumber:whatsapp.display_phone_number||"",
              verifiedName:whatsapp.verified_name||""
            }:null,
            conversationBrain:true,
            structuredDecisions:true,
            duplicateProtection:await tableExists(env,"ai_message_locks"),
            eventLogging:await tableExists(env,"ai_events"),
            recentEvents:recentAI.results||[]
          }
        });
      }

      if (path[0] === "ai" && path[1] === "followups" && req.method === "POST") {
        if (!env.OPENAI_API_KEY) {
          return json({ ok:false, error:"AI is not configured yet. Add OPENAI_API_KEY to the ColdCloud Worker." },503);
        }
        const body = await read(req);
        const b = body.businessInfo || {};
        const required = ["name","type","description","offer","target","market","problem","difference","goal","tone","rules"];
        const missing = required.filter(k => !String(b[k] || "").trim());
        if (missing.length) {
          return json({ ok:false, error:"Complete Business Information before generating follow-ups.", missing },400);
        }

        const model = env.OPENAI_MODEL || "gpt-5.6-luna";
        const prompt = [
          "Create five WhatsApp lead-recovery follow-up templates for this business.",
          "These are reusable templates, not messages for one specific person.",
          "Use only the supplied business facts. Do not invent prices, guarantees, results, discounts, policies, credentials, or claims.",
          "Keep each message natural, concise, human, and suitable for WhatsApp.",
          "Respect the requested tone and rules.",
          "Use only these placeholders when useful: {{name}}, {{interest}}, {{company}}.",
          "Do not use markdown, emojis, numbered lists, or quotation marks around the messages.",
          "The final follow-up should close the loop without sounding aggressive.",
          "",
          "BUSINESS INFORMATION:",
          JSON.stringify({
            name:b.name,type:b.type,description:b.description,offer:b.offer,target:b.target,
            market:b.market,problem:b.problem,difference:b.difference,goal:b.goal,
            tone:b.tone,rules:b.rules,extra:b.extra || ""
          })
        ].join("\n");

        const aiRes = await fetch("https://api.openai.com/v1/responses", {
          method:"POST",
          headers:{
            "content-type":"application/json",
            "authorization":"Bearer "+env.OPENAI_API_KEY
          },
          body:JSON.stringify({
            model,
            input:[
              {
                role:"system",
                content:"You are ColdCloud's lead-recovery copywriter. Generate practical, truthful WhatsApp follow-ups for small businesses."
              },
              { role:"user", content:prompt }
            ],
            text:{
              format:{
                type:"json_schema",
                name:"coldcloud_followups",
                strict:true,
                schema:{
                  type:"object",
                  additionalProperties:false,
                  properties:{
                    followups:{
                      type:"array",
                      minItems:5,
                      maxItems:5,
                      items:{
                        type:"object",
                        additionalProperties:false,
                        properties:{
                          name:{type:"string"},
                          use:{type:"string",enum:["first","second","third","fourth","final"]},
                          body:{type:"string"}
                        },
                        required:["name","use","body"]
                      }
                    }
                  },
                  required:["followups"]
                }
              }
            },
            max_output_tokens:1200,
            store:false
          })
        });

        const aiJson = await aiRes.json().catch(() => ({}));
        if (!aiRes.ok) {
          return json({
            ok:false,
            error:aiJson?.error?.message || "AI generation failed. Please try again."
          },502);
        }

        let generated = null;
        if (typeof aiJson.output_text === "string" && aiJson.output_text.trim()) {
          try { generated = JSON.parse(aiJson.output_text); } catch {}
        }
        if (!generated) {
          const textPart = (aiJson.output || [])
            .flatMap(x => x.content || [])
            .find(x => x.type === "output_text")?.text || "";
          try { generated = JSON.parse(textPart); } catch {}
        }

        if (!Array.isArray(generated?.followups) || generated.followups.length !== 5) {
          return json({ok:false,error:"AI returned an invalid follow-up set. Please try again."},502);
        }

        if (!(await tableExists(env,"whatsapp_templates"))) {
          return json({ok:false,error:"Template storage is not installed yet."},500);
        }

        const created=[];
        const existingRows=(await env.DB.prepare(
          "SELECT id,name FROM whatsapp_templates WHERE workspace_id=?"
        ).bind(workspace.id).all()).results || [];
        const existingNames=new Set(existingRows.map(x=>String(x.name||"").toLowerCase()));

        for (const item of generated.followups) {
          const name=String(item.name||"").trim();
          const message=String(item.body||"").trim();
          if (!name || !message || existingNames.has(name.toLowerCase())) continue;

          const id=uid();
          const use=String(item.use||"custom");
          const useLabel=({first:"First follow-up",second:"Second follow-up",third:"Third follow-up",fourth:"Fourth follow-up",final:"Final follow-up"})[use] || "Follow-up";

          await insertDynamic(env,"whatsapp_templates",{
            id,workspace_id:workspace.id,name,category:"MARKETING",language:"en_US",
            body_text:message,use_type:use,use_label:useLabel,
            provider_template_id:null,provider_template_name:null,
            provider_status:"not_submitted",rejection_reason:null,
            created_at:now(),updated_at:now()
          });

          created.push({
            id,name,category:"MARKETING",language:"en_US",body:message,
            use,useLabel,providerId:"",providerStatus:"not_submitted",rejectionReason:""
          });
          existingNames.add(name.toLowerCase());
        }

        return json({ok:true,model,templates:created});
      }

      if (path[0] === "ai" && path[1] === "reply" && req.method === "POST") {
        if (!env.OPENAI_API_KEY) return json({ok:false,error:"AI is not configured yet. Add OPENAI_API_KEY to the ColdCloud Worker."},503);
        const body=await read(req);
        const lead=body.lead||{};
        const businessCheck=await requireBusinessInfo(env,workspace.id,authUser.sub);
        if(businessCheck.missing.length){
          return json({ok:false,error:"Business Information is incomplete",code:"BUSINESS_INFO_REQUIRED",missing:businessCheck.missing},428);
        }
        const business=businessCheck.info;
        const messages=Array.isArray(body.messages)?body.messages.slice(-12):[];
        const instruction=String(body.instruction||"").trim();

        if(!String(lead.name||"").trim()){
          return json({ok:false,error:"Lead information is missing."},400);
        }
        if(!String(business.name||business.description||business.offer||"").trim()){
          return json({ok:false,error:"Complete Business Information before using AI reply generation."},400);
        }

        const context={
          business:{
            name:business.name||"",type:business.type||"",description:business.description||"",
            offer:business.offer||"",target:business.target||"",market:business.market||"",
            problem:business.problem||"",difference:business.difference||"",goal:business.goal||"",
            tone:business.tone||"",rules:business.rules||""
          },
          lead:{
            name:lead.name||"",company:lead.company||"",interest:lead.interest||"",
            status:lead.status||"",notes:lead.notes||""
          },
          conversation:messages.map(m=>({direction:m.direction,text:m.text})),
          instruction
        };

        const aiRes=await fetch("https://api.openai.com/v1/responses",{
          method:"POST",
          headers:{"content-type":"application/json","authorization":"Bearer "+env.OPENAI_API_KEY},
          body:JSON.stringify({
            model:env.OPENAI_MODEL||"gpt-5.6-luna",
            input:[
              {
                role:"system",
                content:"You are ColdCloud's AI sales follow-up assistant. Write one natural WhatsApp reply for a business lead. Use only facts provided in the context. Never invent prices, discounts, guarantees, results, policies, credentials, availability, or product details. Do not pressure the lead. If the lead asks a question, answer only from the supplied facts; if the information is unavailable, say the business should confirm it. Keep the reply concise and human. Do not use markdown, quotation marks, or emojis unless the business rules explicitly request them."
              },
              {role:"user",content:"Generate the next WhatsApp reply for this lead. Return only the reply text.\n\nCONTEXT:\n"+JSON.stringify(context)}
            ],
            max_output_tokens:400,
            store:false
          })
        });
        const aiJson=await aiRes.json().catch(()=>({}));
        if(!aiRes.ok) return json({ok:false,error:aiJson?.error?.message||"AI reply generation failed."},502);
        const reply=String(aiJson.output_text||"").trim() ||
          String((aiJson.output||[]).flatMap(x=>x.content||[]).find(x=>x.type==="output_text")?.text||"").trim();
        if(!reply) return json({ok:false,error:"AI returned an empty reply."},502);
        return json({ok:true,model:env.OPENAI_MODEL||"gpt-5.6-luna",reply});
      }

      if (path[0] === "templates" && req.method === "GET") {
        if (!(await tableExists(env, "whatsapp_templates"))) return json({ ok: true, templates: [] });
        const rows = (await env.DB.prepare(
          "SELECT * FROM whatsapp_templates WHERE workspace_id=? ORDER BY created_at DESC"
        ).bind(workspace.id).all()).results || [];
        return json({ ok: true, templates: rows.map(t => ({
          id:t.id,name:t.name,category:t.category,language:t.language,body:t.body_text,
          use:t.use_type||"custom",useLabel:t.use_label||"Follow-up",
          providerId:t.provider_template_id||"",providerStatus:t.provider_status||"not_submitted",
          rejectionReason:t.rejection_reason||""
        }))});
      }

      if (path[0] === "templates" && path[1] && req.method === "DELETE") {
        if (!(await tableExists(env, "whatsapp_templates"))) return json({ok:false,error:"Template storage is not installed yet"},500);
        const existing=await env.DB.prepare(
          "SELECT * FROM whatsapp_templates WHERE id=? AND workspace_id=? LIMIT 1"
        ).bind(path[1],workspace.id).first();
        if(!existing)return json({ok:false,error:"Follow-up not found"},404);

        if(existing.provider_template_name){
          const connection=await env.DB.prepare(
            "SELECT * FROM whatsapp_connections WHERE workspace_id=? AND status='connected' LIMIT 1"
          ).bind(workspace.id).first();
          if(connection?.access_token_encrypted){
            try{
              const graphVersion=env.META_GRAPH_VERSION||"v25.0";
              const token=await decryptSecret(connection.access_token_encrypted,env.JWT_SECRET||env.META_APP_SECRET);
              const metaRes=await fetch(
                "https://graph.facebook.com/"+graphVersion+"/"+encodeURIComponent(connection.waba_id)+"/message_templates?name="+encodeURIComponent(existing.provider_template_name),
                {method:"DELETE",headers:{Authorization:"Bearer "+token}}
              );
              if(!metaRes.ok){
                const metaJson=await metaRes.json().catch(()=>({}));
                return json({ok:false,error:metaJson?.error?.message||"WhatsApp could not delete this approved follow-up."},400);
              }
            }catch(err){
              return json({ok:false,error:"Could not remove this follow-up from WhatsApp yet."},400);
            }
          }
        }

        await env.DB.prepare("DELETE FROM whatsapp_templates WHERE id=? AND workspace_id=?").bind(path[1],workspace.id).run();
        if(await tableExists(env,"sequence_steps")){
          try{await env.DB.prepare("UPDATE sequence_steps SET template_id=NULL WHERE template_id=?").bind(path[1]).run()}catch{}
        }
        return json({ok:true,deleted:true,id:path[1]});
      }

      if (path[0] === "templates" && req.method === "POST") {
        if (!(await tableExists(env, "whatsapp_templates"))) return json({ ok:false,error:"Template storage is not installed yet" },500);
        const body = await read(req);
        const name = String(body.name || "").trim();
        const message = String(body.body || "").trim();
        const category = String(body.category || "MARKETING").toUpperCase();
        const useType = String(body.use || "custom");
        const useLabel = String(body.useLabel || "Follow-up");
        if (!name || !message) return json({ ok:false,error:"Template name and message are required" },400);

        if (body.draft === true) {
          const id = uid();
          await insertDynamic(env,"whatsapp_templates",{
            id,workspace_id:workspace.id,name,category,language:"en_US",body_text:message,
            use_type:useType,use_label:useLabel,provider_template_id:null,
            provider_template_name:null,provider_status:"not_submitted",
            rejection_reason:null,created_at:now(),updated_at:now()
          });
          return json({ok:true,template:{id,name,category,language:"en_US",body:message,use:useType,useLabel,
            providerId:"",providerStatus:"not_submitted",rejectionReason:""}},201);
        }

        const connection = await env.DB.prepare(
          "SELECT * FROM whatsapp_connections WHERE workspace_id=? AND status='connected' LIMIT 1"
        ).bind(workspace.id).first();
        if (!connection?.access_token_encrypted) {
          return json({ ok:false,error:"Connect WhatsApp first. ColdCloud needs the connected business number to submit this follow-up." },400);
        }

        const graphVersion = env.META_GRAPH_VERSION || "v25.0";
        const token = await decryptSecret(connection.access_token_encrypted, env.JWT_SECRET || env.META_APP_SECRET);
        const providerName = name.toLowerCase().replace(/[^a-z0-9_]+/g,"_").replace(/^_+|_+$/g,"").slice(0,60) || ("coldcloud_followup_"+Date.now());

        const existingName = await env.DB.prepare(
          "SELECT id FROM whatsapp_templates WHERE workspace_id=? AND provider_template_name=? LIMIT 1"
        ).bind(workspace.id, providerName).first();
        if (existingName) return json({ok:false,error:"A WhatsApp template with this name already exists. Choose a different follow-up name."},409);

        const variableMap = {};
        let n = 0;
        const metaBody = message.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, key) => {
          if (!variableMap[key]) variableMap[key] = String(++n);
          return "{{"+variableMap[key]+"}}";
        });

        const payload = {
          name: providerName,
          language: "en_US",
          category: category === "UTILITY" ? "UTILITY" : "MARKETING",
          parameter_format: "POSITIONAL",
          components: [{ type:"BODY", text:metaBody }]
        };

        const metaRes = await fetch(
          "https://graph.facebook.com/" + graphVersion + "/" + encodeURIComponent(connection.waba_id) + "/message_templates",
          {
            method:"POST",
            headers:{"content-type":"application/json",Authorization:"Bearer "+token},
            body:JSON.stringify(payload)
          }
        );
        const metaJson = await metaRes.json().catch(()=>({}));
        if (!metaRes.ok || !metaJson.id) {
          return json({ok:false,error:metaJson?.error?.message || "WhatsApp could not accept this template yet."},400);
        }

        const id=uid();
        await insertDynamic(env,"whatsapp_templates",{
          id,workspace_id:workspace.id,name,category:payload.category,language:"en_US",body_text:message,
          use_type:useType,use_label:useLabel,provider_template_id:String(metaJson.id),
          provider_template_name:providerName,provider_status:String(metaJson.status||"PENDING").toLowerCase(),
          rejection_reason:null,created_at:now(),updated_at:now()
        });
        return json({ok:true,template:{id,name,category,language:"en_US",body:message,use:useType,useLabel,
          providerId:String(metaJson.id),providerStatus:String(metaJson.status||"PENDING").toLowerCase(),rejectionReason:""}},201);
      }

      if (path[0] === "templates" && path[1] && req.method === "POST" && path[2] === "submit") {
        if (!(await tableExists(env, "whatsapp_templates"))) return json({ok:false,error:"Template storage is not installed yet"},500);
        const existing = await env.DB.prepare(
          "SELECT * FROM whatsapp_templates WHERE id=? AND workspace_id=? LIMIT 1"
        ).bind(path[1],workspace.id).first();
        if (!existing) return json({ok:false,error:"Follow-up not found"},404);
        if (String(existing.provider_status||"").toLowerCase()==="approved") {
          return json({ok:true,template:{
            id:existing.id,name:existing.name,category:existing.category,language:existing.language,
            body:existing.body_text,use:existing.use_type,useLabel:existing.use_label,
            providerId:existing.provider_template_id||"",providerStatus:"approved",
            rejectionReason:existing.rejection_reason||""
          }});
        }

        const connection = await env.DB.prepare(
          "SELECT * FROM whatsapp_connections WHERE workspace_id=? AND status='connected' LIMIT 1"
        ).bind(workspace.id).first();
        if (!connection?.access_token_encrypted) {
          return json({ok:false,error:"Connect WhatsApp first. ColdCloud needs the connected business number to submit this follow-up."},400);
        }

        const graphVersion=env.META_GRAPH_VERSION||"v25.0";
        const token=await decryptSecret(connection.access_token_encrypted,env.JWT_SECRET||env.META_APP_SECRET);
        const providerName=(existing.provider_template_name ||
          existing.name.toLowerCase().replace(/[^a-z0-9_]+/g,"_").replace(/^_+|_+$/g,"").slice(0,60) ||
          ("coldcloud_followup_"+Date.now()));

        const variableMap={}; let n=0;
        const metaBody=String(existing.body_text||"").replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g,(_,key)=>{
          if(!variableMap[key])variableMap[key]=String(++n);
          return "{{"+variableMap[key]+"}}";
        });

        const payload={
          name:providerName,
          language:existing.language||"en_US",
          category:String(existing.category||"MARKETING").toUpperCase()==="UTILITY"?"UTILITY":"MARKETING",
          parameter_format:"POSITIONAL",
          components:[{type:"BODY",text:metaBody}]
        };

        const metaRes=await fetch(
          "https://graph.facebook.com/"+graphVersion+"/"+encodeURIComponent(connection.waba_id)+"/message_templates",
          {method:"POST",headers:{"content-type":"application/json",Authorization:"Bearer "+token},body:JSON.stringify(payload)}
        );
        const metaJson=await metaRes.json().catch(()=>({}));
        if(!metaRes.ok||!metaJson.id){
          return json({ok:false,error:metaJson?.error?.message||"WhatsApp could not accept this follow-up for approval."},400);
        }

        await updateDynamic(env,"whatsapp_templates",{
          provider_template_id:String(metaJson.id),
          provider_template_name:providerName,
          provider_status:String(metaJson.status||"PENDING").toLowerCase(),
          rejection_reason:null,
          updated_at:now()
        },"id=? AND workspace_id=?",[existing.id,workspace.id]);

        return json({ok:true,template:{
          id:existing.id,name:existing.name,category:payload.category,language:existing.language,
          body:existing.body_text,use:existing.use_type,useLabel:existing.use_label,
          providerId:String(metaJson.id),providerStatus:String(metaJson.status||"PENDING").toLowerCase(),
          rejectionReason:""
        }});
      }

      if (path[0] === "templates" && path[1] && req.method === "PATCH") {
        if (!(await tableExists(env, "whatsapp_templates"))) return json({ok:false,error:"Template storage is not installed yet"},500);
        const existing = await env.DB.prepare(
          "SELECT * FROM whatsapp_templates WHERE id=? AND workspace_id=? LIMIT 1"
        ).bind(path[1],workspace.id).first();
        if (!existing) return json({ok:false,error:"Template not found"},404);
        if (existing.provider_template_id && String(existing.provider_status).toLowerCase()==="approved") {
          return json({ok:false,error:"This follow-up is already approved by WhatsApp. Create a new follow-up instead of editing it."},400);
        }
        const body=await read(req);
        const name=String(body.name||existing.name).trim();
        const message=String(body.body||existing.body_text).trim();
        await updateDynamic(env,"whatsapp_templates",{
          name,body_text:message,category:String(body.category||existing.category).toUpperCase(),
          use_type:String(body.use||existing.use_type||"custom"),use_label:String(body.useLabel||existing.use_label||"Follow-up"),
          updated_at:now()
        },"id=? AND workspace_id=?",[path[1],workspace.id]);
        const row=await env.DB.prepare("SELECT * FROM whatsapp_templates WHERE id=?").bind(path[1]).first();
        return json({ok:true,template:{id:row.id,name:row.name,category:row.category,language:row.language,body:row.body_text,use:row.use_type,useLabel:row.use_label,providerId:row.provider_template_id||"",providerStatus:row.provider_status,rejectionReason:row.rejection_reason||""}});
      }

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

        let sequenceId = body.sequenceId || null;
        if (sequenceId && !(await getWorkspaceSequence(env, workspace.id, sequenceId))) {
          // During MVP/dev, stale browser localStorage can reference a sequence
          // that no longer exists in D1. Do not block lead creation for that.
          if (env.DEV_MODE === "true") {
            sequenceId = null;
          } else {
            return json({ ok: false, error: "Sequence not found in this workspace" }, 404);
          }
        }
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
          sequence_id: sequenceId,
          sequence_progress: 0,
          sequence_plan: sequenceId && body.sequencePlan ? JSON.stringify(body.sequencePlan) : "[]",
          next_follow_up_at: sequenceId && Array.isArray(body.sequencePlan) && body.sequencePlan.length
            ? new Date(Date.now() + Math.max(0, Number(body.sequencePlan[0]?.day || 0)) * 86400000).toISOString()
            : null,
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

        if (body.sequenceId && !(await getWorkspaceSequence(env, workspace.id, body.sequenceId))) {
          return json({ ok: false, error: "Sequence not found in this workspace" }, 404);
        }

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
          sequence_id: body.sequenceId === undefined ? undefined : (body.sequenceId || null),
          sequence_progress: body.sequenceProgress === undefined ? undefined : Number(body.sequenceProgress || 0),
          sequence_plan: body.sequencePlan === undefined ? undefined : JSON.stringify(body.sequencePlan || []),
          next_follow_up_at: body.sequencePlan !== undefined
            ? ((Array.isArray(body.sequencePlan) && body.sequencePlan.length && Number(body.sequenceProgress || 0) < body.sequencePlan.length)
                ? new Date(Date.now() + Math.max(0, Number(body.sequencePlan[Number(body.sequenceProgress || 0)]?.day || 0)) * 86400000).toISOString()
                : null)
            : undefined,
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

      if (path[0] === "automations" && path[1] && (req.method === "PATCH" || req.method === "DELETE")) {
        if (!(await tableExists(env, "automations"))) {
          return json({ ok: false, error: "Automations table is unavailable" }, 500);
        }

        const existing = await env.DB.prepare(
          "SELECT * FROM automations WHERE id=? AND workspace_id=? LIMIT 1"
        ).bind(path[1], workspace.id).first();

        if (!existing) return json({ ok: false, error: "Automation not found" }, 404);

        if (req.method === "DELETE") {
          if (existing.is_builtin) {
            return json({ ok: false, error: "Built-in automation cannot be deleted" }, 400);
          }
          await env.DB.prepare(
            "DELETE FROM automations WHERE id=? AND workspace_id=?"
          ).bind(path[1], workspace.id).run();
          return json({ ok: true });
        }

        const body = await read(req);
        const sequenceId = body.sequenceId === undefined ? existing.sequence_id : (body.sequenceId || null);

        if (sequenceId && !(await getWorkspaceSequence(env, workspace.id, sequenceId))) {
          return json({ ok: false, error: "Sequence not found in this workspace" }, 404);
        }

        await updateDynamic(env, "automations", {
          name: body.name,
          trigger_text: body.trigger,
          action_text: body.action,
          trigger: body.trigger,
          action: body.action,
          sequence_id: sequenceId,
          enabled: body.enabled === undefined ? undefined : (body.enabled ? 1 : 0),
          updated_at: now()
        }, "id=? AND workspace_id=?", [path[1], workspace.id]);

        const updated = await env.DB.prepare(
          "SELECT * FROM automations WHERE id=? AND workspace_id=? LIMIT 1"
        ).bind(path[1], workspace.id).first();

        return json({ ok: true, automation: updated });
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
      const detail = error?.message || String(error);
      return json({
        ok: false,
        error: env.DEV_MODE === "true" ? detail : "Server error"
      }, 500);
    }
  }
};