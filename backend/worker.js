const CORS={"access-control-allow-origin":"*","access-control-allow-headers":"Content-Type, Authorization","access-control-allow-methods":"GET,POST,PATCH,PUT,DELETE,OPTIONS"};
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json",...CORS}});
const uid=()=>crypto.randomUUID(), now=()=>new Date().toISOString();
async function read(req){try{return await req.json()}catch{return {}}}
function b64u(s){return btoa(s).replace(/=/g,"").replace(/\\+/g,"-").replace(/\\//g,"_")}
function unb64(s){return atob(s.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((s.length+3)%4))}
async function jwt(payload,secret){
 const h=b64u(JSON.stringify({alg:"HS256",typ:"JWT"})),p=b64u(JSON.stringify(payload)),data=h+"."+p;
 const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const s=await crypto.subtle.sign("HMAC",k,new TextEncoder().encode(data));
 return data+"."+b64u(String.fromCharCode(...new Uint8Array(s)));
}
async function userFrom(req,env){
 const t=(req.headers.get("Authorization")||"").replace(/^Bearer /,"");if(!t)return null;
 try{const [h,p,s]=t.split("."),k=await crypto.subtle.importKey("raw",new TextEncoder().encode(env.JWT_SECRET),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
 const ok=await crypto.subtle.verify("HMAC",k,Uint8Array.from(unb64(s),c=>c.charCodeAt(0)),new TextEncoder().encode(h+"."+p));const x=JSON.parse(unb64(p));return ok&&x.exp>Date.now()/1000?x:null}catch{return null}
}
async function hash(password,salt=crypto.getRandomValues(new Uint8Array(16))){const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveBits"]);const b=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:120000,hash:"SHA-256"},k,256);return btoa(String.fromCharCode(...salt))+"."+btoa(String.fromCharCode(...new Uint8Array(b)))}
async function verify(password,v){try{const [a,b]=v.split("."),salt=Uint8Array.from(atob(a),c=>c.charCodeAt(0)),x=await hash(password,salt);return x.split(".")[1]===b}catch{return false}}
const out=r=>({...r,id:r.id,createdAt:r.created_at,updatedAt:r.updated_at,nextFollowUpAt:r.next_follow_up_at,sequenceId:r.sequence_id,sequenceProgress:r.sequence_progress});
async function defaults(env,userId){
 if(!(await env.DB.prepare("SELECT 1 FROM sequences WHERE user_id=? LIMIT 1").bind(userId).first())){
  const s=uid();await env.DB.prepare("INSERT INTO sequences VALUES(?,?,?,?,?,?)").bind(s,userId,"Cold Lead Recovery",1,now(),now()).run();
  for(const [i,d] of [0,2,5,9].entries())await env.DB.prepare("INSERT INTO sequence_steps VALUES(?,?,?,?,?,?,?,?)").bind(uid(),s,i+1,d,"WhatsApp",1,"",now()).run();
 }
 if(!(await env.DB.prepare("SELECT 1 FROM automations WHERE user_id=? LIMIT 1").bind(userId).first())){
  for(const x of [["New Lead → Start Sequence","New lead added","Start sequence"],["Lead Replies → Pause Sequence","Lead replies on WhatsApp","Pause sequence"],["No Reply → Continue Sequence","Lead does not reply","Continue sequence"],["Opt-out → Stop Automation","Lead says stop / opts out","Stop all follow-ups"],["Interested Lead → Mark Hot","Lead shows positive intent","Mark lead as hot"]])await env.DB.prepare("INSERT INTO automations VALUES(?,?,?,?,?,?,?,?,?)").bind(uid(),userId,x[0],x[1],x[2],null,1,1,now(),now()).run();
 }
}
export default{async fetch(req,env){
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:CORS});
 try{
  const u=new URL(req.url),p=u.pathname.replace(/^\/api\/?/,"").split("/").filter(Boolean);
  if(p.join("/")==="health")return json({ok:true,service:"coldcloud-api",database:true});
  if(p[0]==="auth"&&p[1]==="signup"&&req.method==="POST"){const b=await read(req),email=String(b.email||"").trim().toLowerCase();if(!b.name||!email||String(b.password||"").length<8)return json({ok:false,error:"Name, email and 8+ character password are required"},400);if(await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first())return json({ok:false,error:"Email already exists"},409);const id=uid(),t=now();await env.DB.prepare("INSERT INTO users VALUES(?,?,?,?,?,?,?)").bind(id,email,await hash(b.password),String(b.name).trim(),b.company||"",t,t).run();await defaults(env,id);return json({ok:true,token:await jwt({sub:id,email,exp:Date.now()/1000+604800},env.JWT_SECRET),user:{id,email,name:b.name,company:b.company||""}},201)}
  if(p[0]==="auth"&&p[1]==="login"&&req.method==="POST"){const b=await read(req),email=String(b.email||"").trim().toLowerCase(),x=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!x||!(await verify(b.password||"",x.password_hash)))return json({ok:false,error:"Incorrect email or password"},401);return json({ok:true,token:await jwt({sub:x.id,email:x.email,exp:Date.now()/1000+604800},env.JWT_SECRET),user:{id:x.id,email:x.email,name:x.name,company:x.company||""}})}
  const me=await userFrom(req,env);if(!me)return json({ok:false,error:"Unauthorized"},401);await defaults(env,me.sub);
  if(p[0]==="me")return json({ok:true,user:await env.DB.prepare("SELECT id,email,name,company FROM users WHERE id=?").bind(me.sub).first()});
  if(p[0]==="business"&&req.method==="GET")return json({ok:true,businessInfo:await env.DB.prepare("SELECT * FROM business_profiles WHERE user_id=?").bind(me.sub).first()});
  if(p[0]==="business"&&req.method==="PUT"){const b=await read(req),cols=["name","type","description","offer","target","market","problem","difference","goal","tone","rules","extra"],vals=cols.map(k=>b[k]||"");await env.DB.prepare("INSERT INTO business_profiles(user_id,"+cols.join(",")+",updated_at) VALUES(?,"+cols.map(()=>"?").join(",")+",?) ON CONFLICT(user_id) DO UPDATE SET "+cols.map(k=>k+"=excluded."+k).join(",")+",updated_at=excluded.updated_at").bind(me.sub,...vals,now()).run();return json({ok:true})}
  if(p[0]==="leads"&&req.method==="GET")return json({ok:true,leads:(await env.DB.prepare("SELECT * FROM leads WHERE user_id=? ORDER BY created_at DESC").bind(me.sub).all()).results.map(out)});
  if(p[0]==="leads"&&req.method==="POST"){const b=await read(req),phone=String(b.phone||"").replace(/[\\s\\-()]/g,"");if(!b.firstName||!/^[+0-9]{7,15}$/.test(phone))return json({ok:false,error:"First name and valid phone are required"},400);if(await env.DB.prepare("SELECT id FROM leads WHERE user_id=? AND phone=?").bind(me.sub,phone).first())return json({ok:false,error:"Lead already exists"},409);const seq=b.sequenceId||(await env.DB.prepare("SELECT id FROM sequences WHERE user_id=? AND is_builtin=1").bind(me.sub).first())?.id||null,id=uid(),t=now();await env.DB.prepare("INSERT INTO leads(id,user_id,first_name,last_name,phone,email,company,business_type,source,interest,notes,status,sequence_id,sequence_progress,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id,me.sub,b.firstName,b.lastName||"",phone,b.email||"",b.company||"",b.businessType||"",b.source||"",b.interest||"",b.notes||"","new",seq,0,t,t).run();await env.DB.prepare("INSERT INTO activities VALUES(?,?,?,?,?)").bind(uid(),me.sub,id,"Lead added: "+b.firstName,t).run();return json({ok:true,lead:out(await env.DB.prepare("SELECT * FROM leads WHERE id=?").bind(id).first())},201)}
  if(p[0]==="leads"&&p[1]&&req.method==="GET"){const x=await env.DB.prepare("SELECT * FROM leads WHERE id=? AND user_id=?").bind(p[1],me.sub).first();return x?json({ok:true,lead:out(x)}):json({ok:false,error:"Lead not found"},404)}
  if(p[0]==="leads"&&p[1]&&req.method==="PATCH"){const b=await read(req),allowed=["first_name","last_name","phone","email","company","business_type","source","interest","notes","status","sequence_id","sequence_progress"],sets=[],vals=[];for(const k of allowed)if(b[k]!==undefined){sets.push(k+"=?");vals.push(b[k])}if(!sets.length)return json({ok:false,error:"No changes"},400);sets.push("updated_at=?");vals.push(now(),p[1],me.sub);await env.DB.prepare("UPDATE leads SET "+sets.join(",")+" WHERE id=? AND user_id=?").bind(...vals).run();return json({ok:true,lead:out(await env.DB.prepare("SELECT * FROM leads WHERE id=? AND user_id=?").bind(p[1],me.sub).first())})}
  if(p[0]==="leads"&&p[1]&&req.method==="DELETE"){await env.DB.prepare("DELETE FROM leads WHERE id=? AND user_id=?").bind(p[1],me.sub).run();return json({ok:true})}
  if(p[0]==="sequences"&&req.method==="GET"){const r=(await env.DB.prepare("SELECT * FROM sequences WHERE user_id=? ORDER BY is_builtin DESC,created_at").bind(me.sub).all()).results;for(const s of r)s.steps=(await env.DB.prepare("SELECT * FROM sequence_steps WHERE sequence_id=? ORDER BY position").bind(s.id).all()).results;return json({ok:true,sequences:r})}
  if(p[0]==="sequences"&&req.method==="POST"){const b=await read(req),id=uid(),t=now();await env.DB.prepare("INSERT INTO sequences VALUES(?,?,?,?,?,?)").bind(id,me.sub,b.name||"New Sequence",0,t,t).run();for(const [i,s] of (b.steps||[]).entries())await env.DB.prepare("INSERT INTO sequence_steps VALUES(?,?,?,?,?,?,?,?)").bind(uid(),id,i+1,Number(s.day)||0,"WhatsApp",s.enabled===false?0:1,s.aiInstructions||"",t).run();return json({ok:true,id},201)}
  if(p[0]==="automations"&&req.method==="GET")return json({ok:true,automations:(await env.DB.prepare("SELECT * FROM automations WHERE user_id=? ORDER BY is_builtin DESC,created_at").bind(me.sub).all()).results});
  if(p[0]==="automations"&&req.method==="POST"){const b=await read(req),id=uid(),t=now();await env.DB.prepare("INSERT INTO automations VALUES(?,?,?,?,?,?,?,?,?)").bind(id,me.sub,b.name||"New Automation",b.trigger||"",b.action||"",b.sequenceId||null,b.enabled===false?0:1,0,t,t).run();return json({ok:true,id},201)}
  if(p[0]==="activity"&&req.method==="GET")return json({ok:true,activities:(await env.DB.prepare("SELECT * FROM activities WHERE user_id=? ORDER BY created_at DESC LIMIT 200").bind(me.sub).all()).results});
  return json({ok:false,error:"Not found"},404);
 }catch(e){console.error(e);return json({ok:false,error:"Server error"},500)}
}};
