'use strict';
// Security regressions for 0.2.0: sessions, pairing approval, local API, quotas, rate limits.
const {test,before,after}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawn}=require('node:child_process');

const NATIVE='test-native-key-0123456789abcdef';
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ryadom-sec-'));
const port=15280+Math.floor(Math.random()*700);
const base=`http://127.0.0.1:${port}`;
let proc,logs='';

const env={...process.env,
 RYADOM_PORT:String(port),RYADOM_DATA:dir,RYADOM_NO_OPEN:'1',
 RYADOM_NATIVE_KEY:NATIVE,
 RYADOM_MSG_PER_MIN:'3',
 RYADOM_UPLOAD_PER_MIN:'30',
 RYADOM_MAX_TOTAL_MB:'1',
 RYADOM_MAX_DEVICE_MB:'1',
 RYADOM_PAIR_TTL_MS:'60000',
 RYADOM_PAIR_ATTEMPTS_PER_MIN:'100',
 RYADOM_ROLE_SIGNAL:path.join(dir,'role-signal')
};

async function start(){
 const command=process.env.RYADOM_TEST_JAVA||process.env.RYADOM_TEST_EXE||process.execPath;
 const args=process.env.RYADOM_TEST_JAVA?['-cp',process.env.RYADOM_TEST_CLASSPATH,'local.ryadom.chat.ServerHarness',path.resolve(__dirname,'../public')]:process.env.RYADOM_TEST_EXE?[]:[path.resolve(__dirname,'../server.cjs')];
 proc=spawn(command,args,{env,stdio:['ignore','pipe','pipe']});
 proc.stdout.on('data',x=>logs+=x);proc.stderr.on('data',x=>logs+=x);
 for(let i=0;i<120;i++){try{if((await fetch(`${base}/api/health`)).ok)return;}catch{}await new Promise(r=>setTimeout(r,60));}
 throw new Error(logs);
}
async function stop(){if(proc&&proc.exitCode===null){const end=new Promise(r=>proc.once('exit',r));proc.kill();await end;}}
before(start);after(async()=>{await stop();fs.rmSync(dir,{recursive:true,force:true});});

const jsonHeaders=c=>c?{Cookie:c}:{};
async function req(route,{method='GET',body,cookie,headers={},redirect}={}){
 const r=await fetch(base+route,{method,redirect,headers:{...jsonHeaders(cookie),...(method!=='GET'?{'X-Ryadom':'1','Content-Type':'application/json'}:{}),...headers},body:body===undefined?undefined:JSON.stringify(body)});
 let data=null;try{data=await r.json();}catch{}
 return {r,data};
}
async function hostToken(){
 const {r,data}=await req('/api/local/host-token',{method:'POST',headers:{'X-Ryadom-Native':NATIVE}});
 assert.equal(r.status,200,'host-token must be available to the native launcher: '+r.status);
 assert.match(data.token,/^[0-9a-f]{64}$/);
 return data.token;
}
async function login(){
 const token=await hostToken();
 const {r}=await req('/api/host-login',{method:'POST',body:{token}});
 assert.equal(r.status,200);
 return r.headers.get('set-cookie').split(';')[0];
}
async function pairingCode(host){
 const {data}=await req('/api/state',{cookie:host});
 return data.pairing.code;
}
async function pairRequest(host,name='Телефон'){
 const code=await pairingCode(host);
 const {r,data}=await req('/api/pair',{method:'POST',body:{name,code,protocol:4}});
 assert.equal(r.status,202,'pairing must wait for host approval');
 assert.equal(data.pending,true);
 return data.requestId;
}
async function approve(host,requestId){
 const {r}=await req('/api/host/pair/approve',{method:'POST',body:{requestId},cookie:host});
 assert.equal(r.status,200);
 const status=await fetch(`${base}/api/pair/status?requestId=${encodeURIComponent(requestId)}`);
 assert.equal(status.status,200);
 const cookie=status.headers.get('set-cookie').split(';')[0];
 return {cookie,data:await status.json()};
}
async function newDevice(host,name='Телефон'){
 const id=await pairRequest(host,name);
 return approve(host,id);
}

test('Локальный API требует native-ключ',async()=>{
 assert.equal((await req('/api/local/host-token',{method:'POST'})).r.status,403);
 assert.equal((await req('/api/local/status',{headers:{'X-Ryadom-Native':'wrong'}})).r.status,403);
 const ok=await req('/api/local/host-token',{method:'POST',headers:{'X-Ryadom-Native':NATIVE}});
 assert.equal(ok.r.status,200);
});

test('Одноразовый токен входа главного',async()=>{
 const token=await hostToken();
 const first=await req('/api/host-login',{method:'POST',body:{token}});
 assert.equal(first.r.status,200);
 const second=await req('/api/host-login',{method:'POST',body:{token}});
 assert.equal(second.r.status,403);
 const legacy=await req('/api/host-login',{method:'POST',body:{key:'ab'.repeat(32)}});
 assert.equal(legacy.r.status,403);
});

test('Спаривание требует подтверждения главного и код одноразовый',async()=>{
 const host=await login();
 const code=await pairingCode(host);
 const pending=await req('/api/pair',{method:'POST',body:{name:'Плохой',code,protocol:4}});
 assert.equal(pending.r.status,202);
 const reused=await req('/api/pair',{method:'POST',body:{name:'Ещё',code,protocol:4}});
 assert.equal(reused.r.status,403);
 const beforeApprove=await fetch(`${base}/api/pair/status?requestId=${pending.data.requestId}`);
 assert.equal(beforeApprove.status,202);
 const bad=await req('/api/host/pair/approve',{method:'POST',body:{requestId:'нет'},cookie:host});
 assert.equal(bad.r.status,404);
 const approved=await approve(host,pending.data.requestId);
 const state=await req('/api/state',{cookie:approved.cookie});
 assert.equal(state.r.status,200);
 assert.equal(state.data.me.name,'Плохой');
});

test('Выход отзывает серверную сессию',async()=>{
 const host=await login();
 const d=await newDevice(host);
 assert.equal((await req('/api/state',{cookie:d.cookie})).r.status,200);
 assert.equal((await req('/api/logout',{method:'POST',body:{},cookie:d.cookie})).r.status,200);
 assert.equal((await req('/api/state',{cookie:d.cookie})).r.status,401);
});

test('«Выйти на всех» ротирует сессии, сохраняя текущую',async()=>{
 const host=await login();
 const other=await newDevice(host,'Второй');
 const rotated=await req('/api/host/logout-all',{method:'POST',body:{},cookie:host});
 assert.equal(rotated.r.status,200);
 const fresh=rotated.r.headers.get('set-cookie').split(';')[0];
 assert.equal((await req('/api/state',{cookie:host})).r.status,401);
 assert.equal((await req('/api/state',{cookie:other.cookie})).r.status,401);
 assert.equal((await req('/api/state',{cookie:fresh})).r.status,200);
});

test('Журнал подключений доступен главному',async()=>{
 const host=await login();
 await newDevice(host,'Журнал');
 const {r,data}=await req('/api/host/events',{cookie:host});
 assert.equal(r.status,200);
 assert.ok(data.events.some(e=>e.type==='pair_request'));
 assert.ok(data.events.some(e=>e.type==='pair_approved'));
});

test('Ограничение частоты сообщений на устройство',async()=>{
 const host=await login();
 const d=await newDevice(host,'Флуд');
 for(let i=0;i<3;i++){
  const {r}=await req('/api/messages',{method:'POST',body:{text:'msg '+i,requestId:'flood-'+i},cookie:d.cookie});
  assert.equal(r.status,201);
 }
 const blocked=await req('/api/messages',{method:'POST',body:{text:'ещё',requestId:'flood-x'},cookie:d.cookie});
 assert.equal(blocked.r.status,429);
});

test('Квота хранилища не позволяет заполнить диск',async()=>{
 const host=await login();
 const d=await newDevice(host,'Файлы');
 const big=Buffer.alloc(700*1024,7);
 const first=await fetch(`${base}/api/files?name=a.bin&requestId=quota-1`,{method:'POST',headers:{Cookie:d.cookie,'X-Ryadom':'1','Content-Type':'application/octet-stream'},body:big});
 assert.equal(first.status,201);
 const second=await fetch(`${base}/api/files?name=b.bin&requestId=quota-2`,{method:'POST',headers:{Cookie:d.cookie,'X-Ryadom':'1','Content-Type':'application/octet-stream'},body:big});
 assert.equal(second.status,507);
});

test('Параллельные загрузки не обходят квоту',async()=>{
 const host=await login();
 const d=await newDevice(host,'Параллель');
 const body=Buffer.alloc(200*1024,3);
 const upload=n=>fetch(`${base}/api/files?name=p${n}.bin&requestId=par-${n}`,{method:'POST',headers:{Cookie:d.cookie,'X-Ryadom':'1','Content-Type':'application/octet-stream'},body});
 const results=await Promise.all([upload(1),upload(2)]);
 const statuses=results.map(r=>r.status).sort();
 assert.deepEqual(statuses,[201,507],'exactly one parallel upload must fit the remaining quota: '+statuses.join(','));
 const state=await req('/api/state',{cookie:host});
 assert.ok(state.data.storage.usedBytes<=1024*1024,'stored bytes must stay within the 1 MiB quota');
});

test('SSE закрывается при выходе устройства',async()=>{
 const host=await login();
 const d=await newDevice(host,'Поток');
 const controller=new AbortController();
 const stream=await fetch(`${base}/api/events`,{headers:{Cookie:d.cookie},signal:controller.signal});
 assert.equal(stream.status,200);
 const reader=stream.body.getReader();
 await reader.read();
 assert.equal((await req('/api/logout',{method:'POST',body:{},cookie:d.cookie})).r.status,200);
 const next=await Promise.race([reader.read(),new Promise(r=>setTimeout(()=>r({timeout:true}),2000))]);
 assert.ok(next.timeout!==true,'SSE must be closed after logout');
 const text=next.value?Buffer.from(next.value).toString('utf8'):'';
 assert.ok(next.done||text.includes('event: logout'),'closing event must be logout, got: '+text);
 controller.abort();
});

test('Выбор роли доступен сессии главного, но не без аутентификации',async()=>{
 const host=await login();
 const denied=await req('/api/local/choose-role',{method:'POST',body:{}});
 assert.equal(denied.r.status,403);
 const allowed=await req('/api/local/choose-role',{method:'POST',body:{},cookie:host});
 assert.equal(allowed.r.status,200);
 assert.equal(fs.readFileSync(env.RYADOM_ROLE_SIGNAL,'utf8'),'choose');
});
