'use strict';
const {test,before,after}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawn}=require('node:child_process');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ryadom-test-'));
const port=14280+Math.floor(Math.random()*1000);
const base=`http://127.0.0.1:${port}`;
const nativeKey='server-test-native-key';
let proc,host='',client='',clientId='',fileId='',logs='';

async function start(){
 const command=process.env.RYADOM_TEST_JAVA||process.env.RYADOM_TEST_EXE||process.execPath;
 const args=process.env.RYADOM_TEST_JAVA?['-cp',process.env.RYADOM_TEST_CLASSPATH,'local.ryadom.chat.ServerHarness',path.resolve(__dirname,'../public')]:process.env.RYADOM_TEST_EXE?[]:[path.resolve(__dirname,'../server.cjs')];
 proc=spawn(command,args,{env:{...process.env,RYADOM_PORT:String(port),RYADOM_DATA:dir,RYADOM_NO_OPEN:'1',RYADOM_NATIVE_KEY:nativeKey,RYADOM_MSG_PER_MIN:'1000',RYADOM_UPLOAD_PER_MIN:'1000'},stdio:['ignore','pipe','pipe']});
 proc.stdout.on('data',x=>logs+=x);proc.stderr.on('data',x=>logs+=x);
 for(let i=0;i<120;i++){try{if((await fetch(`${base}/api/health`)).ok)return;}catch{}await new Promise(r=>setTimeout(r,60));}
 throw new Error(logs);
}
async function stop(){if(proc&&proc.exitCode===null){const end=new Promise(r=>proc.once('exit',r));proc.kill();await end;}}
async function call(route,method='GET',body,cookie=host,headers={}){
 const r=await fetch(base+route,{method,headers:{...(cookie?{Cookie:cookie}:{}),...(method!=='GET'?{'X-Ryadom':'1','Content-Type':'application/json'}:{}),...headers},body:body===undefined?undefined:JSON.stringify(body)});
 let data=null;try{data=await r.json();}catch{}
 return {r,data};
}
async function hostToken(){
 const {r,data}=await call('/api/local/host-token','POST',undefined,'',{'X-Ryadom-Native':nativeKey});
 assert.equal(r.status,200,logs);
 return data.token;
}
async function loginHost(){
 const token=await hostToken();
 const {r}=await call('/api/host-login','POST',{token},'');
 assert.equal(r.status,200,logs);
 return r.headers.get('set-cookie').split(';')[0];
}
async function pairingCode(cookie){
 const {data}=await call('/api/state','GET',undefined,cookie);
 return data.pairing.code;
}
async function pairDevice(cookie,name,customCode){
 const code=customCode||await pairingCode(cookie);
 const pending=await call('/api/pair','POST',{name,code},'');
 assert.equal(pending.r.status,202,JSON.stringify(pending.data)+logs);
 const approve=await call('/api/host/pair/approve','POST',{requestId:pending.data.requestId},cookie);
 assert.equal(approve.r.status,200,JSON.stringify(approve.data)+logs);
 const status=await fetch(`${base}/api/pair/status?requestId=${encodeURIComponent(pending.data.requestId)}`);
 assert.equal(status.status,200,logs);
 return {cookie:status.headers.get('set-cookie').split(';')[0],device:await status.json()};
}
before(async()=>{await start();host=await loginHost();});
after(async()=>{await stop();fs.rmSync(dir,{recursive:true,force:true});});

test('Protocol 4 exposes the session chat revision',async()=>{
 const health=await fetch(`${base}/api/health`);
 const h=await health.json();
 assert.equal(h.protocol,4);
 const {r,data}=await call('/api/state','GET',undefined,host);
 assert.equal(r.status,200);
 assert.equal(data.chat.id,'legacy');
 assert.equal(typeof data.chat.revision,'number');
 assert.equal(typeof data.chat.deletionRevision,'number');
 assert.equal(typeof data.chat.epoch,'number');
 assert.equal(typeof data.chat.sessionId,'string');
 assert.equal(typeof data.chat.term,'number');
 assert.equal(typeof data.chat.hostDeviceId,'string');
 assert.equal(data.server.protocol,4);
});

test('Private chat end-to-end',async t=>{
 await t.test('Reject unauthenticated reads and protect host login',async()=>{
  assert.equal((await call('/api/state','GET',undefined,'')).r.status,401);
  assert.equal((await call('/api/host-login','POST',{key:'incorrect'},'')).r.status,403);
  const token=await hostToken();
  const x=await call('/api/host-login','POST',{token},'');
  assert.equal(x.r.status,200);
  assert.equal(x.data.device.host,true);
 });
 await t.test('Reject cross-origin requests and DNS rebinding',async()=>{
  assert.equal((await call('/api/state','GET',undefined,host,{Origin:'https://evil.example'})).r.status,403);
  const status=await new Promise((resolve,reject)=>{require('node:http').get(base+'/api/state',{headers:{Host:'evil.example',Cookie:host}},r=>{r.resume();resolve(r.statusCode);}).on('error',reject);});
  assert.equal(status,403);
  const r=await fetch(base+'/api/messages',{method:'POST',headers:{Cookie:host,'Content-Type':'application/json'},body:'{"text":"bad"}'});
  assert.equal(r.status,403);
 });
 await t.test('Pair a second device with host approval and hide owner controls',async()=>{
  const state=(await call('/api/state')).data;
  assert.ok(state.pairing.code);
  assert.equal((await call('/api/pair','POST',{name:'Android',code:'00000000'},'')).r.status,403);
  const pending=await call('/api/pair','POST',{name:'Мой Android',code:state.pairing.code},'');
  assert.equal(pending.r.status,202);
  assert.equal((await call('/api/state','GET',undefined,'')).r.status,401);
  const approved=await call('/api/host/pair/approve','POST',{requestId:pending.data.requestId});
  assert.equal(approved.r.status,200);
  const status=await fetch(`${base}/api/pair/status?requestId=${encodeURIComponent(pending.data.requestId)}`);
  assert.equal(status.status,200);
  client=status.headers.get('set-cookie').split(';')[0];
  const s=(await call('/api/state','GET',undefined,client)).data;
  assert.equal(s.pairing,undefined);
  assert.equal(s.devices.length,2);
  clientId=s.me.id;
  assert.equal((await call('/api/host/pairing','POST',{},client)).r.status,403);
 });
 await t.test('Deliver text live to both devices and deduplicate retries',async()=>{
  const abort=new AbortController();
  const res=await fetch(base+'/api/events',{headers:{Cookie:client},signal:abort.signal});
  const reader=res.body.getReader();
  const a=await call('/api/messages','POST',{text:'Привет, телефон! <script>alert(1)</script>',requestId:'test-1'});
  const b=await call('/api/messages','POST',{text:'Повтор',requestId:'test-1'});
  assert.equal(a.r.status,201);assert.equal(a.data.id,b.data.id);
  let s='';for(let i=0;i<10&&!s.includes('Привет');i++){const item=await reader.read();s+=new TextDecoder().decode(item.value);}
  assert.match(s,/event: message/);assert.match(s,/Привет/);abort.abort();
  const x=await call('/api/messages','POST',{text:'Получено',requestId:'test-2'},client);
  assert.equal(x.data.deviceId,clientId);
 });
 await t.test('Upload real PNG bytes, preserve filename and serve authenticated ranges',async()=>{
  const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jWZkAAAAASUVORK5CYII=','base64');
  const r=await fetch(base+'/api/files?name='+encodeURIComponent('Фото кота.png')+'&requestId=photo-1',{method:'POST',headers:{Cookie:client,'X-Ryadom':'1','Content-Type':'application/octet-stream'},body:png});
  assert.equal(r.status,201);
  const m=await r.json();assert.equal(m.file.mime,'image/png');assert.equal(m.file.name,'Фото кота.png');fileId=m.file.id;
  assert.equal((await fetch(base+'/files/'+fileId)).status,401);
  const download=await fetch(base+'/files/'+fileId,{headers:{Cookie:host}});assert.deepEqual(Buffer.from(await download.arrayBuffer()),png);
  const part=await fetch(base+'/files/'+fileId,{headers:{Cookie:host,Range:'bytes=8-15'}});assert.equal(part.status,206);assert.deepEqual(Buffer.from(await part.arrayBuffer()),png.subarray(8,16));
  const suffix=await fetch(base+'/files/'+fileId,{headers:{Cookie:host,Range:'bytes=-5'}});assert.deepEqual(Buffer.from(await suffix.arrayBuffer()),png.subarray(-5));
  const invalid=await fetch(base+'/files/'+fileId,{headers:{Cookie:host,Range:'bytes=999-'}});assert.equal(invalid.status,416);
 });
 await t.test('Recognize video, preserve binary data and force unknown types to download',async()=>{
  for(const [name,bytes,mime] of [['clip.mp4',Buffer.concat([Buffer.from([0,0,0,24]),Buffer.from('ftypisom'),Buffer.alloc(256)]),'video/mp4'],['page.svg',Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),'application/octet-stream']]){
   const r=await fetch(base+'/api/files?name='+encodeURIComponent(name),{method:'POST',headers:{Cookie:client,'X-Ryadom':'1'},body:bytes});
   assert.equal(r.status,201);const m=await r.json();assert.equal(m.file.mime,mime);
   const download=await fetch(base+'/files/'+m.file.id,{headers:{Cookie:host}});assert.deepEqual(Buffer.from(await download.arrayBuffer()),bytes);
   if(mime==='application/octet-stream')assert.match(download.headers.get('content-disposition'),/^attachment/);
  }
 });
 await t.test('Reject empty and excessive messages and empty files',async()=>{
  assert.equal((await call('/api/messages','POST',{text:''})).r.status,400);
  assert.equal((await call('/api/messages','POST',{text:'x'.repeat(12001)})).r.status,400);
  const r=await fetch(base+'/api/files?name=empty',{method:'POST',headers:{Cookie:client,'X-Ryadom':'1'},body:Buffer.alloc(0)});assert.equal(r.status,413);
 });
 await t.test('Catch up more than 100 messages after a disconnection',async()=>{
  const from=(await call('/api/state')).data.messages.at(-1).seq;
  for(let i=0;i<105;i++)await call('/api/messages','POST',{text:`Сообщение ${i}`,requestId:`batch-${i}`},client);
  const first=(await call(`/api/messages?after=${from}`)).data;assert.equal(first.length,100);assert.equal(first[0].seq,from+1);
  const second=(await call(`/api/messages?after=${first.at(-1).seq}`)).data;assert.equal(second.length,5);
  const older=(await call(`/api/messages?before=${first[0].seq}`)).data;assert.equal(older.at(-1).seq,from);
 });
 await t.test('Clear history on restart but preserve device and session',async()=>{
  const before=(await call('/api/state')).data;
  assert.ok(before.chat.sessionId);
  await stop();await start();
  const s=(await call('/api/state','GET',undefined,client)).data;
  assert.equal(s.total,0);assert.equal(s.me.id,clientId);
  assert.notEqual(s.chat.sessionId,before.chat.sessionId);
  assert.equal((await fetch(base+'/files/'+fileId,{headers:{Cookie:host}})).status,404);
 });
 await t.test('Close pairing and revoke device access',async()=>{
  await call('/api/host/pairing','POST',{enabled:false});
  assert.equal((await call('/api/pair','POST',{name:'test',code:'12345678'},'')).r.status,403);
  assert.equal((await call(`/api/host/devices/${clientId}`,'DELETE',{})).r.status,200);
  assert.equal((await call('/api/state','GET',undefined,client)).r.status,401);
  assert.equal((await fetch(base+'/files/'+fileId,{headers:{Cookie:client}})).status,401);
  assert.equal((await call('/api/state')).data.devices.length,1);
 });
});
