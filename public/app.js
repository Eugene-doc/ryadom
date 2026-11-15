'use strict';
const $ = id => document.getElementById(id);
const icon = name => { const s=document.createElementNS('http://www.w3.org/2000/svg','svg');const u=document.createElementNS(s.namespaceURI,'use');u.setAttribute('href',`#i-${name}`);s.append(u);return s; };
const el = (tag,cls,text) => {const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;};
let me=null, devices=[], messages=new Map(), chat=null, deleteTarget=null, clearRevision=0, clearOperationId=null, stateGeneration=0, pairing=null, addresses=[], maxFile=512*1024*1024, events=null, online=false, filter='all', queue=[], sending=false, canLoadOlder=false, expiryTimer=null, toastTimer=null, syncing=false, pendingRequests=[], fingerprint='', storage=null, tlsEnabled=false;
const uuid=()=>{if(crypto.randomUUID)return crypto.randomUUID();const b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;return [...b].map((v,i)=>([4,6,8,10].includes(i)?'-':'')+v.toString(16).padStart(2,'0')).join('');};
const sizeText=n=>n<1024?`${n} Б`:n<1024*1024?`${(n/1024).toFixed(0)} КБ`:`${(n/1024/1024).toFixed(n<10*1024*1024?1:0)} МБ`;
function toast(text){$('toast').textContent=text;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,4500);}
async function api(route,method='GET',body){
 const r=await fetch(route,{method,headers:method==='GET'?{}:{'Content-Type':'application/json','X-Ryadom':'1'},body:body===undefined?undefined:JSON.stringify(body)});
 const data=await r.json();if(!r.ok){const e=new Error(data.error||'Не удалось выполнить действие');e.status=r.status;throw e;}return data;
}
async function copy(text){try{if(navigator.clipboard&&window.isSecureContext)await navigator.clipboard.writeText(text);else{const input=el('textarea');input.value=text;input.className='copy-helper';(document.querySelector('dialog[open]')||document.body).append(input);input.select();const ok=document.execCommand('copy');input.remove();if(!ok)throw new Error();}toast('Скопировано');}catch{toast('Не удалось скопировать. Выделите текст вручную.');}}
function showJoin(){events?.close();events=null;me=null;chat=null;messages.clear();queue=[];pendingRequests=[];fingerprint='';storage=null;$('join-pending').hidden=true;$('join-error').textContent='';$('app').hidden=true;$('join-screen').hidden=false;$('device-name').value=/Android/i.test(navigator.userAgent)?'Мой Android':/iPhone|iPad/i.test(navigator.userAgent)?'Мой iPhone':'Мой ноутбук';if($('settings-dialog').open)$('settings-dialog').close();}
function showUpdate(){events?.close();events=null;me=null;$('app').hidden=true;$('join-screen').hidden=false;$('join-error').textContent='Версия главного устройства несовместима. Обновите Рядом на всех устройствах.';}
function applyState(data,generation=stateGeneration){
 if(generation!==stateGeneration)return;
 if(data.server&&data.server.protocol!==undefined&&data.server.protocol!==3){showUpdate();return;}
 me=data.me;devices=data.devices;pairing=data.pairing;addresses=data.server.addresses;pendingRequests=data.pendingRequests||[];fingerprint=data.server.fingerprint||'';tlsEnabled=!!data.server.tls;storage=data.storage||null;
 const incoming=data.chat||{id:'legacy',revision:0,deletionRevision:0,epoch:0};
 if(chat&&(incoming.revision<chat.revision||(incoming.deletionRevision??0)<(chat.deletionRevision??0)))return;
 const reset=chat&&(chat.id!==incoming.id||(chat.deletionRevision??0)!==(incoming.deletionRevision??0)||chat.epoch!==incoming.epoch);chat=incoming;
 if(reset){messages.clear();canLoadOlder=false;stateGeneration++;}
 $('change-role-button').hidden=!data.server.localControls;maxFile=data.maxFile;data.messages.forEach(m=>messages.set(m.id,m));canLoadOlder=data.total>messages.size;$('app').hidden=false;$('join-screen').hidden=true;
 $('app-version').textContent=`Приложение ${(typeof window.ryadom?.appVersion==='function'?window.ryadom.appVersion():window.ryadom?.appVersion)||'—'} · главное ${data.server.version||'—'}`;
 renderDevices();renderMessages();renderPending();updateButtons();
}
async function sync(){
 if(syncing||!me)return;syncing=true;const generation=stateGeneration;
 try{
  const last=Math.max(0,...[...messages.values()].map(m=>m.seq));
  if(last){let cursor=last;while(true){const page=await api(`/api/messages?after=${cursor}`);if(generation!==stateGeneration)return;page.forEach(m=>messages.set(m.id,m));if(page.length<100)break;cursor=page[page.length-1].seq;}}
  const data=await api('/api/state');if(generation!==stateGeneration)return;applyState(data,generation);
 }catch(e){if(e.status===401){showJoin();toast('Подключите устройство заново');}}finally{syncing=false;}
}
function connectEvents(){
 events?.close();events=new EventSource('/api/events');
 events.onopen=()=>{online=true;renderConnection();sync();};
 events.onerror=()=>{online=false;renderConnection();sync();};
 events.addEventListener('message',e=>{const m=JSON.parse(e.data);if(chat&&((typeof m.revision==='number'&&m.revision<chat.revision)||(typeof m.epoch==='number'&&m.epoch<chat.epoch)))return;stateGeneration++;if(chat)chat.revision=Math.max(chat.revision??0,m.revision??0);messages.set(m.id,m);renderMessages(m.deviceId===me?.id);});
 events.addEventListener('message_deleted',e=>{const d=JSON.parse(e.data);if(chat&&(d.deletionRevision??0)<(chat.deletionRevision??0))return;stateGeneration++;const old=messages.get(d.id);messages.delete(d.id);if(chat){chat.revision=Math.max(chat.revision??0,d.revision??0);chat.deletionRevision=Math.max(chat.deletionRevision??0,d.deletionRevision??0);}if(old?.file&&$('full-image').src.includes(old.file.id)&&$('image-dialog').open)$('image-dialog').close();const node=$('messages').querySelector(`[data-key="${CSS.escape(d.id)}"]`);node?.remove();renderMessages();});
 events.addEventListener('chat_cleared',e=>{const d=JSON.parse(e.data);if(chat&&((d.epoch??0)<chat.epoch||(d.revision??0)<chat.revision))return;stateGeneration++;messages.clear();canLoadOlder=false;chat={...(chat||{id:'legacy'}),revision:Math.max(chat?.revision??0,d.revision??0),deletionRevision:Math.max(chat?.deletionRevision??0,d.deletionRevision??0),epoch:d.epoch??chat?.epoch??0};clearOperationId=null;if($('clear-dialog').open)$('clear-dialog').close();if($('image-dialog').open)$('image-dialog').close();renderMessages(true);toast(d.cleanupPending?'Чат очищен, но некоторые файлы остались на диске. Повторите очистку позже.':'Чат и файлы очищены');});
 events.addEventListener('devices',e=>{devices=JSON.parse(e.data);renderDevices();});
 events.addEventListener('pair_request',e=>{if(me?.host){sync();toast('Новый запрос на подключение');if(!$('settings-dialog').open)openSettings();}});
 events.addEventListener('pairing',()=>{if(me?.host)sync();});
 events.addEventListener('pair_decided',()=>{if(me?.host)sync();});
 events.addEventListener('revoked',()=>{showJoin();toast('Доступ устройства отозван на главном устройстве');});
}
function renderConnection(){
 $('connection-dot').className=`status-dot ${online?'online':'offline'}`;
 const n=devices.filter(d=>d.online).length;
 $('connection-text').textContent=online?`${n} ${n===1?'устройство':n<5?'устройства':'устройств'} в сети`:'Нет связи с компьютером';
 $('connection-banner').hidden=online;updateButtons();
}
function deviceIcon(d){if(/android|телефон|iphone|pixel|galaxy/i.test(d.name))return 'phone';return d.host||/компьютер|ноутбук|pc|mac|desktop/i.test(d.name)?'monitor':'phone';}
function renderDevices(){
 if(!me)return;const current=devices.find(d=>d.id===me.id);if(current)me.name=current.name;
 $('device-count').textContent=devices.length;$('settings-count').textContent=devices.length;
 $('profile-name').textContent=me.name;$('profile-initial').textContent=me.name.slice(0,1).toUpperCase();
 const list=$('device-list');const settings=$('settings-devices');list.replaceChildren();settings.replaceChildren();
 for(const d of devices){
  const row=el('div','device-row');row.append(icon(deviceIcon(d)));const detail=el('div','device-detail');detail.append(el('strong','',d.name));const small=el('small');small.append(el('span',`small-dot ${d.online?'online':''}`),document.createTextNode(d.id===me.id?'Это устройство':d.online?'В сети':'Не в сети'));detail.append(small);row.append(detail);list.append(row);
  const item=el('div','settings-device');item.append(icon(deviceIcon(d)));const info=el('div','device-detail');info.append(el('strong','',d.name),el('small','',`${d.host?'Главное устройство':d.online?'В сети':'Не в сети'}${d.id===me.id?' · Вы':''}`));item.append(info);
  if(me.host&&!d.host){const b=el('button','revoke','Отключить');b.type='button';b.onclick=async()=>{if(!confirm(`Отозвать доступ устройства «${d.name}»? Для нового входа понадобится код.`))return;try{await api(`/api/host/devices/${d.id}`,'DELETE');toast('Доступ отозван');await sync();}catch(e){toast(e.message);}};item.append(b);}settings.append(item);
 }
 $('sidebar-connect').hidden=!me.host;$('connect-button').hidden=!me.host;renderConnection();
}
function renderMessages(forceBottom=false){
 const area=$('scroll-area');const atBottom=area.scrollHeight-area.scrollTop-area.clientHeight<100;const all=[...messages.values()].sort((a,b)=>a.seq-b.seq);const query=$('search').value.trim().toLocaleLowerCase('ru');
 const shown=all.filter(m=>(filter!=='media'||m.file&&/^(image|video)\//.test(m.file.mime))&&(!query||`${m.text} ${m.file?.name||''} ${m.deviceName}`.toLocaleLowerCase('ru').includes(query)));
 $('empty').hidden=all.length>0||!!query||filter==='media';$('no-results').hidden=shown.length>0||!$('empty').hidden;$('no-results').textContent=filter==='media'&&!query?'Здесь появятся ваши фото и видео':'Ничего не найдено среди загруженных сообщений';$('load-older').hidden=!canLoadOlder;
 const target=$('messages');const existing=new Map([...target.children].map(n=>[n.dataset.key,n]));const desired=[];let day='';
 for(const m of shown){const date=new Date(m.created);const label=date.toLocaleDateString('ru-RU',{day:'numeric',month:'long',year:date.getFullYear()===new Date().getFullYear()?undefined:'numeric'});if(day!==label){const key=`day-${m.seq}`;const node=existing.get(key)||el('div','day-label',label);node.dataset.key=key;desired.push(node);day=label;}const node=existing.get(m.id)||renderMessage(m);node.dataset.key=m.id;desired.push(node);}
 const keep=new Set(desired);for(const child of [...target.children])if(!keep.has(child))child.remove();desired.forEach((node,i)=>{if(target.children[i]!==node)target.insertBefore(node,target.children[i]||null);});if(atBottom||forceBottom)area.scrollTop=area.scrollHeight;
}
function renderMessage(m){
 const own=m.deviceId===me?.id;const row=el('article',`message-row ${own?'own':''}`);row.dataset.id=m.id;row.append(el('span','message-avatar',m.deviceName.slice(0,1).toUpperCase()));const content=el('div','message-content');content.append(el('div','message-author',own?'Вы':m.deviceName));const bubble=el('div','bubble');
 if(m.text)bubble.append(el('p','message-text',m.text));
 if(m.file){const f=m.file;const url=`/files/${f.id}`;
  if(f.mime.startsWith('image/')){const b=el('button','media-button');b.type='button';b.setAttribute('aria-label',`Открыть ${f.name}`);const img=el('img','media-preview');img.src=url;img.alt=f.name;img.loading='lazy';b.append(img);b.onclick=()=>{$('full-image').src=url;$('full-image').alt=f.name;$('full-image-download').href=`${url}?download`;$('full-image-download').download=f.name;$('image-dialog').showModal();};bubble.append(b);}
  if(f.mime.startsWith('video/')){const video=el('video','media-preview');video.controls=true;video.preload='metadata';video.playsInline=true;video.src=url;video.setAttribute('aria-label',f.name);bubble.append(video);}
  const detail=el('div','file-details');if(f.mime==='application/octet-stream'){const i=el('span','file-icon');i.append(icon('file'));detail.append(i);}const info=el('div','file-info');info.append(el('div','file-name',f.name),el('div','file-size',`${sizeText(f.size)} · Оригинал`));const download=el('a','file-download');download.href=`${url}?download`;download.download=f.name;download.title='Скачать оригинал';download.setAttribute('aria-label',`Скачать ${f.name}`);download.append(icon('download'));detail.append(info,download);bubble.append(detail);
 }
 const footer=el('div','message-footer');if(m.text){const c=el('button','message-copy');c.title='Скопировать текст';c.setAttribute('aria-label','Скопировать текст');c.append(icon('copy'));c.onclick=()=>copy(m.text);footer.append(c);}if(own||me?.host){const d=el('button','message-delete');d.title='Удалить сообщение';d.setAttribute('aria-label','Удалить сообщение');d.append(icon('trash'));d.onclick=()=>openDeleteDialog(m);footer.append(d);}const time=el('time','',new Date(m.created).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}));time.dateTime=m.created;footer.append(time);if(own){const check=icon('check');check.setAttribute('aria-label','Сохранено на компьютере');footer.append(check);}bubble.append(footer);content.append(bubble);row.append(content);return row;
}
function addFiles(files){
 for(const f of files){if(queue.length>=20){toast('За один раз можно добавить до 20 файлов');break;}if(f.size>maxFile||!f.size){toast(`«${f.name}»: нужен файл от 1 байта до 512 МБ`);continue;}queue.push({id:uuid(),file:f,progress:0,status:'ready'});}renderQueue();updateButtons();
}
function renderQueue(){const list=$('attachment-list');list.replaceChildren();list.hidden=!queue.length;for(const item of queue){const row=el('div',`attachment-item ${item.status==='error'?'failed':''}`);row.append(icon(item.file.type.startsWith('image/')?'image':item.file.type.startsWith('video/')?'play':'file'));const info=el('div','attachment-info');info.append(el('div','attachment-name',item.file.name),el('div','attachment-status',item.status==='error'?'Не отправлен · нажмите отправить снова':item.status==='uploading'?`Передаём ${item.progress}%`:`${sizeText(item.file.size)} · Готов к отправке`));if(item.status==='uploading'){const progress=el('progress');progress.max=100;progress.value=item.progress;info.append(progress);}row.append(info);if(item.status!=='uploading'){const remove=el('button','icon-button');remove.setAttribute('aria-label',`Убрать ${item.file.name}`);remove.append(icon('close'));remove.disabled=sending;remove.onclick=()=>{queue=queue.filter(x=>x.id!==item.id);renderQueue();updateButtons();};row.append(remove);}list.append(row);}}
function updateButtons(){$('send-button').disabled=sending||(!$('message-input').value.trim()&&!queue.length);$('attach-button').disabled=sending;}
function upload(item){return new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();xhr.open('POST',`/api/files?name=${encodeURIComponent(item.file.name)}&requestId=${item.id}`);xhr.setRequestHeader('X-Ryadom','1');xhr.setRequestHeader('Content-Type','application/octet-stream');xhr.timeout=30*60*1000;item.status='uploading';renderQueue();xhr.upload.onprogress=e=>{if(e.lengthComputable){item.progress=Math.round(e.loaded/e.total*100);renderQueue();}};xhr.onload=()=>{let data;try{data=JSON.parse(xhr.responseText);}catch{reject(new Error('Не удалось получить подтверждение передачи'));return;}if(xhr.status>=200&&xhr.status<300)resolve(data);else reject(new Error(data.error||'Передача не удалась'));};xhr.onerror=()=>reject(new Error('Связь прервалась. Проверьте домашнюю сеть и повторите отправку'));xhr.ontimeout=()=>reject(new Error('Передача заняла слишком долго. Попробуйте ещё раз'));xhr.send(item.file);});}
function openDeleteDialog(message){
 deleteTarget=message;
 $('delete-summary').textContent=message.file?`Сообщение и вложение «${message.file.name}» будут удалены у всех устройств.`:'Сообщение будет удалено у всех устройств.';
 $('delete-dialog').showModal();
}
async function deleteMessage(){
 const message=deleteTarget;if(!message)return;
 const button=$('delete-confirm');button.disabled=true;let done=false;
 try{
  const result=await api(`/api/messages/${encodeURIComponent(message.id)}`,'DELETE');
  stateGeneration++;messages.delete(message.id);if(chat){chat.revision=Math.max(chat.revision??0,result.revision??0);chat.deletionRevision=Math.max(chat.deletionRevision??0,result.deletionRevision??0);}
  if(message.file&&$('full-image').src.includes(message.file.id)&&$('image-dialog').open)$('image-dialog').close();
  $('delete-dialog').close();renderMessages();toast(result.freedBytes?`Удалено, освобождено ${sizeText(result.freedBytes)}`:'Сообщение удалено');done=true;
 }catch(e){toast(e.message);}
 finally{button.disabled=false;if(done)deleteTarget=null;}
}
async function openClearDialog(){
 if(!me?.host)return;
 try{
  const preview=await api('/api/chat/clear/preview');clearRevision=preview.revision;clearOperationId=uuid();
  $('clear-summary').textContent=`Будет удалено ${preview.activeMessages} сообщений и ${preview.activeFiles} файлов (${sizeText(preview.bytes)}). Незавершённых передач: ${preview.tempFiles}.`;
  $('clear-dialog').showModal();
 }catch(e){toast(e.message);}
}
async function clearChat(){
 const button=$('clear-confirm');button.disabled=true;const generation=stateGeneration;const operationId=clearOperationId||uuid();clearOperationId=operationId;
 try{
  const result=await api('/api/chat/clear','POST',{confirm:true,revision:clearRevision,operationId});
  if(generation!==stateGeneration||(chat&&(result.epoch<chat.epoch||result.revision<chat.revision))){$('clear-dialog').close();return;}
  stateGeneration++;messages.clear();canLoadOlder=false;chat={...(chat||{id:'legacy'}),revision:result.revision,deletionRevision:result.deletionRevision??chat?.deletionRevision??0,epoch:result.epoch};
  if($('image-dialog').open)$('image-dialog').close();
  $('clear-dialog').close();clearOperationId=null;renderMessages(true);
  toast(result.cleanupPending?`История очищена, но не все файлы удалены (${sizeText(result.freedBytes)}).`:`Чат и файлы очищены. Освобождено ${sizeText(result.freedBytes)}.`);
 }catch(e){toast(e.message);}
 finally{button.disabled=false;}
}
$('delete-confirm').onclick=deleteMessage;$('delete-cancel').onclick=()=>$('delete-dialog').close();$('delete-cancel-x').onclick=()=>$('delete-dialog').close();
$('clear-chat-button').onclick=openClearDialog;$('clear-confirm').onclick=clearChat;$('clear-cancel').onclick=()=>$('clear-dialog').close();$('clear-cancel-x').onclick=()=>$('clear-dialog').close();
$('downloads-button').onclick=()=>{if(window.ryadom&&typeof window.ryadom.openDownloads==='function')window.ryadom.openDownloads();else toast('Папка загрузок доступна в приложении Рядом для Windows или Android');};
let pendingText=null;
$('message-form').onsubmit=async e=>{e.preventDefault();if(sending)return;const input=$('message-input');const text=input.value.trim();if(!text&&!queue.length)return;sending=true;updateButtons();
 try{if(text){if(!pendingText||pendingText.text!==text)pendingText={text,requestId:uuid()};const m=await api('/api/messages','POST',pendingText);messages.set(m.id,m);pendingText=null;if(input.value.trim()===text)input.value='';input.style.height='auto';renderMessages(true);}for(const item of [...queue]){try{const m=await upload(item);messages.set(m.id,m);queue=queue.filter(x=>x.id!==item.id);renderMessages(true);renderQueue();}catch(e){item.status='error';renderQueue();throw e;}}}catch(e){toast(e.message||'Не удалось отправить. Проверьте соединение');}finally{sending=false;renderQueue();updateButtons();input.focus();}
};
$('message-input').oninput=()=>{const t=$('message-input');t.style.height='auto';t.style.height=`${Math.min(t.scrollHeight,140)}px`;updateButtons();};
$('message-input').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing&&!matchMedia('(pointer:coarse)').matches){e.preventDefault();$('message-form').requestSubmit();}};
$('message-input').onpaste=e=>{if(e.clipboardData.files.length){e.preventDefault();addFiles(e.clipboardData.files);}};
$('attach-button').onclick=()=>$('file-input').click();$('file-input').onchange=()=>{addFiles($('file-input').files);$('file-input').value='';};
let dragCount=0;document.addEventListener('dragenter',e=>{if(me&&e.dataTransfer.types.includes('Files')){e.preventDefault();dragCount++;$('drop-overlay').hidden=false;}});document.addEventListener('dragleave',()=>{if(--dragCount<=0){dragCount=0;$('drop-overlay').hidden=true;}});document.addEventListener('dragover',e=>{if(me&&e.dataTransfer.types.includes('Files'))e.preventDefault();});document.addEventListener('drop',e=>{if(!me)return;e.preventDefault();dragCount=0;$('drop-overlay').hidden=true;if(!sending)addFiles(e.dataTransfer.files);});
$('join-form').onsubmit=async e=>{e.preventDefault();$('join-error').textContent='';$('join-pending').hidden=true;$('join-button').disabled=true;try{const pending=await api('/api/pair','POST',{name:$('device-name').value.trim(),code:$('pair-code').value});if(pending&&pending.pending){$('join-pending').hidden=false;$('join-button').textContent='Ожидаем подтверждения…';const deadline=Date.now()+120000;let approved=false;while(Date.now()<deadline){await new Promise(r=>setTimeout(r,1000));const r=await fetch('/api/pair/status?requestId='+encodeURIComponent(pending.requestId));if(r.status===200){approved=true;break;}if(r.status===202)continue;let msg='Подключение не подтверждено';try{const d=await r.json();msg=d.error||msg;}catch{}throw new Error(msg);}if(!approved)throw new Error('Главное устройство не подтвердило подключение. Попробуйте снова.');}const data=await api('/api/state');applyState(data);connectEvents();$('pair-code').value='';}catch(e){$('join-error').textContent=e.message==='Failed to fetch'?'Нет связи. Проверьте домашнюю сеть и главное устройство.':e.message;}finally{$('join-button').disabled=false;$('join-button').textContent='Подключиться';$('join-pending').hidden=true;}};
$('pair-code').oninput=()=>{const s=$('pair-code').value.replace(/\D/g,'').slice(0,8);$('pair-code').value=s.length>4?`${s.slice(0,4)} ${s.slice(4)}`:s;};
function setFilter(next){filter=next;$('tab-all').classList.toggle('active',next==='all');$('tab-media').classList.toggle('active',next==='media');$('tab-all').setAttribute('aria-pressed',next==='all');$('tab-media').setAttribute('aria-pressed',next==='media');renderMessages(true);}
$('tab-all').onclick=()=>setFilter('all');$('all-room').onclick=()=>setFilter('all');$('tab-media').onclick=()=>setFilter('media');
$('search-toggle').onclick=()=>{$('search-bar').hidden=!$('search-bar').hidden;if(!$('search-bar').hidden)$('search').focus();else{$('search').value='';renderMessages();}};$('search-close').onclick=()=>{$('search-bar').hidden=true;$('search').value='';renderMessages();};$('search').oninput=()=>renderMessages();
$('load-older').onclick=async()=>{const a=$('scroll-area');const before=Math.min(...[...messages.values()].map(m=>m.seq));const previous=a.scrollHeight;const generation=stateGeneration;$('load-older').disabled=true;try{const page=await api(`/api/messages?before=${before}`);if(generation!==stateGeneration)return;page.forEach(m=>messages.set(m.id,m));canLoadOlder=page.length===100;renderMessages();a.scrollTop+=a.scrollHeight-previous;}catch(e){toast(e.message);}finally{$('load-older').disabled=false;}};
function eventName(type){return {host_login:'вход главного',pair_request:'запрос на подключение',pair_approved:'подключение подтверждено',pair_rejected:'подключение отклонено',device_revoked:'устройство отозвано',logout:'выход',logout_all:'выход на всех'}[type]||type;}
function renderPending(){const section=$('pending-section');if(!section)return;const host=!!me?.host;section.hidden=!host||!pendingRequests.length;if(section.hidden)return;const list=$('pending-list');list.replaceChildren();for(const p of pendingRequests){const row=el('div','settings-device');const info=el('div','device-detail');info.append(el('strong','',p.name),el('small','',`${p.ip} · ${new Date(p.created).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})}`));row.append(info);const ok=el('button','button secondary','Подтвердить');ok.type='button';ok.onclick=async()=>{ok.disabled=true;try{await api('/api/host/pair/approve','POST',{requestId:p.requestId});toast('Устройство подключено');await sync();}catch(e){toast(e.message);ok.disabled=false;}};const no=el('button','text-button danger','Отклонить');no.type='button';no.onclick=async()=>{try{await api('/api/host/pair/reject','POST',{requestId:p.requestId});await sync();}catch(e){toast(e.message);}};row.append(ok,no);list.append(row);}}
async function renderHostSecurity(){if(!me)return;const host=!!me.host;$('host-security').hidden=!host;if(!host)return;$('tls-fingerprint').textContent=fingerprint||'ещё не сформирован';$('storage-info').textContent=storage?`Занято ${sizeText(storage.usedBytes)} из ${sizeText(storage.totalBytes)}`:' ';try{const data=await api('/api/host/events');const box=$('host-events');box.replaceChildren();for(const ev of data.events.slice(0,12)){box.append(el('div','field-hint',`${new Date(ev.created).toLocaleString('ru-RU')} · ${eventName(ev.type)}${ev.detail?' · '+ev.detail:''}`));}}catch{}try{const p=await api('/api/chat/clear/preview');$('chat-stats').textContent=`${p.activeMessages} сообщений · ${p.activeFiles} файлов · ${sizeText(p.bytes)}`;}catch{$('chat-stats').textContent='Не удалось получить размер истории';}}
function renderPairing(){if(!pairing)return;const seconds=Math.max(0,Math.ceil((pairing.expires-Date.now())/1000));$('pairing-code').textContent=seconds?`${pairing.code.slice(0,4)} ${pairing.code.slice(4)}`:'•••• ••••';$('pairing-expiry').textContent=seconds?`Действует ещё ${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,'0')}`:'Подключение закрыто';$('copy-code').disabled=!seconds;$('disable-pairing').hidden=!seconds;}
async function openSettings(){try{await sync();if(!me)return;$('pairing-section').hidden=!me.host;$('client-info').hidden=me.host;$('logout-button').hidden=me.host;$('stop-button').hidden=!me.host;$('tls-state').hidden=me.host;$('tls-state').textContent=tlsEnabled?'Соединение с главным защищено (TLS)':'Соединение с главным без шифрования. Обновите главное устройство.';$('rename-input').value=me.name;$('server-addresses').replaceChildren();$('no-address').hidden=addresses.length>0;for(const address of addresses){const row=el('div','server-address');row.append(el('code','',address));const c=el('button','icon-button');c.append(icon('copy'));c.setAttribute('aria-label','Скопировать адрес');c.onclick=()=>copy(address);row.append(c);$('server-addresses').append(row);}renderPairing();renderPending();renderHostSecurity();clearInterval(expiryTimer);expiryTimer=setInterval(renderPairing,1000);$('settings-dialog').showModal();}catch(e){toast(e.message);}}
for(const id of ['sidebar-connect','connect-button','profile-button','mobile-settings'])$(id).onclick=openSettings;
$('close-settings').onclick=()=>$('settings-dialog').close();$('settings-dialog').addEventListener('close',()=>clearInterval(expiryTimer));
$('new-code').onclick=async()=>{try{pairing=await api('/api/host/pairing','POST',{enabled:true});renderPairing();toast('Новый код готов');}catch(e){toast(e.message);}};
$('disable-pairing').onclick=async()=>{try{pairing=await api('/api/host/pairing','POST',{enabled:false});renderPairing();}catch(e){toast(e.message);}};
$('copy-code').onclick=()=>copy(pairing.code);
$('rename-form').onsubmit=async e=>{e.preventDefault();try{await api('/api/device','PATCH',{name:$('rename-input').value.trim()});await sync();toast('Имя сохранено');}catch(e){toast(e.message);}};
$('logout-button').onclick=async()=>{if(!confirm('Выйти из чата на этом устройстве? Для входа понадобится новый код.'))return;try{await api('/api/logout','POST',{});showJoin();}catch(e){toast(e.message);}};
$('logout-all').onclick=async()=>{if(!confirm('Выйти на всех устройствах? Текущее подключение сохранится, остальным понадобится новый код.'))return;try{await api('/api/host/logout-all','POST',{});toast('Остальные сессии отозваны');await sync();}catch(e){toast(e.message);}};
$('change-role-button').onclick=async()=>{if(!confirm('Вернуться к выбору главного устройства? Текущий чат на этом устройстве закроется. История останется там, где был создан чат.'))return;try{await api('/api/local/choose-role','POST',{});events?.close();$('settings-dialog').close();toast('Открываем выбор главного устройства…');}catch(e){toast(e.message);}};
$('stop-button').onclick=async()=>{if(!confirm('Выключить чат? Другие устройства потеряют соединение. Переписка и файлы сохранятся.'))return;try{await api('/api/host/stop','POST',{});events?.close();const box=el('main','stopped');box.append(el('h1','','До встречи рядом.'),el('p','','Чат выключен. Переписка сохранена. Чтобы продолжить, запустите Рядом на компьютере.'));document.body.replaceChildren(box);}catch(e){toast(e.message);}};
$('close-image').onclick=()=>$('image-dialog').close();$('image-dialog').addEventListener('close',()=>{$('full-image').removeAttribute('src');});
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&me)sync();});
window.addEventListener('online',()=>{if(me){connectEvents();sync();}});
(async()=>{try{const connect=new URLSearchParams(location.search).get('connect')==='1';const hash=new URLSearchParams(location.hash.slice(1));const token=hash.get('t');if(token){history.replaceState(null,'',location.pathname);await api('/api/host-login','POST',{token});}applyState(await api('/api/state'));connectEvents();if(connect)openSettings();}catch(e){showJoin();if(e.status!==401)$('join-error').textContent=e.message==='Failed to fetch'?'Нет связи с главным компьютером.':e.message;}})();
