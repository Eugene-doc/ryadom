package local.ryadom.chat;

import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * Local host shared by Android and the JVM integration tests. Persistent, streaming, LAN-only.
 * Protocol 0.2.0: random revocable sessions, one-time host login, pairing with host approval,
 * event log, quotas and rate limits, TLS identity of the host.
 */
final class ChatHost implements AutoCloseable {
 interface Assets {byte[] read(String name) throws IOException;}
 interface Mutation {void apply(JSONObject next) throws Exception;}
 static final String VERSION="0.5.1";static final int PROTOCOL=4;
 static final long MAX_FILE=512L*1024*1024;
 static final int MAX_STREAMS=8,MAX_EVENT_LOG=500,MAX_PENDING_DEFAULT=5;
 final File directory,files,stateFile;final Assets assets;final List<String> addresses;final int port;
 final TlsIdentity tls;
 private JSONObject state;private String code;private long expires;
 private final SecureRandom random=new SecureRandom();
 private final Map<MiniHttp.Request,Stream> streams=new ConcurrentHashMap<>();
 private final Map<String,Integer> deviceStreams=new HashMap<>();
 private final Map<String,long[]> attempts=new HashMap<>();
 private final Set<String> uploadIds=new HashSet<>();
 private final Map<String,Integer> uploads=new HashMap<>();
 private final Map<String,MiniHttp.Request> uploadRequests=new HashMap<>();
 private final Map<String,Long> uploadEpochs=new HashMap<>();
 private final Map<String,Long> reserved=new HashMap<>();private long reservedTotal;
 private final Map<String,List<Long>> rate=new HashMap<>();
 private final Map<String,Long> hostTokens=new HashMap<>();
 private final Map<String,JSONObject> pending=new LinkedHashMap<>();
 private final long sessionTtl,hostTokenTtl,pairTtl,maxTotal,maxDevice,minFree;
 private final int msgPerMin,uploadPerMin,maxPending,pairAttempts;
 private final String nativeKey;
 private final String hostId;
 private final Runnable stop;private final MiniHttp http;private boolean sessionEnding;
 private final ExecutorService sse=Executors.newCachedThreadPool(new ThreadFactory(){public Thread newThread(Runnable run){Thread thread=new Thread(run,"Ryadom SSE");thread.setDaemon(true);return thread;}});
 ChatHost(File dir,List<String> ips,int port,Assets a,Runnable stopRequest) throws Exception {
  this(dir,ips,port,a,stopRequest,"");
 }
 ChatHost(File dir,List<String> ips,int port,Assets a,Runnable stopRequest,String deviceId) throws Exception {
  directory=dir;files=new File(dir,"files");files.mkdirs();stateFile=new File(dir,"chat.json");assets=a;addresses=new ArrayList<>(ips);this.port=port;stop=stopRequest;hostId=deviceId==null?"":deviceId;
  nativeKey=value("RYADOM_NATIVE_KEY","");
  sessionTtl=number("RYADOM_SESSION_DAYS",30)*86400000L;
  hostTokenTtl=number("RYADOM_HOST_TOKEN_TTL_MS",120000);
  pairTtl=number("RYADOM_PAIR_TTL_MS",120000);
  maxTotal=number("RYADOM_MAX_TOTAL_MB",20480)*1024*1024;
  maxDevice=number("RYADOM_MAX_DEVICE_MB",8192)*1024*1024;
  minFree=number("RYADOM_MIN_FREE_MB",256)*1024*1024;
  msgPerMin=(int)number("RYADOM_MSG_PER_MIN",120);
  uploadPerMin=(int)number("RYADOM_UPLOAD_PER_MIN",30);
  maxPending=(int)number("RYADOM_MAX_PENDING",MAX_PENDING_DEFAULT);
  pairAttempts=(int)number("RYADOM_PAIR_ATTEMPTS_PER_MIN",8);
  boolean fresh=!stateFile.exists();
  state=fresh?new JSONObject():new JSONObject(new String(Files.readAllBytes(stateFile.toPath()),StandardCharsets.UTF_8));
  if(!state.has("devices"))state.put("devices",new JSONArray());
  if(!state.has("messages"))state.put("messages",new JSONArray());
  if(!state.has("files"))state.put("files",new JSONArray());
  if(!state.has("sessions"))state.put("sessions",new JSONArray());
  if(!state.has("events"))state.put("events",new JSONArray());
  if(!state.has("operations"))state.put("operations",new JSONArray());
  if(!state.has("revoked"))state.put("revoked",new JSONArray());
  if(!state.has("privateChats"))state.put("privateChats",new JSONArray());
  if(!state.has("chatMembers"))state.put("chatMembers",new JSONArray());
  if(!state.has("deviceKeys"))state.put("deviceKeys",new JSONArray());
  for(int i=0;i<state.getJSONArray("messages").length();i++){JSONObject message=state.getJSONArray("messages").getJSONObject(i);if(message.optString("chatId","").isEmpty())message.put("chatId","legacy");if(!message.has("encrypted"))message.put("encrypted",false);}
  for(int i=0;i<state.getJSONArray("files").length();i++){JSONObject file=state.getJSONArray("files").getJSONObject(i);if(file.optString("chatId","").isEmpty())file.put("chatId","legacy");if(!file.has("encrypted"))file.put("encrypted",false);}
  if(!state.has("seq"))state.put("seq",0);
  if(fresh){
   state.put("schema",3);
   state.put("chat",new JSONObject().put("id","legacy").put("type","legacy").put("title","Свои устройства").put("revision",0).put("deletionRevision",0).put("epoch",0));
  }
  tls=TlsIdentity.ensure(new File(dir,"tls"));
  for(File file:Objects.requireNonNull(files.listFiles()))if(file.getName().endsWith(".part"))try{file.delete();}catch(Exception ignored){}
  migrateSessions();
  migrateChatV3();
  importTrustRoster();
  recoverDeletedFiles();
  beginEphemeralSession();
  newCode(true);
  List<String> plain=new ArrayList<>();plain.add("127.0.0.1");
  List<String> secure=new ArrayList<>();for(String ip:ips)if(!plain.contains(ip)&&!secure.contains(ip))secure.add(ip);
  http=new MiniHttp(plain,secure,port,tls.context,this::handle);
 }
 private static String value(String key,String fallback){String value=System.getenv(key);return value==null||value.isEmpty()?fallback:value;}
 private static long number(String key,long fallback){try{return Long.parseLong(value(key,String.valueOf(fallback)));}catch(Exception e){return fallback;}}
 String tlsFingerprint(){return tls.fingerprint;}
 String localUrl(){
  String token=token(32);  synchronized(this){long nowMs=System.currentTimeMillis();Iterator<Map.Entry<String,Long>> iterator=hostTokens.entrySet().iterator();while(iterator.hasNext()){if(iterator.next().getValue()<nowMs)iterator.remove();}hostTokens.put(token,nowMs+hostTokenTtl);}
  return "http://127.0.0.1:"+port+"/#t="+token;
 }
 private static String now(){return Instant.now().toString();}
 private static long instant(String value){try{return Instant.parse(value).toEpochMilli();}catch(Exception e){return 0;}}
 private String token(int size){byte[] bytes=new byte[size];random.nextBytes(bytes);StringBuilder text=new StringBuilder();for(byte value:bytes)text.append(String.format("%02x",value));return text.toString();}
 private static String hash(String text) throws Exception {byte[] bytes=MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));StringBuilder result=new StringBuilder();for(byte value:bytes)result.append(String.format("%02x",value));return result.toString();}
 private static boolean safeEqual(String first,String second){return MessageDigest.isEqual(String.valueOf(first).getBytes(StandardCharsets.UTF_8),String.valueOf(second).getBytes(StandardCharsets.UTF_8));}
 private synchronized void change(Mutation mutation) throws Exception {
  JSONObject next=new JSONObject(state.toString());mutation.apply(next);File temporary=new File(directory,"chat.json.tmp");
  try(FileOutputStream out=new FileOutputStream(temporary)){out.write(next.toString().getBytes(StandardCharsets.UTF_8));out.getFD().sync();}
  try{Files.move(temporary.toPath(),stateFile.toPath(),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}catch(AtomicMoveNotSupportedException e){Files.move(temporary.toPath(),stateFile.toPath(),StandardCopyOption.REPLACE_EXISTING);}state=next;
 }
 private static JSONObject find(JSONArray values,String key,String value) throws JSONException {for(int i=0;i<values.length();i++){JSONObject item=values.getJSONObject(i);if(item.optString(key).equals(value))return item;}return null;}
 private static void remove(JSONArray values,String key,String value) throws JSONException {for(int i=values.length()-1;i>=0;i--)if(values.getJSONObject(i).optString(key).equals(value))values.remove(i);}
 private void recoverDeletedFiles() throws Exception {
  final List<String> removed=new ArrayList<>();final boolean[] reconcile=new boolean[1];
  synchronized(this){
   JSONArray fileArray=state.getJSONArray("files");
   for(int i=fileArray.length()-1;i>=0;i--){
    JSONObject file=fileArray.getJSONObject(i);if(!"deleting".equals(file.optString("state")))continue;
    File disk=new File(files,file.optString("id"));if(!disk.exists()||disk.delete())removed.add(file.optString("id"));
   }
   boolean pending=false;for(int i=0;i<fileArray.length();i++){JSONObject file=fileArray.getJSONObject(i);if("deleting".equals(file.optString("state"))&&!removed.contains(file.optString("id")))pending=true;}
   File[] local=files.listFiles();if(local!=null)for(File file:local)if(file.getName().endsWith(".part"))pending=true;
   reconcile[0]=!pending;
  }
  if(removed.isEmpty()&&!reconcile[0])return;
  change(next->{
   JSONArray fileArray=next.getJSONArray("files");for(String id:removed)remove(fileArray,"id",id);
   if(reconcile[0])for(String status:new String[]{"deleting","partial"}){JSONArray operations=next.getJSONArray("operations");for(int i=0;i<operations.length();i++){JSONObject operation=operations.getJSONObject(i);if("clear".equals(operation.optString("type"))&&status.equals(operation.optString("status"))){operation.put("status","done").put("updatedAt",now());JSONObject result=operation.optJSONObject("result");if(result!=null)result.put("cleanupPending",false).put("tempFiles",0);}}}
  });
 }
 private synchronized void migrateSessions() throws Exception {
  if(state.optInt("schema",1)>=2)return;
  change(next->{
   JSONArray devices=next.getJSONArray("devices"),sessions=next.getJSONArray("sessions");long nowMs=System.currentTimeMillis();
   for(int i=0;i<devices.length();i++){
    JSONObject device=devices.getJSONObject(i);String legacy=device.optString("token","");
    if(!legacy.isEmpty()&&find(sessions,"deviceId",device.optString("id"))==null){
     sessions.put(new JSONObject().put("token",legacy).put("deviceId",device.optString("id")).put("created",device.optString("created",now())).put("lastSeen",now()).put("expires",Instant.ofEpochMilli(nowMs+sessionTtl).toString()));
    }
    device.remove("token");
   }
   next.put("schema",2);
  });
 }
  private synchronized void migrateChatV3() throws Exception {
   boolean migrate=state.optInt("schema",1)<3;
   if(!migrate){
    JSONObject chat=state.optJSONObject("chat");
    if(chat==null||!chat.has("revision")||!chat.has("deletionRevision")||!chat.has("epoch"))migrate=true;
    if(!migrate){
     JSONArray messages=state.optJSONArray("messages"),files=state.optJSONArray("files");
     if(messages==null||files==null)migrate=true;
     else{
      for(int i=0;i<messages.length()&&!migrate;i++)if(messages.getJSONObject(i).optString("chatId").isEmpty())migrate=true;
      for(int i=0;i<files.length()&&!migrate;i++){JSONObject file=files.getJSONObject(i);if(file.optString("chatId").isEmpty()||file.optString("state").isEmpty())migrate=true;}
     }
    }
   }
   if(!migrate)return;
   change(next->{
    JSONObject chat=next.optJSONObject("chat");
    if(chat==null)chat=new JSONObject();
    if(!chat.has("id"))chat.put("id","legacy");
    if(!chat.has("type"))chat.put("type","legacy");
    if(!chat.has("title"))chat.put("title","Свои устройства");
    if(!chat.has("revision"))chat.put("revision",0);
    if(!chat.has("deletionRevision"))chat.put("deletionRevision",0);
    if(!chat.has("epoch"))chat.put("epoch",0);
    next.put("chat",chat);
    JSONArray messages=next.getJSONArray("messages"),files=next.getJSONArray("files");
    Map<String,String> messageFiles=new HashMap<>();
    for(int i=0;i<messages.length();i++){
     JSONObject message=messages.getJSONObject(i);
     if(message.optString("chatId").isEmpty())message.put("chatId","legacy");
     JSONObject file=message.optJSONObject("file");
     if(file!=null&&!file.optString("id").isEmpty())messageFiles.put(file.optString("id"),message.optString("id"));
    }
    for(int i=0;i<files.length();i++){
     JSONObject file=files.getJSONObject(i);
     if(file.optString("chatId").isEmpty())file.put("chatId","legacy");
     if(file.optString("messageId").isEmpty()&&messageFiles.containsKey(file.optString("id")))file.put("messageId",messageFiles.get(file.optString("id")));
     if(file.optString("state").isEmpty())file.put("state","ready");
    }
    if(!next.has("operations"))next.put("operations",new JSONArray());
    next.put("schema",3);
   });
  }
  private synchronized void pruneSessions() throws Exception {
  JSONArray sessions=state.getJSONArray("sessions");long nowMs=System.currentTimeMillis();boolean changed=false;
  for(int i=sessions.length()-1;i>=0;i--){if(instant(sessions.getJSONObject(i).optString("expires"))<nowMs){sessions.remove(i);changed=true;}}
  if(changed){final JSONArray kept=sessions;change(next->next.put("sessions",kept));}
 }
 private String newSession(JSONObject device) throws Exception {
  String raw=token(32);long nowMs=System.currentTimeMillis();
  final JSONObject session=new JSONObject().put("token",hash(raw)).put("deviceId",device.getString("id")).put("created",now()).put("lastSeen",now()).put("expires",Instant.ofEpochMilli(nowMs+sessionTtl).toString());
  synchronized(this){pruneSessions();change(next->next.getJSONArray("sessions").put(session));}
  return raw;
 }
 private String rawCookie(MiniHttp.Request request){for(String part:request.header("cookie").split(";"))if(part.trim().startsWith("ryadom_sid="))return part.trim().substring(11);return "";}
 private String sessionCookie(String raw){return "ryadom_sid="+raw+"; HttpOnly; SameSite=Strict; Path=/; Max-Age="+(sessionTtl/1000);}
 private static String clearCookie(){return "ryadom_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";}
 private synchronized Auth auth(MiniHttp.Request request) throws Exception {
  String raw=rawCookie(request);if(raw.isEmpty())return null;
  String tokenHash=hash(raw);
  JSONArray sessions=state.getJSONArray("sessions");JSONObject session=find(sessions,"token",tokenHash);
  if(session==null)return null;
  long expires=instant(session.optString("expires"));
  if(expires<System.currentTimeMillis()){removeSession(tokenHash);return null;}
  JSONObject device=find(state.getJSONArray("devices"),"id",session.optString("deviceId"));
  if(device==null){removeSession(tokenHash);return null;}
  if(System.currentTimeMillis()-instant(session.optString("lastSeen"))>60000){
   change(next->{JSONObject current=find(next.getJSONArray("sessions"),"token",tokenHash);if(current!=null)current.put("lastSeen",now());});
  }
  return new Auth(device,tokenHash,expires);
 }
 private synchronized void removeSession(String tokenHash) throws Exception {change(next->remove(next.getJSONArray("sessions"),"token",tokenHash));}
 private static String cleanName(String value){String result=value.replaceAll("[\\x00-\\x1f\\x7f/\\\\]","").trim();return result.isEmpty()?"Файл":result.substring(0,Math.min(result.length(),180));}
 private JSONObject body(MiniHttp.Request request) throws Exception {try{return new JSONObject(new String(request.body(65536),StandardCharsets.UTF_8));}catch(JSONException e){throw new MiniHttp.Failure(400,"Некорректный запрос");}}
 private synchronized JSONObject pairing() throws Exception {return new JSONObject().put("code",code).put("expires",expires);}
 private synchronized void newCode(boolean enabled){code=String.valueOf(10000000+random.nextInt(90000000));expires=enabled?System.currentTimeMillis()+15*60*1000:0;}
 private synchronized boolean pairingDisabled(){return expires==0||System.currentTimeMillis()>expires;}
 private synchronized void prunePairs(){long nowMs=System.currentTimeMillis();Iterator<Map.Entry<String,JSONObject>> iterator=pending.entrySet().iterator();while(iterator.hasNext())if(iterator.next().getValue().optLong("expires",0)<nowMs)iterator.remove();}
 private synchronized JSONArray pendingList() throws Exception {
  prunePairs();JSONArray result=new JSONArray();
  for(JSONObject request:pending.values())if(request.optString("status").equals("pending"))result.put(new JSONObject().put("requestId",request.optString("requestId")).put("name",request.optString("name")).put("ip",request.optString("ip")).put("created",request.optString("created")));
  return result;
 }
 private synchronized JSONArray publicDevices() throws Exception {
  JSONArray result=new JSONArray(),all=state.getJSONArray("devices"),sessions=state.getJSONArray("sessions");
  for(int i=0;i<all.length();i++){
   JSONObject device=all.getJSONObject(i);String id=device.getString("id"),lastSeen="";
   for(int j=0;j<sessions.length();j++){JSONObject session=sessions.getJSONObject(j);if(id.equals(session.optString("deviceId"))&&session.optString("lastSeen").compareTo(lastSeen)>0)lastSeen=session.optString("lastSeen");}
   result.put(new JSONObject().put("id",id).put("name",device.getString("name")).put("host",device.optBoolean("host")).put("created",device.optString("created")).put("lastSeen",lastSeen).put("online",deviceStreams.containsKey(id)));
  }
  return result;
 }
 private synchronized long totalBytes() throws Exception {long sum=0;JSONArray all=state.getJSONArray("files");for(int i=0;i<all.length();i++)sum+=all.getJSONObject(i).optLong("size",0);return sum;}
 private synchronized long deviceBytes(String deviceId) throws Exception {long sum=0;JSONArray all=state.getJSONArray("files");for(int i=0;i<all.length();i++){JSONObject file=all.getJSONObject(i);if(deviceId.equals(file.optString("deviceId")))sum+=file.optLong("size",0);}return sum;}
 private long reserved(String deviceId){Long value=reserved.get(deviceId);return value==null?0:value;}
 private void logEvent(String type,String detail,String ip){
  try{
   synchronized(this){
    final long id=state.optLong("eventSeq",0)+1;
    final JSONObject event=new JSONObject().put("id",id).put("type",type).put("detail",detail==null?JSONObject.NULL:detail).put("ip",ip==null?JSONObject.NULL:ip).put("created",now());
    change(next->{next.put("eventSeq",id);JSONArray events=next.getJSONArray("events");events.put(event);while(events.length()>MAX_EVENT_LOG)events.remove(0);});
   }
  }catch(Exception ignored){}
 }
 private static String eventData(String type,Object value){return "event: "+type+"\ndata: "+value+"\n\n";}
 private void broadcast(String type,Object value,boolean hostOnly){broadcastExcept(null,type,value,hostOnly);}
 private void broadcastExcept(MiniHttp.Request excluded,String type,Object value,boolean hostOnly){
  String data=eventData(type,value);long nowMs=System.currentTimeMillis();
  for(Stream stream:streams.values()){
   if(stream.request==excluded)continue;
   if(stream.closed)continue;
   if(stream.expires<=nowMs){closeStream(stream);continue;}
   if(hostOnly&&!stream.host)continue;
   if(!stream.queue.offer(data))closeStream(stream);
  }
 }
 private void devicesChanged() throws Exception {broadcast("devices",publicDevices(),false);}
 private JSONObject chatFor(String id) throws Exception {
  if("legacy".equals(id))return state.getJSONObject("chat");
  return find(state.getJSONArray("privateChats"),"id",id);
 }
 private JSONObject chatForFrom(JSONObject source,String id) throws Exception {
  if("legacy".equals(id))return source.optJSONObject("chat");
  return find(source.getJSONArray("privateChats"),"id",id);
 }
 private void requireChat(JSONObject device,String chatId) throws Exception {
  if("legacy".equals(chatId))return;
  boolean member=false;JSONArray members=state.getJSONArray("chatMembers");
  for(int i=0;i<members.length();i++){JSONObject m=members.getJSONObject(i);if(chatId.equals(m.optString("chatId"))&&device.getString("id").equals(m.optString("deviceId"))){member=true;break;}}
  if(!member)throw new MiniHttp.Failure(403,"Нет доступа к чату");
 }
 private String privateChatId(String first,String second) throws Exception {String a=first,b=second;if(a.compareTo(b)>0){String t=a;a=b;b=t;}return "private-"+hash(a+":"+b).substring(0,24);}
 private JSONArray chatsFor(JSONObject device) throws Exception {
  JSONArray result=new JSONArray();JSONArray privateChats=state.getJSONArray("privateChats");JSONArray members=state.getJSONArray("chatMembers");JSONArray allMessages=state.getJSONArray("messages");
  for(int c=-1;c<privateChats.length();c++){
   JSONObject chat;boolean legacy=c<0;
   if(legacy)chat=state.getJSONObject("chat");else chat=privateChats.getJSONObject(c);
   if(!legacy){boolean member=false;for(int i=0;i<members.length();i++){JSONObject m=members.getJSONObject(i);if(chat.optString("id").equals(m.optString("chatId"))&&device.getString("id").equals(m.optString("deviceId"))){member=true;break;}}if(!member)continue;}
   JSONObject last=null;int unread=0;long lastRead=0;
   for(int i=0;i<members.length();i++){JSONObject m=members.getJSONObject(i);if(chat.optString("id").equals(m.optString("chatId"))&&device.getString("id").equals(m.optString("deviceId")))lastRead=m.optLong("lastReadSeq",0);}
   for(int i=0;i<allMessages.length();i++){JSONObject m=allMessages.getJSONObject(i);if(!chat.optString("id").equals(m.optString("chatId"))||!m.optString("deletedAt").isEmpty())continue;if(last==null||m.optLong("seq",0)>last.optLong("seq",0))last=m;if(!legacy&&!device.getString("id").equals(m.optString("deviceId"))&&m.optLong("seq",0)>lastRead)unread++;}
   JSONArray memberList=new JSONArray();for(int i=0;i<members.length();i++){JSONObject m=members.getJSONObject(i);if(!chat.optString("id").equals(m.optString("chatId")))continue;JSONObject d=find(state.getJSONArray("devices"),"id",m.optString("deviceId"));if(d!=null)memberList.put(new JSONObject().put("id",d.optString("id")).put("name",d.optString("name")));}
   JSONObject summary=new JSONObject().put("id",chat.optString("id")).put("type",legacy?"legacy":"private").put("title",chat.optString("title")).put("sessionId",chat.optString("sessionId")).put("revision",chat.optLong("revision",0)).put("epoch",chat.optLong("epoch",0)).put("unread",unread).put("members",memberList);
   if(last!=null)summary.put("last",new JSONObject().put("id",last.optString("id")).put("deviceId",last.optString("deviceId")).put("text",last.optBoolean("encrypted")?"":last.optString("text")).put("encrypted",last.optBoolean("encrypted")).put("created",last.optString("created")).put("seq",last.optLong("seq")));
   result.put(summary);
  }
  return result;
 }
 private boolean allowRate(String deviceId,String kind,int limit){
  synchronized(this){
   String key=deviceId+":"+kind;long nowMs=System.currentTimeMillis();List<Long> list=rate.get(key);
   if(list==null){list=new ArrayList<>();rate.put(key,list);}
   while(!list.isEmpty()&&nowMs-list.get(0)>60000)list.remove(0);
   if(list.size()>=limit)return false;
   list.add(nowMs);return true;
  }
 }
 private void nativeOnly(MiniHttp.Request request) throws MiniHttp.Failure {
  if(!request.loopback())throw new MiniHttp.Failure(403,"Только на этом устройстве");
  if(nativeKey.isEmpty()||!safeEqual(request.header("x-ryadom-native"),nativeKey))throw new MiniHttp.Failure(403,"Нужен native-ключ");
 }
 private JSONObject hostDevice() throws Exception {
  synchronized(this){
   JSONObject existing=find(state.getJSONArray("devices"),"host","true");
   if(existing!=null&&!hostId.isEmpty()&&!existing.optString("id").equals(hostId)&&find(state.getJSONArray("devices"),"id",hostId)==null){
    final String oldId=existing.optString("id");
    change(next->{JSONObject current=find(next.getJSONArray("devices"),"id",oldId);if(current!=null)current.put("id",hostId);JSONArray sessions=next.getJSONArray("sessions");for(int i=0;i<sessions.length();i++){JSONObject session=sessions.getJSONObject(i);if(oldId.equals(session.optString("deviceId")))session.put("deviceId",hostId);}});
    existing=find(state.getJSONArray("devices"),"host","true");
   }
   if(existing!=null)return existing;
  }
  final JSONObject created=new JSONObject().put("id",hostId.isEmpty()?UUID.randomUUID().toString():hostId).put("name","Мой Android").put("host",true).put("created",now());
  synchronized(this){change(next->next.getJSONArray("devices").put(created));}
  return created;
 }
 private void sessionReply(MiniHttp.Request request,int status,String raw,JSONObject value) throws IOException {
  Map<String,String> headers=new LinkedHashMap<>();headers.put("Set-Cookie",sessionCookie(raw));
  request.reply(status,"application/json; charset=utf-8",value.toString().getBytes(StandardCharsets.UTF_8),headers);
 }
 private JSONObject addMessage(JSONObject device,String text,JSONObject file,String requestId) throws Exception { return addMessage(device,text,file,requestId,"legacy",false); }
 private JSONObject addMessage(JSONObject device,String text,JSONObject file,String requestId,String chatId,boolean encrypted) throws Exception {
  final JSONObject message;
  synchronized(this){
   JSONObject old=find(state.getJSONArray("messages"),"requestId",requestId);
   if(old!=null){if(!old.optString("deletedAt").isEmpty())throw new MiniHttp.Failure(410,"Сообщение было удалено");if(!old.optString("deviceId").equals(device.getString("id")))throw new MiniHttp.Failure(409,"Повторите отправку");return old;}
   if(file!=null&&find(state.getJSONArray("devices"),"id",device.getString("id"))==null)throw new MiniHttp.Failure(401,"Доступ устройства отозван");
   JSONObject chat=chatFor(chatId);long revision=(chat==null?0:chat.optLong("revision",0))+1;
   if(file!=null)file.put("chatId",chatId).put("state","ready");
   message=new JSONObject().put("seq",state.getLong("seq")+1).put("id",UUID.randomUUID().toString()).put("deviceId",device.getString("id")).put("deviceName",device.getString("name")).put("text",text).put("file",file==null?JSONObject.NULL:file).put("created",now()).put("requestId",requestId).put("chatId",chatId).put("encrypted",encrypted).put("sessionId",state.getJSONObject("chat").optString("sessionId")).put("revision",revision).put("epoch",chat==null?0:chat.optLong("epoch",0));
   if(file!=null)file.put("messageId",message.getString("id"));
   final JSONObject created=message;
   change(next->{
    next.put("seq",created.getLong("seq"));
    next.getJSONArray("messages").put(created);
    if(file!=null)next.getJSONArray("files").put(file);
    JSONObject nextChat=chatForFrom(next,chatId);if(nextChat!=null)nextChat.put("revision",revision);
   });
  }
  broadcast("message",message,false);
  return message;
 }
 private synchronized void importTrustRoster() {
  File file=new File(directory.getParentFile(),"trust-roster.json");if(!file.exists())return;
  try{
   JSONObject value=new JSONObject(new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8));
   String groupId=value.optString("groupId","");if(groupId.matches("[0-9a-f]{32}"))state.put("group_id",groupId);
   JSONArray revoked=value.optJSONArray("revoked");JSONArray incoming=value.optJSONArray("devices");if(incoming==null)return;
   change(next->{
    JSONArray devices=next.getJSONArray("devices");
    JSONArray revokedState=next.getJSONArray("revoked");
    if(revoked!=null)for(int i=0;i<revoked.length();i++){String id=revoked.optString(i,"");if(!id.matches("d1-[0-9a-f]{32}"))continue;if(find(revokedState,"id",id)==null)revokedState.put(new JSONObject().put("id",id));remove(devices,"id",id);remove(next.getJSONArray("sessions"),"deviceId",id);}
    for(int i=0;i<incoming.length();i++){
     JSONObject source=incoming.getJSONObject(i);String id=source.optString("id","").toLowerCase(Locale.ROOT),token=source.optString("tokenHash","").toLowerCase(Locale.ROOT);
     if(!id.matches("d1-[0-9a-f]{32}")||!token.matches("[0-9a-f]{64}")||id.equals(hostId)||find(revokedState,"id",id)!=null||find(devices,"id",id)!=null)continue;
     String name=cleanName(source.optString("name","Устройство"));devices.put(new JSONObject().put("id",id).put("name",name.substring(0,Math.min(name.length(),40))).put("token",token).put("host",false).put("created",now()));
    }
   });
  }catch(Exception ignored){}
 }
 private synchronized void beginEphemeralSession() throws Exception {
  final JSONObject host=hostDevice();
  final String sessionId=token(16);
  final long[] term=new long[1];
  change(next->{
   JSONObject chat=next.getJSONObject("chat");term[0]=chat.optLong("term",0)+1;
   next.put("messages",new JSONArray()).put("files",new JSONArray()).put("operations",new JSONArray()).put("privateChats",new JSONArray()).put("chatMembers",new JSONArray()).put("deviceKeys",new JSONArray());
   chat.put("sessionId",sessionId).put("term",term[0]).put("hostDeviceId",hostId.isEmpty()?host.getString("id"):hostId).put("revision",0).put("deletionRevision",0).put("epoch",0);
  });
  File[] local=files.listFiles();boolean pending=false;if(local!=null)for(File file:local)try{if(!file.delete()&&file.exists())pending=true;}catch(Exception ignored){pending=true;}
  if(pending)throw new IOException("Не удалось удалить остатки предыдущей истории. Закройте файлы Рядом и запустите снова.");
  File marker=new File(directory,"runtime.json");
  try(FileOutputStream out=new FileOutputStream(marker)){out.write(new JSONObject().put("state","ACTIVE").put("sessionId",sessionId).put("term",term[0]).put("hostDeviceId",hostId.isEmpty()?host.getString("id"):hostId).toString().getBytes(StandardCharsets.UTF_8));out.getFD().sync();}
 }
 private synchronized void endEphemeralSession() {
  if(sessionEnding)return;sessionEnding=true;
  try{broadcast("session_ending",new JSONObject().put("sessionId",state.getJSONObject("chat").optString("sessionId")).put("reason","shutdown"),false);}catch(Exception ignored){}
  for(MiniHttp.Request pending:new ArrayList<>(uploadRequests.values()))try{pending.close();}catch(Exception ignored){}
  try{change(next->{next.put("messages",new JSONArray()).put("files",new JSONArray()).put("operations",new JSONArray()).put("privateChats",new JSONArray()).put("chatMembers",new JSONArray()).put("deviceKeys",new JSONArray());JSONObject chat=next.getJSONObject("chat");chat.put("revision",0).put("deletionRevision",0).put("epoch",0);});}catch(Exception ignored){}
  File[] local=files.listFiles();if(local!=null)for(File file:local)try{file.delete();}catch(Exception ignored){}
  try{new File(directory,"runtime.json").delete();}catch(Exception ignored){}
 }
 private static JSONObject operationResponse(JSONObject operation) throws Exception {
  JSONObject response=new JSONObject(operation.toString()).put("operationId",operation.optString("id"));JSONObject result=operation.optJSONObject("result");
  if(result!=null){Iterator<String> keys=result.keys();while(keys.hasNext()){String key=keys.next();response.put(key,result.get(key));}}
  return response;
 }
 private void handle(MiniHttp.Request request) throws Exception {
  String remote=request.socket.getInetAddress().getHostAddress();
  if(!request.loopback()&&!LanNetwork.privateAddress(remote))throw new MiniHttp.Failure(403,"Только локальная сеть");
  Set<String> hosts=new HashSet<>();hosts.add("127.0.0.1:"+port);hosts.add("localhost:"+port);for(String ip:addresses)hosts.add(ip+":"+port);
  if(!hosts.contains(request.header("host")))throw new MiniHttp.Failure(403,"Недопустимый адрес");
  if(!request.header("origin").isEmpty()&&!request.header("origin").equals("http://"+request.header("host")))throw new MiniHttp.Failure(403,"Недопустимый источник");
  if(!request.method.equals("GET")&&!request.method.equals("HEAD")&&!request.header("x-ryadom").equals("1"))throw new MiniHttp.Failure(403,"Недопустимый запрос");
  String route=request.path;
  if(request.method.equals("GET")&&Arrays.asList("/","/app.js","/e2ee.js","/style.css","/icon.svg").contains(route)){
   String asset=route.equals("/")?"index.html":route.substring(1);String mime=asset.endsWith(".html")?"text/html; charset=utf-8":asset.endsWith(".js")?"text/javascript; charset=utf-8":asset.endsWith(".css")?"text/css; charset=utf-8":"image/svg+xml";
   request.reply(200,mime,assets.read(asset),null);return;
  }
  if(route.equals("/api/health")&&request.method.equals("GET")){JSONObject chat=state.optJSONObject("chat");request.json(200,new JSONObject().put("app","ryadom").put("version",VERSION).put("protocol",PROTOCOL).put("name","Рядом на Android").put("tls","1").put("fingerprint",tls.fingerprint).put("sessionId",chat==null?"":chat.optString("sessionId")).put("term",chat==null?0:chat.optLong("term",0)).put("hostDeviceId",chat==null?"":chat.optString("hostDeviceId")).toString());return;}
  if(route.startsWith("/api/local/")){
   if(route.equals("/api/local/choose-role")&&request.method.equals("POST")){
    if(!request.loopback())throw new MiniHttp.Failure(403,"Только на этом устройстве");
    String signal=System.getenv("RYADOM_ROLE_SIGNAL");if(signal==null||signal.isEmpty())throw new MiniHttp.Failure(404,"Не найдено");
    boolean nativeAllowed=!nativeKey.isEmpty()&&safeEqual(request.header("x-ryadom-native"),nativeKey);
    Auth session=auth(request);if(!nativeAllowed&&(session==null||!session.device.optBoolean("host")))throw new MiniHttp.Failure(403,"Нужен native-ключ или сессия главного");
    try{Files.write(Paths.get(signal),"choose".getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new MiniHttp.Failure(500,"Не удалось сохранить выбор роли");}
    request.json(200,"{\"ok\":true}");return;
   }
   nativeOnly(request);
   if(route.equals("/api/local/status")&&request.method.equals("GET")){request.json(200,new JSONObject().put("app","ryadom").put("version",VERSION).put("protocol",PROTOCOL).put("role","host").toString());return;}
   if(route.equals("/api/local/host-token")&&request.method.equals("POST")){
    String token=token(32);synchronized(this){long nowMs=System.currentTimeMillis();Iterator<Map.Entry<String,Long>> iterator=hostTokens.entrySet().iterator();while(iterator.hasNext())if(iterator.next().getValue()<nowMs)iterator.remove();hostTokens.put(token,nowMs+hostTokenTtl);}
    request.json(200,new JSONObject().put("token",token).put("expires",hostTokenTtl).toString());return;
   }
   throw new MiniHttp.Failure(404,"Не найдено");
  }
  if(route.equals("/api/host-login")&&request.method.equals("POST")){
   if(!request.loopback())throw new MiniHttp.Failure(403,"Откройте чат на главном устройстве");
   JSONObject body=body(request);String supplied=body.optString("token","");
   if(supplied.isEmpty())throw new MiniHttp.Failure(403,"Откройте чат на главном устройстве");
   Long until;synchronized(this){until=hostTokens.remove(supplied);}
   if(until==null||until<System.currentTimeMillis())throw new MiniHttp.Failure(403,"Ссылка входа устарела. Откройте приложение заново");
   JSONObject device=hostDevice();logEvent("host_login",device.getString("name"),remote);
   String raw=newSession(device);
   sessionReply(request,200,raw,new JSONObject().put("ok",true).put("device",new JSONObject().put("id",device.getString("id")).put("name",device.getString("name")).put("host",true)));return;
  }
  if(route.equals("/api/auth")&&request.method.equals("POST")){
   JSONObject body=body(request);
   if(body.optInt("protocol",0)!=PROTOCOL)throw new MiniHttp.Failure(426,"Обновите Рядом на этом устройстве до протокола 4");
   String requestedId=body.optString("deviceId","").toLowerCase(Locale.ROOT),requestedToken=body.optString("deviceToken","").toLowerCase(Locale.ROOT);
   if(!requestedId.matches("d1-[0-9a-f]{32}")||!requestedToken.matches("[0-9a-f]{64}"))throw new MiniHttp.Failure(400,"Некорректная идентичность устройства");
   JSONObject device;String raw;
   synchronized(this){device=find(state.getJSONArray("devices"),"id",requestedId);if(device==null||device.optBoolean("host")||!safeEqual(device.optString("token"),hash(requestedToken)))throw new MiniHttp.Failure(401,"Устройство не remembered. Подключитесь по коду");raw=newSession(device);}
   logEvent("device_auth",device.getString("name"),remote);
   sessionReply(request,200,raw,new JSONObject().put("ok",true).put("device",new JSONObject().put("id",device.getString("id")).put("name",device.getString("name")).put("host",false)));return;
  }
  if(route.equals("/api/pair")&&request.method.equals("POST")){
   synchronized(this){long[] attempt=attempts.get(remote);long nowMs=System.currentTimeMillis();if(attempt==null||attempt[1]<nowMs){attempt=new long[]{0,nowMs+60000};attempts.put(remote,attempt);}if(++attempt[0]>pairAttempts)throw new MiniHttp.Failure(429,"Слишком много попыток. Подождите минуту");}
   JSONObject body=body(request);
   if(body.optInt("protocol",0)!=PROTOCOL)throw new MiniHttp.Failure(426,"Обновите Рядом на этом устройстве до протокола 4");
   final String requestId;final String deviceName,finalDeviceId,finalTokenHash;
   synchronized(this){
    prunePairs();
    if(pairingDisabled())throw new MiniHttp.Failure(403,"Код истёк. Создайте новый код на главном устройстве");
    if(!safeEqual(body.optString("code","").replaceAll("\\s",""),code))throw new MiniHttp.Failure(403,"Неверный код подключения");
    String name=body.optString("name","").trim();
    if(name.isEmpty())throw new MiniHttp.Failure(400,"Укажите имя устройства");
    name=cleanName(name);name=name.substring(0,Math.min(name.length(),40));
    String requestedId=body.optString("deviceId","").toLowerCase(Locale.ROOT),requestedToken=body.optString("deviceToken","").toLowerCase(Locale.ROOT);
    if(!requestedId.isEmpty()||!requestedToken.isEmpty()){
     if(!requestedId.matches("d1-[0-9a-f]{32}")||!requestedToken.matches("[0-9a-f]{64}"))throw new MiniHttp.Failure(400,"Некорректная идентичность устройства");
     JSONObject existing=find(state.getJSONArray("devices"),"id",requestedId);
     if(find(state.getJSONArray("revoked"),"id",requestedId)!=null)throw new MiniHttp.Failure(403,"Устройство отозвано на главном");
     if(existing!=null&&(existing.optBoolean("host")||!safeEqual(existing.optString("token"),hash(requestedToken))))throw new MiniHttp.Failure(409,"Идентичность устройства не совпадает");
     finalDeviceId=requestedId;finalTokenHash=hash(requestedToken);
    }else{finalDeviceId=null;finalTokenHash=null;}
    if(pendingList().length()>=maxPending)throw new MiniHttp.Failure(429,"Слишком много запросов на подключение. Подождите");
    newCode(true);
    requestId=token(16);deviceName=name;
    JSONObject pendingRequest=new JSONObject().put("requestId",requestId).put("name",deviceName).put("ip",remote).put("created",now()).put("expires",System.currentTimeMillis()+pairTtl).put("status","pending");
    if(finalDeviceId!=null)pendingRequest.put("deviceId",finalDeviceId).put("tokenHash",finalTokenHash);
    pending.put(requestId,pendingRequest);
   }
   broadcast("pairing",pairing(),true);
   logEvent("pair_request",deviceName,remote);
   broadcast("pair_request",new JSONObject().put("requestId",requestId).put("name",deviceName).put("ip",remote).put("created",now()),true);
   request.json(202,new JSONObject().put("pending",true).put("requestId",requestId).toString());return;
  }
  if(route.equals("/api/pair/status")&&request.method.equals("GET")){
   JSONObject pendingRequest;synchronized(this){prunePairs();JSONObject found=pending.get(request.parameter("requestId"));pendingRequest=found==null?null:new JSONObject(found.toString());}
   if(pendingRequest==null||!safeEqual(remote,pendingRequest.optString("ip")))throw new MiniHttp.Failure(404,"Запрос не найден");
   String status=pendingRequest.optString("status");
   if(status.equals("pending")){request.json(202,"{\"pending\":true}");return;}
   if(status.equals("rejected"))throw new MiniHttp.Failure(403,"Подключение отклонено на главном устройстве");
   JSONObject device;String raw=pendingRequest.optString("raw","");
   synchronized(this){
    device=find(state.getJSONArray("devices"),"id",pendingRequest.optString("deviceId"));
    if(device==null)throw new MiniHttp.Failure(410,"Устройство удалено");
    if(raw.isEmpty()){raw=newSession(device);JSONObject current=pending.get(pendingRequest.optString("requestId"));if(current!=null)current.put("raw",raw);}
   }
   sessionReply(request,200,raw,new JSONObject().put("ok",true).put("device",new JSONObject().put("id",device.getString("id")).put("name",device.getString("name")).put("host",false)));return;
  }
  Auth auth=auth(request);if(auth==null)throw new MiniHttp.Failure(401,"Подключите устройство по коду");
  JSONObject device=auth.device;String deviceId=device.getString("id");
  if(sessionEnding&&!request.method.equals("GET")&&!route.equals("/api/host/stop")&&!route.equals("/api/logout"))throw new MiniHttp.Failure(409,"Чат завершается. Дождитесь остановки");
  if(route.equals("/api/trust/roster")&&request.method.equals("GET")){
   JSONObject result;
   synchronized(this){JSONArray devices=new JSONArray(),revoked=new JSONArray();JSONArray all=state.getJSONArray("devices");for(int i=0;i<all.length();i++){JSONObject entry=all.getJSONObject(i);if(entry.optBoolean("host"))continue;devices.put(new JSONObject().put("id",entry.optString("id")).put("name",entry.optString("name")).put("tokenHash",entry.optString("token")).put("created",entry.optString("created")));}JSONArray revokedState=state.getJSONArray("revoked");for(int i=0;i<revokedState.length();i++)revoked.put(revokedState.getJSONObject(i).optString("id"));result=new JSONObject().put("groupId",state.optString("group_id")).put("devices",devices).put("revoked",revoked);}
   request.json(200,result.toString());return;
  }
  if(route.equals("/api/chats")&&request.method.equals("GET")){request.json(200,new JSONObject().put("chats",chatsFor(device)).toString());return;}
  if(route.equals("/api/chats")&&request.method.equals("POST")){
   JSONObject body=body(request);if(!body.optString("type").equals("private"))throw new MiniHttp.Failure(400,"Пока поддерживаются только личные чаты");
   String peerId=body.optString("peerDeviceId","");if(peerId.isEmpty()||peerId.equals(deviceId))throw new MiniHttp.Failure(400,"Выберите другое устройство");
   JSONObject peer=find(state.getJSONArray("devices"),"id",peerId);if(peer==null)throw new MiniHttp.Failure(404,"Устройство не найдено");
   final String id=privateChatId(deviceId,peerId);JSONObject summary=null;
   synchronized(this){JSONObject existing=find(state.getJSONArray("privateChats"),"id",id);if(existing==null){final JSONObject created=new JSONObject().put("id",id).put("type","private").put("title",peer.optString("name")).put("created",now()).put("revision",0).put("deletionRevision",0).put("epoch",0).put("sessionId",state.getJSONObject("chat").optString("sessionId"));change(next->{next.getJSONArray("privateChats").put(created);next.getJSONArray("chatMembers").put(new JSONObject().put("chatId",id).put("deviceId",deviceId).put("joinedAt",now()).put("lastReadSeq",0));next.getJSONArray("chatMembers").put(new JSONObject().put("chatId",id).put("deviceId",peerId).put("joinedAt",now()).put("lastReadSeq",0));});}JSONArray list=chatsFor(device);for(int i=0;i<list.length();i++){JSONObject c=list.getJSONObject(i);if(id.equals(c.optString("id"))){summary=c;break;}}}
   request.json(201,new JSONObject().put("chat",summary).toString());return;
  }
  if(route.startsWith("/api/chats/")&&route.endsWith("/read")&&request.method.equals("POST")){
   final String chatId=route.substring("/api/chats/".length(),route.length()-"/read".length());requireChat(device,chatId);JSONObject body=body(request);final long seq=Math.max(0,body.optLong("seq",0));
   synchronized(this){change(next->{JSONArray members=next.getJSONArray("chatMembers");for(int i=0;i<members.length();i++){JSONObject m=members.getJSONObject(i);if(chatId.equals(m.optString("chatId"))&&deviceId.equals(m.optString("deviceId")))m.put("lastReadSeq",Math.max(m.optLong("lastReadSeq",0),seq));}});}
   request.json(200,new JSONObject().put("ok",true).put("chatId",chatId).put("seq",seq).toString());return;
  }
  if(route.equals("/api/keys")&&request.method.equals("POST")){
   JSONObject body=body(request);String publicKey=body.optString("publicKey","");String algorithm=body.optString("algorithm","ECDH-P256");
   if(publicKey.length()<20||publicKey.length()>4096)throw new MiniHttp.Failure(400,"Некорректный публичный ключ");
   synchronized(this){change(next->{JSONArray keys=next.getJSONArray("deviceKeys");for(int i=keys.length()-1;i>=0;i--){if(deviceId.equals(keys.getJSONObject(i).optString("deviceId")))keys.remove(i);}keys.put(new JSONObject().put("deviceId",deviceId).put("publicKey",publicKey).put("algorithm",algorithm).put("createdAt",now()));});}
   request.json(200,"{\"ok\":true}");return;
  }
  if(route.equals("/api/keys")&&request.method.equals("GET")){
   String[] ids=request.parameter("deviceIds").split(",");JSONArray keys=new JSONArray();synchronized(this){for(String id:ids){if(!id.matches("[a-zA-Z0-9_-]{1,80}"))continue;JSONObject key=find(state.getJSONArray("deviceKeys"),"deviceId",id);if(key!=null)keys.put(new JSONObject().put("deviceId",key.optString("deviceId")).put("publicKey",key.optString("publicKey")).put("algorithm",key.optString("algorithm")));}}
   request.json(200,new JSONObject().put("keys",keys).toString());return;
  }
  if(route.equals("/api/state")&&request.method.equals("GET")){
   JSONObject result;
   synchronized(this){
    JSONArray all=state.getJSONArray("messages"),last=new JSONArray();int total=0;
    for(int i=0;i<all.length();i++)if(all.getJSONObject(i).optString("deletedAt").isEmpty()&&"legacy".equals(all.getJSONObject(i).optString("chatId","legacy")))total++;
    List<JSONObject> recent=new ArrayList<>();
    for(int i=all.length()-1;i>=0&&recent.size()<100;i--){JSONObject message=all.getJSONObject(i);if(message.optString("deletedAt").isEmpty()&&"legacy".equals(message.optString("chatId","legacy")))recent.add(message);}
    Collections.reverse(recent);for(JSONObject message:recent)last.put(message);
    JSONArray urls=new JSONArray();for(String ip:addresses)urls.put("http://"+ip+":"+port);
    result=new JSONObject().put("me",new JSONObject().put("id",deviceId).put("name",device.getString("name")).put("host",device.optBoolean("host"))).put("devices",publicDevices()).put("chats",chatsFor(device)).put("messages",last).put("maxFile",MAX_FILE).put("total",total).put("chat",state.optJSONObject("chat")).put("server",new JSONObject().put("addresses",urls).put("version",VERSION).put("protocol",PROTOCOL).put("direct",true).put("localControls",false).put("tls",true).put("fingerprint",tls.fingerprint));
    if(device.optBoolean("host")){
     result.put("pairing",pairing()).put("pendingRequests",pendingList()).put("storage",new JSONObject().put("totalBytes",maxTotal).put("usedBytes",totalBytes()).put("freeBytes",files.getUsableSpace()));
    }
   }
   request.json(200,result.toString());return;
  }
  if(route.equals("/api/messages")&&request.method.equals("GET")){
   String chatId=request.parameter("chatId");if(chatId.isEmpty())chatId="legacy";requireChat(device,chatId);
   JSONArray result=new JSONArray();long cursor;boolean after=!request.parameter("after").isEmpty();
   try{cursor=Long.parseLong(request.parameter(after?"after":"before"));}catch(Exception e){cursor=after?0:Long.MAX_VALUE;}
   synchronized(this){
    JSONArray all=state.getJSONArray("messages");List<JSONObject> selected=new ArrayList<>();
    for(int i=0;i<all.length();i++){JSONObject message=all.getJSONObject(i);if(!message.optString("deletedAt").isEmpty())continue;if(!chatId.equals(message.optString("chatId","legacy")))continue;if(after?message.getLong("seq")>cursor:message.getLong("seq")<cursor)selected.add(message);}
    int start=after?0:Math.max(0,selected.size()-100);
    for(int i=start;i<Math.min(selected.size(),start+100);i++)result.put(selected.get(i));
   }
   request.json(200,result.toString());return;
  }
  if(route.equals("/api/messages")&&request.method.equals("POST")){
   if(!allowRate(deviceId,"msg",msgPerMin))throw new MiniHttp.Failure(429,"Слишком часто. Подождите минуту");
   JSONObject body=body(request);String text=body.optString("text").trim();String chatId=body.optString("chatId","legacy");boolean encrypted=body.optBoolean("encrypted",false);requireChat(device,chatId);
   int limit=encrypted?64000:12000;if(text.isEmpty()||text.length()>limit)throw new MiniHttp.Failure(400,"Сообщение должно содержать от 1 до "+limit+" символов");
   String requestId=body.optString("requestId","");if(requestId.isEmpty())requestId=UUID.randomUUID().toString();
   request.json(201,addMessage(device,text,null,requestId.substring(0,Math.min(80,requestId.length())),chatId,encrypted).toString());return;
  }
  if(route.startsWith("/api/messages/")&&request.method.equals("DELETE")){
   String id=route.substring("/api/messages/".length());
   JSONObject row;JSONObject fileRow=null;
   synchronized(this){
    row=find(state.getJSONArray("messages"),"id",id);
    if(row!=null){JSONObject file=row.optJSONObject("file");if(file!=null)fileRow=find(state.getJSONArray("files"),"id",file.optString("id"));}
   }
   if(row==null)throw new MiniHttp.Failure(404,"Сообщение не найдено");
   if(!row.optString("deletedAt").isEmpty()){JSONObject chat;JSONObject pending; synchronized(this){chat=state.getJSONObject("chat");pending=null;JSONArray fileArray=state.getJSONArray("files");for(int i=0;i<fileArray.length();i++)if(id.equals(fileArray.getJSONObject(i).optString("messageId"))&&"deleting".equals(fileArray.getJSONObject(i).optString("state")))pending=fileArray.getJSONObject(i);}request.json(200,new JSONObject().put("ok",true).put("id",id).put("chatId","legacy").put("revision",chat.optLong("revision",0)).put("deletionRevision",chat.optLong("deletionRevision",0)).put("freedBytes",0).put("cleanupPending",pending!=null).toString());return;}
   if(!row.optString("deviceId").equals(deviceId)&&!device.optBoolean("host"))throw new MiniHttp.Failure(403,"Удалить можно только своё сообщение");
   long freedBytes=0;
   final JSONObject selectedFile=fileRow;final long[] revision=new long[1];final long[] deletionRevision=new long[1];
   synchronized(this){
    change(next->{
     JSONObject current=find(next.getJSONArray("messages"),"id",id);
     current.put("deletedAt",now()).put("deletedBy",deviceId).put("text","").put("file",JSONObject.NULL);
     if(selectedFile!=null){JSONObject file=find(next.getJSONArray("files"),"id",selectedFile.optString("id"));if(file!=null)file.put("state","deleting");}
     JSONObject chat=next.getJSONObject("chat");chat.put("revision",chat.optLong("revision",0)+1).put("deletionRevision",chat.optLong("deletionRevision",0)+1);revision[0]=chat.optLong("revision");deletionRevision[0]=chat.optLong("deletionRevision");
    });
   }
   boolean cleanupPending=false;
   if(selectedFile!=null){
    File disk=new File(files,selectedFile.getString("id"));
    try{if(disk.exists()&&!disk.delete())throw new IOException("Не удалось удалить файл");synchronized(this){change(next->remove(next.getJSONArray("files"),"id",selectedFile.getString("id")));}freedBytes=selectedFile.optLong("size",0);}
    catch(Exception e){cleanupPending=true;}
   }
   logEvent("message_deleted",id,remote);
   broadcast("message_deleted",new JSONObject().put("id",id).put("chatId","legacy").put("revision",revision[0]).put("deletionRevision",deletionRevision[0]).put("freedBytes",freedBytes).put("deletedBy",deviceId).put("cleanupPending",cleanupPending),false);
   request.json(200,new JSONObject().put("ok",true).put("id",id).put("chatId","legacy").put("revision",revision[0]).put("deletionRevision",deletionRevision[0]).put("freedBytes",freedBytes).put("cleanupPending",cleanupPending).toString());return;
  }
  if(route.equals("/api/chat/clear/preview")&&request.method.equals("GET")){
   if(!device.optBoolean("host"))throw new MiniHttp.Failure(403,"Очистка доступна на главном устройстве");
   JSONObject result;
   synchronized(this){
    JSONArray all=state.getJSONArray("messages");int active=0;for(int i=0;i<all.length();i++)if(all.getJSONObject(i).optString("deletedAt").isEmpty())active++;
    long bytes=0;int activeFiles=0;JSONArray filesState=state.getJSONArray("files");for(int i=0;i<filesState.length();i++){JSONObject file=filesState.getJSONObject(i);if("ready".equals(file.optString("state"))){activeFiles++;bytes+=file.optLong("size",0);}}
    int temp=0;File[] local=files.listFiles();if(local!=null)for(File file:local)if(file.getName().endsWith(".part"))temp++;
    JSONObject chat=state.getJSONObject("chat");
    result=new JSONObject().put("chatId","legacy").put("revision",chat.optLong("revision",0)).put("epoch",chat.optLong("epoch",0)).put("activeMessages",active).put("activeFiles",activeFiles).put("bytes",bytes).put("tempFiles",temp);
   }
   request.json(200,result.toString());return;
  }
  if(route.equals("/api/chat/clear")&&request.method.equals("POST")){
   if(!device.optBoolean("host"))throw new MiniHttp.Failure(403,"Очистка доступна на главном устройстве");
   JSONObject body=body(request);if(!body.optBoolean("confirm",false))throw new MiniHttp.Failure(400,"Подтвердите очистку");
   String rawOperation=body.optString("operationId","");if(rawOperation.isEmpty())throw new MiniHttp.Failure(400,"Нужен идентификатор операции");final String operationId=rawOperation.substring(0,Math.min(80,rawOperation.length()));
   final List<String> fileIds=new ArrayList<>();final List<Long> fileSizes=new ArrayList<>();final List<String> tempNames=new ArrayList<>();final long[] revision=new long[1],deletionRevision=new long[1],epoch=new long[1];final int[] active=new int[1];final long[] bytes=new long[1];
   final List<MiniHttp.Request> cancel=new ArrayList<>();final List<String> cancelIds=new ArrayList<>();JSONObject existingResponse=null;
   synchronized(this){
    JSONObject existing=find(state.getJSONArray("operations"),"id",operationId);
    if(existing!=null){existingResponse=operationResponse(existing);}
    else{
     JSONObject chat=state.getJSONObject("chat");
     if(body.optLong("revision",-1)!=chat.optLong("revision",0))throw new MiniHttp.Failure(409,"Чат изменился. Обновите данные и повторите");
     JSONArray all=state.getJSONArray("messages");for(int i=0;i<all.length();i++)if(all.getJSONObject(i).optString("deletedAt").isEmpty())active[0]++;
     JSONArray filesState=state.getJSONArray("files");for(int i=0;i<filesState.length();i++){JSONObject file=filesState.getJSONObject(i);if("ready".equals(file.optString("state"))||"deleting".equals(file.optString("state"))){fileIds.add(file.getString("id"));fileSizes.add(file.optLong("size",0));bytes[0]+=file.optLong("size",0);}}
     File[] local=files.listFiles();if(local!=null)for(File file:local)if(file.getName().endsWith(".part"))tempNames.add(file.getName());
     change(next->{
      JSONArray messages=next.getJSONArray("messages");for(int i=0;i<messages.length();i++){JSONObject message=messages.getJSONObject(i);if(message.optString("deletedAt").isEmpty())message.put("deletedAt",now()).put("deletedBy",deviceId).put("text","").put("file",JSONObject.NULL);}
      JSONArray nextFiles=next.getJSONArray("files");for(int i=0;i<nextFiles.length();i++){JSONObject file=nextFiles.getJSONObject(i);if("ready".equals(file.optString("state"))||"deleting".equals(file.optString("state")))file.put("state","deleting");}
      JSONObject nextChat=next.getJSONObject("chat");nextChat.put("revision",nextChat.optLong("revision",0)+1).put("deletionRevision",nextChat.optLong("deletionRevision",0)+1).put("epoch",nextChat.optLong("epoch",0)+1);revision[0]=nextChat.optLong("revision");deletionRevision[0]=nextChat.optLong("deletionRevision");epoch[0]=nextChat.optLong("epoch");
      JSONArray operations=next.getJSONArray("operations");operations.put(new JSONObject().put("id",operationId).put("type","clear").put("chatId","legacy").put("actorId",deviceId).put("status","deleting").put("createdAt",now()).put("updatedAt",now()).put("result",new JSONObject().put("revision",revision[0]).put("deletionRevision",deletionRevision[0]).put("epoch",epoch[0]).put("messages",active[0]).put("files",fileIds.size()).put("bytes",bytes[0]).put("tempFiles",tempNames.size())));while(operations.length()>100)operations.remove(0);
     });
     for(Map.Entry<String,Long> entry:uploadEpochs.entrySet())if(entry.getValue()<epoch[0]){MiniHttp.Request pending=uploadRequests.get(entry.getKey());if(pending!=null){cancel.add(pending);cancelIds.add(entry.getKey());}}
    }
   }
   if(existingResponse!=null){request.json(200,existingResponse.toString());return;}
   for(MiniHttp.Request pending:cancel)try{pending.close();}catch(Exception ignored){}
   long uploadDeadline=System.currentTimeMillis()+3000;
   while(System.currentTimeMillis()<uploadDeadline){boolean uploadActive=false;synchronized(this){for(String id:cancelIds)if(uploadIds.contains(id)){uploadActive=true;break;}}if(!uploadActive)break;try{Thread.sleep(50);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();break;}}
   boolean uploadsPending=false;synchronized(this){for(String id:cancelIds)if(uploadIds.contains(id)){uploadsPending=true;break;}}

   long freedBytes=0;boolean cleanupPending=uploadsPending;
   for(int i=0;i<fileIds.size();i++){
    final String fileId=fileIds.get(i);File disk=new File(files,fileId);
    try{if(disk.exists()&&!disk.delete())throw new IOException();freedBytes+=fileSizes.get(i);synchronized(this){change(next->remove(next.getJSONArray("files"),"id",fileId));}}
    catch(Exception e){cleanupPending=true;}
   }
   int tempRemaining=0;for(String name:tempNames){try{if(!new File(files,name).delete()&&new File(files,name).exists())tempRemaining++;}catch(Exception e){tempRemaining++;}}
   if(tempRemaining>0)cleanupPending=true;
   final String status=cleanupPending?"partial":"done";final JSONObject result=new JSONObject().put("revision",revision[0]).put("deletionRevision",deletionRevision[0]).put("epoch",epoch[0]).put("messages",active[0]).put("files",fileIds.size()).put("bytes",bytes[0]).put("freedBytes",freedBytes).put("tempFiles",tempRemaining).put("cleanupPending",cleanupPending);
   synchronized(this){change(next->{JSONObject op=find(next.getJSONArray("operations"),"id",operationId);if(op!=null)op.put("status",status).put("updatedAt",now()).put("result",result);});}
   logEvent("chat_cleared",operationId,remote);
   broadcast("chat_cleared",new JSONObject().put("chatId","legacy").put("sessionId",state.getJSONObject("chat").optString("sessionId")).put("revision",revision[0]).put("deletionRevision",deletionRevision[0]).put("epoch",epoch[0]).put("operationId",operationId).put("freedBytes",freedBytes).put("tempFiles",tempRemaining).put("cleanupPending",cleanupPending),false);
   request.json(202,new JSONObject().put("operationId",operationId).put("status",status).put("revision",revision[0]).put("deletionRevision",deletionRevision[0]).put("epoch",epoch[0]).put("freedBytes",freedBytes).put("tempFiles",tempRemaining).put("cleanupPending",cleanupPending).toString());return;
  }
  if(route.startsWith("/api/operations/")&&request.method.equals("GET")){
   if(!device.optBoolean("host"))throw new MiniHttp.Failure(403,"Операции доступны на главном устройстве");
   JSONObject operation;String id=route.substring("/api/operations/".length());synchronized(this){operation=find(state.getJSONArray("operations"),"id",id);}
   if(operation==null)throw new MiniHttp.Failure(404,"Операция не найдена");request.json(200,operationResponse(operation).toString());return;
  }
  if(route.equals("/api/files")&&request.method.equals("POST")){upload(request,device);return;}
  if(route.startsWith("/files/")&&(request.method.equals("GET")||request.method.equals("HEAD"))){download(request,device,route.substring(7));return;}
  if(route.equals("/api/events")&&request.method.equals("GET")){stream(request,auth);return;}
  if(route.equals("/api/device")&&request.method.equals("PATCH")){
   String name=body(request).optString("name").trim();if(name.isEmpty())throw new MiniHttp.Failure(400,"Укажите имя");
   final String updated=cleanName(name).substring(0,Math.min(cleanName(name).length(),40));
   synchronized(this){change(next->{JSONObject current=find(next.getJSONArray("devices"),"id",deviceId);if(current!=null)current.put("name",updated);});}
   devicesChanged();request.json(200,"{\"ok\":true}");return;
  }
  if(route.equals("/api/logout")&&request.method.equals("POST")){
   String raw=rawCookie(request);
   if(!raw.isEmpty()){String session=hash(raw);removeSession(session);closeStreams(session,null,"logout");}
   logEvent("logout",device.getString("name"),remote);
   Map<String,String> headers=new LinkedHashMap<>();headers.put("Set-Cookie",clearCookie());
   request.reply(200,"application/json; charset=utf-8","{\"ok\":true}".getBytes(StandardCharsets.UTF_8),headers);return;
  }
  if(route.startsWith("/api/host/")){
   if(!device.optBoolean("host"))throw new MiniHttp.Failure(403,"Доступно на главном устройстве");
   if(route.equals("/api/host/pairing")&&request.method.equals("POST")){
    newCode(body(request).optBoolean("enabled",true));
    JSONObject value=pairing();broadcast("pairing",value,true);request.json(200,value.toString());return;
   }
   if(route.equals("/api/host/pair/approve")&&request.method.equals("POST")){
    JSONObject body=body(request);JSONObject pendingRequest;JSONObject created;
    synchronized(this){
     prunePairs();pendingRequest=pending.get(body.optString("requestId",""));
     if(pendingRequest==null||!pendingRequest.optString("status").equals("pending"))throw new MiniHttp.Failure(404,"Запрос не найден или устарел");
     String approvedId=pendingRequest.optString("deviceId",""),approvedToken=pendingRequest.optString("tokenHash","");
     if(approvedId.isEmpty())approvedId=UUID.randomUUID().toString();
     created=new JSONObject().put("id",approvedId).put("name",pendingRequest.optString("name")).put("host",false).put("created",now());
     if(!approvedToken.isEmpty())created.put("token",approvedToken);
     JSONObject prior=find(state.getJSONArray("devices"),"id",approvedId);
     if(prior!=null)change(next->{JSONObject current=find(next.getJSONArray("devices"),"id",created.getString("id"));if(current!=null)current.put("name",created.getString("name"));});
     else change(next->next.getJSONArray("devices").put(created));
     pendingRequest.put("status","approved").put("deviceId",created.getString("id")).put("approved",now());
     pendingRequest.put("raw",newSession(created));
    }
    logEvent("pair_approved",created.getString("name"),pendingRequest.optString("ip"));
    devicesChanged();
    broadcast("pair_decided",new JSONObject().put("requestId",pendingRequest.optString("requestId")).put("approved",true),true);
    request.json(200,new JSONObject().put("ok",true).put("device",new JSONObject().put("id",created.getString("id")).put("name",created.getString("name")).put("host",false)).toString());return;
   }
   if(route.equals("/api/host/pair/reject")&&request.method.equals("POST")){
    JSONObject pendingRequest;
    synchronized(this){
     prunePairs();pendingRequest=pending.get(body(request).optString("requestId",""));
     if(pendingRequest==null||!pendingRequest.optString("status").equals("pending"))throw new MiniHttp.Failure(404,"Запрос не найден или устарел");
     pendingRequest.put("status","rejected");
    }
    logEvent("pair_rejected",pendingRequest.optString("name"),pendingRequest.optString("ip"));
    broadcast("pair_decided",new JSONObject().put("requestId",pendingRequest.optString("requestId")).put("approved",false),true);
    request.json(200,"{\"ok\":true}");return;
   }
   if(route.equals("/api/host/logout-all")&&request.method.equals("POST")){
    synchronized(this){change(next->next.put("sessions",new JSONArray()));}
    closeStreams(null,null,"logout_all");
    logEvent("logout_all",device.getString("name"),remote);
    sessionReply(request,200,newSession(device),new JSONObject().put("ok",true));return;
   }
   if(route.equals("/api/host/events")&&request.method.equals("GET")){
    JSONArray recent=new JSONArray();
    synchronized(this){JSONArray events=state.getJSONArray("events");for(int i=events.length()-1;i>=0&&recent.length()<50;i--)recent.put(events.getJSONObject(i));}
    request.json(200,new JSONObject().put("events",recent).toString());return;
   }
   if(route.startsWith("/api/host/devices/")&&request.method.equals("DELETE")){
    final String id=route.substring("/api/host/devices/".length());
    synchronized(this){change(next->{JSONArray devices=next.getJSONArray("devices");JSONObject target=find(devices,"id",id);if(target!=null&&!target.optBoolean("host")){remove(devices,"id",id);remove(next.getJSONArray("sessions"),"deviceId",id);JSONArray revoked=next.getJSONArray("revoked");if(find(revoked,"id",id)==null)revoked.put(new JSONObject().put("id",id));}});}
    closeStreams(null,id,"revoked");
    logEvent("device_revoked",id,remote);
    devicesChanged();request.json(200,"{\"ok\":true}");return;
   }
   if(route.equals("/api/host/stop")&&request.method.equals("POST")){
    request.json(200,"{\"ok\":true}");new Thread(()->{try{Thread.sleep(200);}catch(Exception ignored){}stop.run();}).start();return;
   }
  }
  throw new MiniHttp.Failure(404,"Не найдено");
 }
 private void stream(MiniHttp.Request request,Auth auth) throws Exception {
  final String deviceId=auth.device.getString("id");final boolean host=auth.device.optBoolean("host");
  final Stream stream=new Stream(request,deviceId,host,auth.session,auth.expires);
  synchronized(this){
   JSONObject session=find(state.getJSONArray("sessions"),"token",auth.session);
   if(session==null||instant(session.optString("expires"))<=System.currentTimeMillis())throw new MiniHttp.Failure(401,"Сессия истекла. Подключите устройство заново");
   if(find(state.getJSONArray("devices"),"id",deviceId)==null)throw new MiniHttp.Failure(401,"Доступ устройства отозван");
   int count=deviceStreams.containsKey(deviceId)?deviceStreams.get(deviceId):0;
   if(count>=MAX_STREAMS)throw new MiniHttp.Failure(429,"Слишком много открытых окон чата. Закройте лишние и повторите.");
   deviceStreams.put(deviceId,count+1);
   streams.put(request,stream);request.detach();
  }
  try{
   request.headStream(200,"text/event-stream",null);
   JSONArray initial=publicDevices();
   request.out.write(("retry: 1500\n\n"+eventData("devices",initial)).getBytes(StandardCharsets.UTF_8));request.out.flush();
   sse.execute(()->pump(stream));
   broadcastExcept(request,"devices",initial,false);
  }catch(RejectedExecutionException e){closeStream(stream);throw new MiniHttp.Failure(503,"Чат останавливается");}
  catch(Exception e){closeStream(stream);throw e;}
 }
 private void pump(Stream stream){
  try{
   while(!http.closed&&!stream.closed){
    long nowMs=System.currentTimeMillis();
    if(stream.expires<=nowMs){try{synchronized(stream.request.out){stream.request.out.write(eventData("expired",new JSONObject()).getBytes(StandardCharsets.UTF_8));stream.request.out.flush();}}catch(Exception ignored){}break;}
    String data=stream.queue.poll(Math.max(1,Math.min(20000,stream.expires-nowMs)),TimeUnit.MILLISECONDS);
    synchronized(stream.request.out){
     stream.request.out.write((data==null?": alive\n\n":data).getBytes(StandardCharsets.UTF_8));
     stream.request.out.flush();
    }
    if(stream.closeAfterWrite)break;
   }
  }catch(Exception ignored){}
  finally{closeStream(stream);try{devicesChanged();}catch(Exception ignored){}}
 }
 private synchronized void closeStream(Stream stream){
  if(stream.closed)return;
  stream.closed=true;streams.remove(stream.request);stream.request.close();
  int count=deviceStreams.containsKey(stream.deviceId)?deviceStreams.get(stream.deviceId):0;if(count<=1)deviceStreams.remove(stream.deviceId);else deviceStreams.put(stream.deviceId,count-1);
 }
 private void closeStreams(String session,String deviceId,String event){
  for(Stream stream:new ArrayList<>(streams.values())){
   boolean match=(session!=null&&session.equals(stream.session))||(deviceId!=null&&deviceId.equals(stream.deviceId))||(session==null&&deviceId==null);
   if(!match)continue;
   if(event==null){closeStream(stream);continue;}
   stream.queue.clear();stream.closeAfterWrite=true;if(!stream.queue.offer(eventData(event,new JSONObject())))closeStream(stream);
  }
 }
 private void upload(MiniHttp.Request request,JSONObject device) throws Exception {
  String deviceId=device.getString("id");
  if(!allowRate(deviceId,"up",uploadPerMin))throw new MiniHttp.Failure(429,"Слишком много передач. Подождите минуту");
  long size=request.length;
  if(size<1||size>MAX_FILE)throw new MiniHttp.Failure(413,"Файл должен быть от 1 байта до 512 МБ");
  String requested=request.parameter("requestId");if(requested.isEmpty())requested=UUID.randomUUID().toString();
  final String requestId=requested.substring(0,Math.min(requested.length(),80));
  final String chatId=request.parameter("chatId").isEmpty()?"legacy":request.parameter("chatId");requireChat(device,chatId);
  final boolean encrypted="1".equals(request.parameter("encrypted"));String encryptedMeta=encrypted?request.parameter("meta"):"";if(encryptedMeta.length()>16000)throw new MiniHttp.Failure(400,"Слишком большой зашифрованный заголовок файла");
  JSONObject already=null;
  synchronized(this){
   JSONObject old=find(state.getJSONArray("messages"),"requestId",requestId);
   if(old!=null){if(!old.optString("deletedAt").isEmpty())throw new MiniHttp.Failure(410,"Сообщение было удалено");if(old.optString("deviceId").equals(deviceId))already=old;}
  }
  if(already!=null){request.discard();request.json(200,already.toString());return;}
  final long epoch;
  synchronized(this){
   if(uploadIds.contains(requestId)||(uploads.containsKey(deviceId)&&uploads.get(deviceId)>=2))throw new MiniHttp.Failure(429,"Дождитесь текущей передачи");
   long used=totalBytes()+reservedTotal,deviceUsed=deviceBytes(deviceId)+reserved(deviceId);
   if(used+size>maxTotal||deviceUsed+size>maxDevice)throw new MiniHttp.Failure(507,"Хранилище заполнено. Удалите старые файлы на главном устройстве");
   if(files.getUsableSpace()-reservedTotal<size+minFree)throw new MiniHttp.Failure(507,"На главном устройстве мало свободного места");
   uploadIds.add(requestId);uploads.put(deviceId,(uploads.containsKey(deviceId)?uploads.get(deviceId):0)+1);
   uploadRequests.put(requestId,request);uploadEpochs.put(requestId,state.getJSONObject("chat").optLong("epoch",0));epoch=uploadEpochs.get(requestId);
   reservedTotal+=size;reserved.put(deviceId,reserved(deviceId)+size);
  }
  String id=UUID.randomUUID().toString();File temporary=new File(files,id+".part"),file=new File(files,id);boolean committed=false;
  try{
   try(OutputStream out=new FileOutputStream(temporary)){request.transfer(out);}
   String mime=sniff(temporary);
   synchronized(this){
    if(sessionEnding||state.getJSONObject("chat").optLong("epoch",0)!=epoch)throw new MiniHttp.Failure(409,"Чат был очищен. Отправьте файл заново");
    if(totalBytes()+size>maxTotal||deviceBytes(deviceId)+size>maxDevice)throw new MiniHttp.Failure(507,"Хранилище заполнено. Удалите старые файлы на главном устройстве");
   }
   if(files.getUsableSpace()<minFree)throw new MiniHttp.Failure(507,"На главном устройстве мало свободного места");
   Files.move(temporary.toPath(),file.toPath());
   JSONObject value=encrypted?new JSONObject().put("id",id).put("name","encrypted").put("mime","application/octet-stream").put("size",size).put("deviceId",deviceId).put("chatId",chatId).put("encrypted",true):new JSONObject().put("id",id).put("name",cleanName(request.parameter("name"))).put("mime",mime).put("size",size).put("deviceId",deviceId).put("chatId",chatId);
   JSONObject message;
   synchronized(this){
    if(sessionEnding||state.getJSONObject("chat").optLong("epoch",0)!=epoch)throw new MiniHttp.Failure(409,"Чат был очищен. Отправьте файл заново");
    message=addMessage(device,encrypted?encryptedMeta:"",value,requestId,chatId,encrypted);
   }
   committed=true;request.json(201,message.toString());
  }finally{
   temporary.delete();if(!committed)file.delete();
   synchronized(this){
    uploadIds.remove(requestId);uploadRequests.remove(requestId);uploadEpochs.remove(requestId);uploads.put(deviceId,Math.max(0,(uploads.containsKey(deviceId)?uploads.get(deviceId):1)-1));
    reservedTotal=Math.max(0,reservedTotal-size);long remaining=reserved(deviceId)-size;if(remaining<=0)reserved.remove(deviceId);else reserved.put(deviceId,remaining);
   }
  }
 }
 private static String sniff(File file) throws IOException {byte[] bytes=new byte[32];int read;try(InputStream in=new FileInputStream(file)){read=in.read(bytes);}if(read<12)return "application/octet-stream";if(bytes[0]==(byte)137&&bytes[1]==80&&bytes[2]==78&&bytes[3]==71)return "image/png";if(bytes[0]==(byte)255&&bytes[1]==(byte)216&&bytes[2]==(byte)255)return "image/jpeg";String start=new String(bytes,StandardCharsets.ISO_8859_1);if(start.startsWith("GIF87a")||start.startsWith("GIF89a"))return "image/gif";if(start.startsWith("RIFF")&&start.substring(8,12).equals("WEBP"))return "image/webp";if(start.substring(4,8).equals("ftyp"))return start.substring(8,12).matches("(hei.|mif.|avi.)")?"application/octet-stream":"video/mp4";if(bytes[0]==26&&bytes[1]==69&&bytes[2]==(byte)223&&bytes[3]==(byte)163)return "video/webm";return "application/octet-stream";}
 private void download(MiniHttp.Request request,JSONObject device,String id) throws Exception {
  JSONObject file;JSONObject message=null;
  synchronized(this){file=find(state.getJSONArray("files"),"id",id);if(file!=null&&"ready".equals(file.optString("state"))&&!file.optString("messageId").isEmpty())message=find(state.getJSONArray("messages"),"id",file.optString("messageId"));}
  if(file==null||message==null||!message.optString("deletedAt").isEmpty())throw new MiniHttp.Failure(404,"Файл не найден");
  requireChat(device,file.optString("chatId","legacy"));
  File disk=new File(files,file.getString("id"));if(!disk.isFile())throw new MiniHttp.Failure(404,"Файл удалён");
  long size=file.getLong("size"),start=0,end=size-1;int status=200;String range=request.header("range");Map<String,String> headers=new LinkedHashMap<>();headers.put("Accept-Ranges","bytes");
  if(!range.isEmpty()){
   try{
    if(!range.matches("bytes=[0-9]*-[0-9]*")||range.equals("bytes=-"))throw new Exception();
    String[] parts=range.substring(6).split("-",-1);
    if(parts[0].isEmpty())start=Math.max(0,size-Long.parseLong(parts[1]));else{start=Long.parseLong(parts[0]);if(!parts[1].isEmpty())end=Math.min(end,Long.parseLong(parts[1]));}
    if(start>end||start>=size)throw new Exception();status=206;headers.put("Content-Range","bytes "+start+"-"+end+"/"+size);
   }catch(Exception e){headers.put("Content-Range","bytes */"+size);request.reply(416,"text/plain",new byte[0],headers);return;}
  }
  String mime=file.getString("mime");boolean inline=!request.target.contains("?download")&&(mime.startsWith("image/")||mime.startsWith("video/"));
  headers.put("Content-Disposition",(inline?"inline":"attachment")+"; filename=\"file\"; filename*=UTF-8''"+URLEncoder.encode(file.getString("name"),"UTF-8").replace("+","%20"));
  request.head(status,mime,end-start+1,headers);if(request.method.equals("HEAD"))return;
  try(FileInputStream in=new FileInputStream(disk)){in.getChannel().position(start);MiniHttp.copy(in,request.out,end-start+1);}
 }
 public void close(){
  endEphemeralSession();
  for(Stream stream:new ArrayList<>(streams.values()))closeStream(stream);
  http.close();sse.shutdownNow();
 }
 private static final class Auth {
  final JSONObject device;final String session;final long expires;
  Auth(JSONObject device,String session,long expires){this.device=device;this.session=session;this.expires=expires;}
 }
 private static final class Stream {
  final MiniHttp.Request request;final String deviceId;final boolean host;final String session;final long expires;final BlockingQueue<String> queue=new ArrayBlockingQueue<>(256);
  volatile boolean closed,closeAfterWrite;
  Stream(MiniHttp.Request request,String deviceId,boolean host,String session,long expires){this.request=request;this.deviceId=deviceId;this.host=host;this.session=session;this.expires=expires;}
 }
}
