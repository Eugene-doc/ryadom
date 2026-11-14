package local.ryadom.chat;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import org.json.*;

/** JVM checks: SSE is bound to its session and revoked; one-shot schema migration never resurrects a legacy token. */
public final class SessionSecurityTest {
 private static final class Response {
  final String raw;final int status;final String body;
  Response(String raw){this.raw=raw;int end=raw.indexOf("\r\n");status=end<0?0:Integer.parseInt(raw.substring(0,end).split(" ")[1]);int split=raw.indexOf("\r\n\r\n");body=split<0?"":raw.substring(split+4);}
  String cookie(){for(String line:raw.split("\r\n"))if(line.toLowerCase(Locale.ROOT).startsWith("set-cookie: ryadom_sid="))return line.substring("set-cookie: ".length()).split(";")[0];return "";}
  JSONObject json(){return new JSONObject(body);}
 }
 public static void main(String[] args) throws Exception {
  File first=Files.createTempDirectory("ryadom-session").toFile();
  File legacy=Files.createTempDirectory("ryadom-legacy").toFile();
  try{
   int port=freePort();
   ChatHost host=new ChatHost(first,Collections.<String>emptyList(),port,name->new byte[0],()->{});
   try{
    String hostCookie=hostLogin(port,host);
    String code=pairingCode(port,hostCookie);
    Device device=pair(port,hostCookie,code,"Первый телефон");
    Socket stream=sse(port,device.cookie);
    Response message=request(port,"POST","/api/messages","{\"text\":\"до отзыва\",\"requestId\":\"before-revoke\"}",hostCookie);
    check(message.status==201,"message before revoke: "+message.status);
    String events=readUntil(stream,"event: message",4000);
    check(events.contains("до отзыва"),"SSE delivers messages");
    Response revoked=request(port,"DELETE","/api/host/devices/"+device.id,"",hostCookie);
    check(revoked.status==200,"device revoke: "+revoked.status);
    String tail=readUntilEof(stream,5000);
    check(tail.contains("revoked")||tail.isEmpty(),"revoked stream tail");
    check(request(port,"GET","/api/state","",device.cookie).status==401,"revoked cookie must be rejected");
    check(request(port,"GET","/api/events","",device.cookie).status==401,"revoked stream registration must be rejected");

    Device second=pair(port,hostCookie,currentCode(port,hostCookie),"Второй телефон");
    Socket secondStream=sse(port,second.cookie);
    Response logoutAll=request(port,"POST","/api/host/logout-all","{}",hostCookie);
    check(logoutAll.status==200,"logout-all: "+logoutAll.status);
    check(!logoutAll.cookie().isEmpty(),"logout-all must rotate the host session");
    readUntilEof(secondStream,5000);
    check(request(port,"GET","/api/state","",hostCookie).status==401,"old host session must be rejected");
    check(request(port,"GET","/api/state","",second.cookie).status==401,"old client session must be rejected");
    check(request(port,"GET","/api/events","",second.cookie).status==401,"old client stream registration must be rejected");
    check(request(port,"GET","/api/state","",logoutAll.cookie()).status==200,"current host session must survive");

    Device third=pair(port,logoutAll.cookie(),currentCode(port,logoutAll.cookie()),"Третий телефон");
    Socket thirdStream=sse(port,third.cookie);
    check(request(port,"POST","/api/logout","{}",third.cookie).status==200,"logout: third device");
    readUntilEof(thirdStream,5000);
    check(request(port,"GET","/api/state","",third.cookie).status==401,"logged out cookie must be rejected");
   }finally{host.close();}

   int legacyPort=freePort();
   String rawLegacy=hex(32);writeLegacy(legacy,rawLegacy);
   ChatHost migrated=new ChatHost(legacy,Collections.<String>emptyList(),legacyPort,name->new byte[0],()->{});
   String newHostCookie;
   try{
    check(request(legacyPort,"GET","/api/state","",cookie("ryadom_sid="+rawLegacy)).status==200,"legacy cookie must log in after migration");
    newHostCookie=hostLogin(legacyPort,migrated);
    check(request(legacyPort,"POST","/api/host/logout-all","{}",newHostCookie).status==200,"logout-all after migration");
    check(request(legacyPort,"GET","/api/state","",cookie("ryadom_sid="+rawLegacy)).status==401,"legacy cookie must be revoked");
   }finally{migrated.close();}

   int restartPort=freePort();
   ChatHost restarted=new ChatHost(legacy,Collections.<String>emptyList(),restartPort,name->new byte[0],()->{});
   try{
    check(request(restartPort,"GET","/api/state","",cookie("ryadom_sid="+rawLegacy)).status==401,"legacy cookie must stay revoked after restart");
    JSONObject state=new JSONObject(new String(Files.readAllBytes(new File(legacy,"chat.json").toPath()),StandardCharsets.UTF_8));
    check(state.optInt("schema",0)==2,"schema must be 2 after migration: "+state.opt("schema"));
    JSONArray devices=state.getJSONArray("devices"),sessions=state.getJSONArray("sessions");
    for(int i=0;i<devices.length();i++)check(!devices.getJSONObject(i).has("token"),"legacy device token must be removed");
    for(int i=0;i<sessions.length();i++)check(!"legacy-device".equals(sessions.getJSONObject(i).optString("deviceId")),"legacy session must not be recreated");
   }finally{restarted.close();}
   System.out.println("SSE session binding and one-shot legacy migration checks passed");
  }finally{delete(first);delete(legacy);}
 }
 private static final class Device {final String id,cookie;Device(String id,String cookie){this.id=id;this.cookie=cookie;}}
 private static String hostLogin(int port,ChatHost host) throws Exception {
  String local=host.localUrl();String token=local.substring(local.indexOf("#t=")+3);
  Response login=request(port,"POST","/api/host-login","{\"token\":\""+token+"\"}",null);
  check(login.status==200,"host-login: "+login.status);
  return login.cookie();
 }
 private static String pairingCode(int port,String hostCookie) throws Exception {
  Response state=request(port,"GET","/api/state","",hostCookie);
  check(state.status==200,"host state: "+state.status);
  return state.json().getJSONObject("pairing").getString("code");
 }
 private static String currentCode(int port,String hostCookie) throws Exception {
  Response pairing=request(port,"POST","/api/host/pairing","{}",hostCookie);
  check(pairing.status==200,"new pairing code: "+pairing.status);
  return pairing.json().getString("code");
 }
 private static Device pair(int port,String hostCookie,String code,String name) throws Exception {
  Response pending=request(port,"POST","/api/pair","{\"name\":\""+name+"\",\"code\":\""+code+"\"}",null);
  check(pending.status==202,"pair request: "+pending.status);
  String requestId=pending.json().getString("requestId");
  check(request(port,"POST","/api/host/pair/approve","{\"requestId\":\""+requestId+"\"}",hostCookie).status==200,"pair approve");
  Response status=request(port,"GET","/api/pair/status?requestId="+requestId,"",null);
  check(status.status==200,"pair status: "+status.status);
  return new Device(status.json().getJSONObject("device").getString("id"),status.cookie());
 }
 private static Socket sse(int port,String cookie) throws IOException {
  Socket socket=new Socket();socket.connect(new InetSocketAddress("127.0.0.1",port),3000);socket.setSoTimeout(5000);
  OutputStream out=socket.getOutputStream();
  out.write(("GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nCookie: "+cookie+"\r\nConnection: keep-alive\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));out.flush();
  String head=readHead(socket);
  check(head.startsWith("HTTP/1.1 200")&&head.contains("text/event-stream"),"SSE head: "+head);
  return socket;
 }
 private static String readHead(Socket socket) throws IOException {
  InputStream in=socket.getInputStream();ByteArrayOutputStream buffer=new ByteArrayOutputStream();int value;
  while((value=in.read())>=0){buffer.write(value);byte[] bytes=buffer.toByteArray();if(bytes.length>=4&&bytes[bytes.length-4]==13&&bytes[bytes.length-3]==10&&bytes[bytes.length-2]==13&&bytes[bytes.length-1]==10)return new String(bytes,StandardCharsets.ISO_8859_1);}
  throw new EOFException("SSE head closed");
 }
 private static String readUntil(Socket socket,String marker,int timeout) throws IOException {
  socket.setSoTimeout(timeout);InputStream in=socket.getInputStream();ByteArrayOutputStream buffer=new ByteArrayOutputStream();byte[] bytes=new byte[1024];
  while(true){String text=new String(buffer.toByteArray(),StandardCharsets.UTF_8);if(text.contains(marker))return text;int count=in.read(bytes);if(count<0)throw new AssertionError("SSE closed before "+marker+": "+text);buffer.write(bytes,0,count);}
 }
 private static String readUntilEof(Socket socket,int timeout) throws IOException {
  socket.setSoTimeout(timeout);InputStream in=socket.getInputStream();ByteArrayOutputStream buffer=new ByteArrayOutputStream();byte[] bytes=new byte[1024];
  try{int count;while((count=in.read(bytes))>=0)buffer.write(bytes,0,count);}catch(SocketTimeoutException e){throw new AssertionError("SSE stream is still open after revocation");}
  return new String(buffer.toByteArray(),StandardCharsets.UTF_8);
 }
 private static Response request(int port,String method,String path,String body,String sessionCookie) throws IOException {
  try(Socket socket=new Socket()){
   socket.connect(new InetSocketAddress("127.0.0.1",port),3000);socket.setSoTimeout(8000);
   byte[] content=body==null?new byte[0]:body.getBytes(StandardCharsets.UTF_8);
   StringBuilder head=new StringBuilder(method+" "+path+" HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nConnection: close\r\n");
   if(sessionCookie!=null)head.append("Cookie: ").append(sessionCookie).append("\r\n");
   if(!method.equals("GET")&&!method.equals("HEAD"))head.append("X-Ryadom: 1\r\nContent-Type: application/json\r\n");
   if(content.length>0)head.append("Content-Length: ").append(content.length).append("\r\n");
   head.append("\r\n");
   OutputStream out=socket.getOutputStream();out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));out.write(content);out.flush();
   ByteArrayOutputStream buffer=new ByteArrayOutputStream();byte[] bytes=new byte[4096];int count;
   while((count=socket.getInputStream().read(bytes))>=0&&buffer.size()<262144)buffer.write(bytes,0,count);
   return new Response(new String(buffer.toByteArray(),StandardCharsets.UTF_8));
  }
 }
 private static String cookie(String value){return value;}
 private static String hex(int size) throws Exception {byte[] bytes=new byte[size];new java.security.SecureRandom().nextBytes(bytes);StringBuilder text=new StringBuilder();for(byte value:bytes)text.append(String.format(Locale.ROOT,"%02x",value));return text.toString();}
 private static String sha256(String value) throws Exception {byte[] bytes=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));StringBuilder text=new StringBuilder();for(byte item:bytes)text.append(String.format(Locale.ROOT,"%02x",item));return text.toString();}
 private static void writeLegacy(File dir,String rawToken) throws Exception {
  JSONObject device=new JSONObject().put("id","legacy-device").put("name","Старый телефон").put("token",sha256(rawToken)).put("host",false).put("created","2024-01-01T00:00:00Z");
  JSONObject state=new JSONObject().put("devices",new JSONArray().put(device)).put("messages",new JSONArray()).put("files",new JSONArray()).put("seq",0);
  Files.write(new File(dir,"chat.json").toPath(),state.toString().getBytes(StandardCharsets.UTF_8));
 }
 private static int freePort() throws IOException {try(ServerSocket socket=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){return socket.getLocalPort();}}
 private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
 private static void delete(File file){if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)delete(child);}file.delete();}
}
