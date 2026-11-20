package local.ryadom.chat;

import org.json.JSONObject;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

/** JVM contract checks for Android host deletion, clear, upload epoch and permissions. */
public final class FunctionalTest {
 private static final class Response {
  final int status; final String body; final String cookie;
  Response(int s, String b, String c) { status=s; body=b; cookie=c; }
 }
 private static Response call(int port,String method,String path,byte[] body,String type,String cookie) throws Exception {
  HttpURLConnection connection=(HttpURLConnection)new URL("http://127.0.0.1:"+port+path).openConnection();
  connection.setRequestMethod(method);connection.setConnectTimeout(3000);connection.setReadTimeout(10000);
  if(cookie!=null&&!cookie.isEmpty())connection.setRequestProperty("Cookie",cookie);
  if(!"GET".equals(method)){connection.setRequestProperty("X-Ryadom","1");connection.setDoOutput(true);if(type!=null)connection.setRequestProperty("Content-Type",type);if(body!=null){connection.setFixedLengthStreamingMode(body.length);try(OutputStream out=connection.getOutputStream()){out.write(body);}}}
  int status=connection.getResponseCode();InputStream in=status>=400?connection.getErrorStream():connection.getInputStream();
  ByteArrayOutputStream out=new ByteArrayOutputStream();if(in!=null)try(InputStream source=in){byte[] buffer=new byte[4096];int count;while((count=source.read(buffer))>0)out.write(buffer,0,count);}
  String setCookie=connection.getHeaderField("Set-Cookie");
  return new Response(status,new String(out.toByteArray(),StandardCharsets.UTF_8),setCookie==null?"":setCookie.split(";",2)[0]);
 }
 private static Response call(int port,String method,String path,String json,String cookie) throws Exception {
  return call(port,method,path,json==null?null:json.getBytes(StandardCharsets.UTF_8),"application/json",cookie);
 }
 private static int freePort() throws Exception {try(ServerSocket socket=new ServerSocket(0)){return socket.getLocalPort();}}
 private static String login(ChatHost host,int port) throws Exception {
  String local=host.localUrl();String token=local.substring(local.indexOf("#t=")+3);
  Response response=call(port,"POST","/api/host-login",new JSONObject().put("token",token).toString(),null);
  check(response.status==200,"host login: "+response.status+" "+response.body);
  return response.cookie;
 }
 private static String pair(int port,String hostCookie,String name) throws Exception {
  Response state=call(port,"GET","/api/state",null,hostCookie);
  String code=new JSONObject(state.body).getJSONObject("pairing").getString("code");
  Response pending=call(port,"POST","/api/pair",new JSONObject().put("name",name).put("code",code).put("protocol",4).toString(),null);
  check(pending.status==202,"pair: "+pending.status+" "+pending.body);
  String requestId=new JSONObject(pending.body).getString("requestId");
  Response approve=call(port,"POST","/api/host/pair/approve",new JSONObject().put("requestId",requestId).toString(),hostCookie);
  check(approve.status==200,"approve: "+approve.status+" "+approve.body);
  Response status=call(port,"GET","/api/pair/status?requestId="+requestId,null,null);
  check(status.status==200,"pair status: "+status.status+" "+status.body);
  return status.cookie;
 }
 private static JSONObject message(int port,String cookie,String text,String requestId) throws Exception {
  Response response=call(port,"POST","/api/messages",new JSONObject().put("text",text).put("requestId",requestId).toString(),cookie);
  check(response.status==201,"message: "+response.status+" "+response.body);
  return new JSONObject(response.body);
 }
 private static JSONObject upload(int port,String cookie,String name,String requestId) throws Exception {
  Response response=call(port,"POST","/api/files?name="+URLEncoder.encode(name,"UTF-8")+"&requestId="+requestId,"payload".getBytes(StandardCharsets.UTF_8),"application/octet-stream",cookie);
  check(response.status==201,"upload: "+response.status+" "+response.body);
  return new JSONObject(response.body);
 }
 private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
 public static void main(String[] args) throws Exception {
  File root=Files.createTempDirectory("ryadom-functional").toFile();int port=freePort();
  ChatHost host=new ChatHost(new File(root,"host"),Collections.<String>emptyList(),port,name->new byte[0],()->{});
  try{
   String hostCookie=login(host,port);
   JSONObject state=new JSONObject(call(port,"GET","/api/state",null,hostCookie).body);
   check("legacy".equals(state.getJSONObject("chat").getString("id")),"legacy chat metadata");
   String device=pair(port,hostCookie,"Функциональный");
   JSONObject text=message(port,device,"удалить","functional-text-1");
   JSONObject attachment=upload(port,device,"functional.txt","functional-file-1");
   Response deleted=call(port,"DELETE","/api/messages/"+text.getString("id"),null,device);
   check(deleted.status==200,"author delete: "+deleted.status+" "+deleted.body);
   String stranger=pair(port,hostCookie,"Чужой");
   check(call(port,"DELETE","/api/messages/"+attachment.getString("id"),null,stranger).status==403,"stranger delete must be forbidden");
   check(call(port,"DELETE","/api/messages/"+attachment.getString("id"),null,hostCookie).status==200,"host delete");
   check(call(port,"GET","/files/"+attachment.getJSONObject("file").getString("id"),null,device).status==404,"attachment must be inaccessible");
   String retry=call(port,"POST","/api/messages",new JSONObject().put("text","вернуть").put("requestId","functional-text-1").toString(),device).status+"";
   check(retry.equals("410"),"deleted requestId must be 410, got "+retry);
   JSONObject preview=new JSONObject(call(port,"GET","/api/chat/clear/preview",null,hostCookie).body);
   Response clear=call(port,"POST","/api/chat/clear",new JSONObject().put("confirm",true).put("revision",preview.getLong("revision")).put("operationId","functional-clear-1").toString(),hostCookie);
   check(clear.status==202,"clear: "+clear.status+" "+clear.body);
   JSONObject cleared=new JSONObject(call(port,"GET","/api/state",null,device).body);
   check(cleared.getJSONArray("messages").length()==0,"history must be empty");
   check(cleared.getJSONObject("chat").getLong("epoch")==1,"epoch must advance");
   JSONObject operation=new JSONObject(call(port,"GET","/api/operations/functional-clear-1",null,hostCookie).body);
   check("done".equals(operation.getString("status")),"operation must be done");
   System.out.println("Android deletion, permissions, clear and epoch checks passed");
  }finally{host.close();delete(root);}
 }
 private static void delete(File file){File[] children=file.listFiles();if(children!=null)for(File child:children)delete(child);file.delete();}
}
