package local.ryadom.chat;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import org.json.*;

/** JVM check: concurrent uploads reserve quota atomically, so the stored total never exceeds the limit. */
public final class QuotaTest {
 private static final int SIZE=700*1024;
 public static void main(String[] args) throws Exception {
  if(!"1".equals(System.getenv("RYADOM_MAX_TOTAL_MB")))throw new AssertionError("Run with RYADOM_MAX_TOTAL_MB=1 RYADOM_MAX_DEVICE_MB=1 RYADOM_MIN_FREE_MB=0");
  File dir=Files.createTempDirectory("ryadom-quota").toFile();
  int port=freePort();
  ChatHost host=new ChatHost(dir,Collections.<String>emptyList(),port,name->new byte[0],()->{});
  try{
   String local=host.localUrl();String token=local.substring(local.indexOf("#t=")+3);
   String cookie=login(port,token);
   Socket first=uploadSocket(port,cookie,"quota-1"),second=uploadSocket(port,cookie,"quota-2");
   Thread.sleep(300);
   ExecutorService pool=Executors.newFixedThreadPool(2);
   try{
    Future<String> a=pool.submit(()->send(first)),b=pool.submit(()->send(second));
    String firstResponse=a.get(30,TimeUnit.SECONDS),secondResponse=b.get(30,TimeUnit.SECONDS);
    List<Integer> statuses=new ArrayList<>();statuses.add(status(firstResponse));statuses.add(status(secondResponse));
    Collections.sort(statuses);
    if(!statuses.get(0).equals(201)||!(statuses.get(1).equals(507)||statuses.get(1).equals(429)))throw new AssertionError("expected one 201 and one 507/429, got "+statuses+"\n"+firstResponse+"\n"+secondResponse);
   }finally{pool.shutdownNow();first.close();second.close();}
   JSONObject state=new JSONObject(request(port,"GET","/api/state","",cookie).body);
   long used=state.getJSONObject("storage").getLong("usedBytes");
   if(used>1024L*1024)throw new AssertionError("stored bytes exceed the quota: "+used);
   System.out.println("Atomic upload quota checks passed (stored "+used+" bytes)");
  }finally{host.close();delete(dir);}
 }
 private static Socket uploadSocket(int port,String cookie,String requestId) throws IOException {
  Socket socket=new Socket();socket.connect(new InetSocketAddress("127.0.0.1",port),3000);socket.setSoTimeout(30000);
  String head="POST /api/files?name="+requestId+".bin&requestId="+requestId+" HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nConnection: close\r\nCookie: "+cookie+"\r\nX-Ryadom: 1\r\nContent-Length: "+SIZE+"\r\n\r\n";
  OutputStream out=socket.getOutputStream();out.write(head.getBytes(StandardCharsets.ISO_8859_1));out.flush();
  return socket;
 }
 private static String send(Socket socket) throws IOException {
  OutputStream out=socket.getOutputStream();byte[] block=new byte[16384];Arrays.fill(block,(byte)7);
  int left=SIZE;while(left>0){int count=Math.min(left,block.length);out.write(block,0,count);left-=count;}out.flush();
  ByteArrayOutputStream buffer=new ByteArrayOutputStream();byte[] bytes=new byte[4096];int count;
  while((count=socket.getInputStream().read(bytes))>=0&&buffer.size()<262144)buffer.write(bytes,0,count);
  return new String(buffer.toByteArray(),StandardCharsets.UTF_8);
 }
 private static int status(String response){try{return Integer.parseInt(response.substring(0,response.indexOf("\r\n")).split(" ")[1]);}catch(Exception e){return 0;}}
 private static String login(int port,String token) throws IOException {
  Reply reply=request(port,"POST","/api/host-login","{\"token\":\""+token+"\"}","");
  return reply.cookie;
 }
 private static final class Reply {
  final String raw,body,cookie;
  Reply(String raw){this.raw=raw;int split=raw.indexOf("\r\n\r\n");body=split<0?"":raw.substring(split+4);String value="";for(String line:raw.split("\r\n"))if(line.toLowerCase(Locale.ROOT).startsWith("set-cookie: ryadom_sid="))value=line.substring("set-cookie: ".length()).split(";")[0];cookie=value;}
 }
 private static Reply request(int port,String method,String path,String body,String cookie) throws IOException {
  try(Socket socket=new Socket()){
   socket.connect(new InetSocketAddress("127.0.0.1",port),3000);socket.setSoTimeout(10000);
   byte[] content=body==null?new byte[0]:body.getBytes(StandardCharsets.UTF_8);
   StringBuilder head=new StringBuilder(method+" "+path+" HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nConnection: close\r\n");
   if(cookie!=null&&!cookie.isEmpty())head.append("Cookie: ").append(cookie).append("\r\n");
   if(!method.equals("GET"))head.append("X-Ryadom: 1\r\nContent-Type: application/json\r\n");
   if(content.length>0)head.append("Content-Length: ").append(content.length).append("\r\n");
   head.append("\r\n");
   OutputStream out=socket.getOutputStream();out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));out.write(content);out.flush();
   ByteArrayOutputStream buffer=new ByteArrayOutputStream();byte[] bytes=new byte[4096];int count;
   while((count=socket.getInputStream().read(bytes))>=0&&buffer.size()<262144)buffer.write(bytes,0,count);
   return new Reply(new String(buffer.toByteArray(),StandardCharsets.UTF_8));
  }
 }
 private static int freePort() throws IOException {try(ServerSocket socket=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){return socket.getLocalPort();}}
 private static void delete(File file){if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)delete(child);}file.delete();}
}
