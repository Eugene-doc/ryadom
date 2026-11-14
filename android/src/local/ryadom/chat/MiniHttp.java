package local.ryadom.chat;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;

/**
 * Small HTTP/1.1 transport with bounded headers, streaming bodies, TLS listeners and connection
 * limits. Loopback can stay plain for the host WebView; LAN listeners are TLS 1.2 only.
 */
final class MiniHttp implements AutoCloseable {
 interface Handler {void handle(Request request) throws Exception;}
 static final int HEADER_TIMEOUT_MS=config("RYADOM_HTTP_HEADER_TIMEOUT_MS",10000),BODY_TIMEOUT_MS=config("RYADOM_HTTP_BODY_TIMEOUT_MS",60000),BODY_TOTAL_TIMEOUT_MS=config("RYADOM_HTTP_BODY_TOTAL_TIMEOUT_MS",1800000),MAX_CONNECTIONS=128,MAX_PER_IP=16,DRAIN_LIMIT=8*1024*1024;
 private static int config(String key,int fallback){try{String value=System.getenv(key);if(value==null||value.isEmpty())return fallback;return Integer.parseInt(value.trim());}catch(Exception e){return fallback;}}
 private static final String SECURITY="Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n";
 static final class Failure extends IOException {final int status;Failure(int s,String m){super(m);status=s;}}
 static final class Request {
  final MiniHttp owner;final Socket socket;final BufferedInputStream in;final OutputStream out;final Map<String,String> headers=new LinkedHashMap<>();
  String method,target,path;long length;long remaining;boolean sent,detached;
  Request(MiniHttp owner,Socket s) throws IOException {
   this.owner=owner;socket=s;s.setSoTimeout(HEADER_TIMEOUT_MS);
   in=new BufferedInputStream(s.getInputStream(),65536);out=s.getOutputStream();
   long deadline=System.currentTimeMillis()+HEADER_TIMEOUT_MS;
   String[] start=line(deadline,8192).split(" ");if(start.length!=3||!start[2].equals("HTTP/1.1")||!start[1].startsWith("/"))throw new Failure(400,"Bad request");method=start[0];target=start[1];path=target.split("\\?",2)[0];
   int total=0;while(true){String h=line(deadline,8192);if(h.isEmpty())break;total+=h.length();if(total>32768)throw new Failure(431,"Headers too large");int colon=h.indexOf(':');if(colon<1)throw new Failure(400,"Bad header");String key=h.substring(0,colon).toLowerCase(Locale.ROOT);if(headers.containsKey(key))throw new Failure(400,"Duplicate header");headers.put(key,h.substring(colon+1).trim());}
   if(headers.containsKey("transfer-encoding"))throw new Failure(411,"Content-Length required");
   try{length=Long.parseLong(headers.getOrDefault("content-length","0"));}catch(Exception e){throw new Failure(400,"Invalid length");}if(length<0)throw new Failure(400,"Invalid length");
   remaining=length;
   s.setSoTimeout(BODY_TIMEOUT_MS);
  }
  private String line(long deadline,int max) throws IOException {
   ByteArrayOutputStream buffer=new ByteArrayOutputStream();int previous=-1;
   while(true){
    long left=deadline-System.currentTimeMillis();
    if(left<=0)throw new Failure(408,"Время ожидания запроса истекло");
    socket.setSoTimeout((int)Math.min(Integer.MAX_VALUE,Math.max(1,left)));
    int value=in.read();
    if(value<0)throw new EOFException();
    if(previous==13&&value==10){byte[] bytes=buffer.toByteArray();return new String(bytes,0,bytes.length-1,StandardCharsets.ISO_8859_1);}
    buffer.write(value);if(buffer.size()>max)throw new Failure(431,"Line too large");previous=value;
   }
  }
  boolean loopback(){return socket.getInetAddress().isLoopbackAddress();}
  String header(String key){return headers.getOrDefault(key,"");}
  String parameter(String key){try{String[] p=target.split("\\?",2);if(p.length<2)return "";for(String entry:p[1].split("&")){String[] kv=entry.split("=",2);if(URLDecoder.decode(kv[0],"UTF-8").equals(key))return kv.length>1?URLDecoder.decode(kv[1],"UTF-8"):"";}}catch(Exception ignored){}return "";}
  byte[] body(int max) throws IOException {if(length>max)throw new Failure(413,"Слишком большой запрос");ByteArrayOutputStream result=new ByteArrayOutputStream();transfer(result);return result.toByteArray();}
  void transfer(OutputStream out) throws IOException {readBody(out,true);}
  /** Reads and drops the whole remaining body (used when a retry is already stored). */
  void discard() throws IOException {readBody(null,false);}
  private void readBody(OutputStream out,boolean write) throws IOException {
   byte[] buffer=new byte[65536];long idle=System.currentTimeMillis()+BODY_TIMEOUT_MS,total=System.currentTimeMillis()+BODY_TOTAL_TIMEOUT_MS;
   while(remaining>0){
    long nowMs=System.currentTimeMillis(),deadline=Math.min(idle,total),left=deadline-nowMs;
    if(left<=0)throw new Failure(408,"Передача прервана: нет данных");
    socket.setSoTimeout((int)Math.min(Integer.MAX_VALUE,Math.max(1,left)));
    int count;try{count=in.read(buffer,0,(int)Math.min(remaining,buffer.length));}catch(SocketTimeoutException e){throw new Failure(408,"Передача прервана: нет данных");}
    if(count<0)throw new EOFException();
    if(write)out.write(buffer,0,count);
    remaining-=count;idle=System.currentTimeMillis()+BODY_TIMEOUT_MS;
   }
  }
  void detach(){detached=true;}
  void close(){owner.release(socket);}
  /** Discards a small unread body so an early error response is not lost to a TCP reset. */
  void drain(){
   long deadline=System.currentTimeMillis()+5000;byte[] buffer=new byte[65536];
   try{while(remaining>0){long left=deadline-System.currentTimeMillis();if(left<=0)break;socket.setSoTimeout((int)Math.min(2000,Math.max(1,left)));int count=in.read(buffer,0,(int)Math.min(remaining,buffer.length));if(count<0)break;remaining-=count;}}
   catch(Exception ignored){}
   finally{try{socket.setSoTimeout(BODY_TIMEOUT_MS);}catch(Exception ignored){}}
  }
  void head(int status,String mime,long length,Map<String,String> extra) throws IOException {writeHead(status,mime,length,"close",extra);}
  void headStream(int status,String mime,Map<String,String> extra) throws IOException {writeHead(status,mime,-1,"keep-alive",extra);}
  private void writeHead(int status,String mime,long length,String connection,Map<String,String> extra) throws IOException {
   StringBuilder h=new StringBuilder("HTTP/1.1 "+status+" "+reason(status)+"\r\nContent-Type: "+mime+"\r\nConnection: "+connection+"\r\n"+SECURITY);
   if(length>=0)h.append("Content-Length: ").append(length).append("\r\n");if(extra!=null)for(Map.Entry<String,String> e:extra.entrySet())h.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");h.append("\r\n");out.write(h.toString().getBytes(StandardCharsets.UTF_8));out.flush();sent=true;
  }
  void reply(int status,String mime,byte[] body,Map<String,String> headers) throws IOException {head(status,mime,body.length,headers);if(!method.equals("HEAD"))out.write(body);out.flush();}
  void json(int status,String value) throws IOException {reply(status,"application/json; charset=utf-8",value.getBytes(StandardCharsets.UTF_8),null);}
 }
 private final List<ServerSocket> listeners=new CopyOnWriteArrayList<>();
 private final Set<Socket> sockets=new HashSet<>();private final Map<String,Integer> byIp=new HashMap<>();
 private final Object limits=new Object();private final Handler handler;
 private final ThreadPoolExecutor workers=new ThreadPoolExecutor(0,64,30,TimeUnit.SECONDS,new SynchronousQueue<Runnable>(),r->{Thread t=new Thread(r,"Ryadom HTTP");t.setDaemon(true);return t;});
 volatile boolean closed;
 MiniHttp(List<String> addresses,int port,Handler handler) throws IOException {this(addresses,Collections.<String>emptyList(),port,null,handler);}
 MiniHttp(List<String> plain,List<String> secure,int port,SSLContext context,Handler handler) throws IOException {
  this.handler=handler;
  try{
   for(String address:plain)addListener(bind(address,port,null));
   for(String address:secure){if(context==null)throw new IOException("TLS context is required");addListener(bind(address,port,context));}
   if(listeners.isEmpty())throw new IOException("No listeners");
  }catch(IOException e){close();throw e;}
 }
 private ServerSocket bind(String address,int port,SSLContext context) throws IOException {
  if(context==null){ServerSocket listener=new ServerSocket();listener.setReuseAddress(true);listener.bind(new InetSocketAddress(InetAddress.getByName(address),port),64);return listener;}
  SSLServerSocket listener=(SSLServerSocket)context.getServerSocketFactory().createServerSocket();
  listener.setReuseAddress(true);listener.setNeedClientAuth(false);listener.setWantClientAuth(false);listener.setEnabledProtocols(new String[]{"TLSv1.2"});
  listener.bind(new InetSocketAddress(InetAddress.getByName(address),port),64);return listener;
 }
 private void addListener(ServerSocket listener){
  listeners.add(listener);Thread thread=new Thread(()->accept(listener),"Ryadom accept");thread.setDaemon(true);thread.start();
 }
 int port(){return listeners.get(0).getLocalPort();}
 private void accept(ServerSocket listener){
  while(!closed){
   Socket socket;
   try{socket=listener.accept();socket.setTcpNoDelay(true);socket.setSoTimeout(HEADER_TIMEOUT_MS);}
   catch(IOException e){if(closed)return;continue;}
   if(!admit(socket)){try{socket.close();}catch(Exception ignored){}continue;}
   try{workers.execute(()->serve(socket));}catch(RejectedExecutionException e){release(socket);}
  }
 }
 private boolean admit(Socket socket){
  String ip=address(socket);
  synchronized(limits){
   if(sockets.size()>=MAX_CONNECTIONS)return false;
   int count=byIp.containsKey(ip)?byIp.get(ip):0;
   if(count>=MAX_PER_IP)return false;
   byIp.put(ip,count+1);sockets.add(socket);return true;
  }
 }
 void release(Socket socket){
  synchronized(limits){if(!sockets.remove(socket))return;String ip=address(socket);Integer count=byIp.get(ip);if(count!=null){if(count<=1)byIp.remove(ip);else byIp.put(ip,count-1);}}
  try{socket.close();}catch(Exception ignored){}
 }
 private static String address(Socket socket){try{return socket.getInetAddress().getHostAddress();}catch(Exception e){return "?";}}
 private void serve(Socket socket){
  Request request=null;
  try{
   request=new Request(this,socket);handler.handle(request);
   if(!request.detached&&request.remaining>0&&request.remaining<=DRAIN_LIMIT)request.drain();
  }
  catch(Exception e){
   if(request!=null&&!request.sent&&!request.detached){
    boolean timeout=e instanceof Failure&&((Failure)e).status==408;
    if(!timeout&&request.remaining>0&&request.remaining<=DRAIN_LIMIT)request.drain();
    try{String message=e instanceof Failure?e.getMessage():"Не удалось выполнить действие";request.json(e instanceof Failure?((Failure)e).status:500,"{\"error\":"+org.json.JSONObject.quote(message)+"}");}catch(Exception ignored){}
   }
  }finally{if(request==null||!request.detached)release(socket);}
 }
 static String line(InputStream in,int max) throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();int previous=-1;while(true){int b=in.read();if(b<0)throw new EOFException();if(previous==13&&b==10){byte[] bytes=out.toByteArray();return new String(bytes,0,bytes.length-1,StandardCharsets.ISO_8859_1);}out.write(b);if(out.size()>max)throw new Failure(431,"Line too large");previous=b;}}
 static void copy(InputStream in,OutputStream out,long count) throws IOException {byte[] buffer=new byte[65536];long left=count;while(left!=0){int n=in.read(buffer,0,(int)(left<0?buffer.length:Math.min(left,buffer.length)));if(n<0){if(left>0)throw new EOFException();break;}out.write(buffer,0,n);if(left>0)left-=n;}}
 static String reason(int s){switch(s){case 200:return "OK";case 201:return "Created";case 202:return "Accepted";case 206:return "Partial Content";case 400:return "Bad Request";case 401:return "Unauthorized";case 403:return "Forbidden";case 404:return "Not Found";case 408:return "Request Timeout";case 409:return "Conflict";case 410:return "Gone";case 411:return "Length Required";case 413:return "Payload Too Large";case 416:return "Range Not Satisfiable";case 429:return "Too Many Requests";case 431:return "Request Header Fields Too Large";case 500:return "Internal Server Error";case 503:return "Unavailable";case 507:return "Insufficient Storage";default:return "Response";}}
 public void close(){
  closed=true;
  for(ServerSocket listener:listeners)try{listener.close();}catch(Exception ignored){}
  List<Socket> all;synchronized(limits){all=new ArrayList<>(sockets);sockets.clear();byIp.clear();}
  for(Socket socket:all)try{socket.close();}catch(Exception ignored){}
  workers.shutdownNow();
 }
}
