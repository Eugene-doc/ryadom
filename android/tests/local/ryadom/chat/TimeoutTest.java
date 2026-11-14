package local.ryadom.chat;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/** JVM check: header and body deadlines are absolute, a slow trickle cannot keep a request alive forever. */
public final class TimeoutTest {
 public static void main(String[] args) throws Exception {
  if(System.getenv("RYADOM_HTTP_HEADER_TIMEOUT_MS")==null)throw new AssertionError("Run with RYADOM_HTTP_HEADER_TIMEOUT_MS/RYADOM_HTTP_BODY_TIMEOUT_MS/RYADOM_HTTP_BODY_TOTAL_TIMEOUT_MS");
  
  int port=freePort();
  MiniHttp http=new MiniHttp(Collections.singletonList("127.0.0.1"),port,request->{request.body(65536);request.json(200,"{\"ok\":true}");});
  try{
   String fast=exchange(port,"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nConnection: close\r\n\r\n");
   check(fast.startsWith("HTTP/1.1 200"),"fast request must succeed: "+fast);

   final Socket headers=new Socket();headers.connect(new InetSocketAddress("127.0.0.1",port),3000);headers.setSoTimeout(5000);
   final String request="GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\n\r\n";
   Thread trickle=new Thread(()->{try{OutputStream out=headers.getOutputStream();for(int i=0;i<request.length();i++){out.write(request.charAt(i));out.flush();Thread.sleep(150);}}catch(Exception ignored){}});
   trickle.setDaemon(true);trickle.start();
   long start=System.currentTimeMillis();String response="";
   try{response=readAll(headers.getInputStream());}catch(Exception ignored){}
   long elapsed=System.currentTimeMillis()-start;headers.close();
   check(!response.contains("200 OK"),"trickled headers must not be served: "+response);
   check(elapsed<5000,"header deadline must be enforced by absolute time, elapsed="+elapsed);

   final Socket bodySocket=new Socket();bodySocket.connect(new InetSocketAddress("127.0.0.1",port),3000);bodySocket.setSoTimeout(5000);
   OutputStream out=bodySocket.getOutputStream();out.write(("POST /api/files?name=slow.bin HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\nX-Ryadom: 1\r\nContent-Length: 200\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));out.flush();
   Thread bodyWriter=new Thread(()->{try{OutputStream stream=bodySocket.getOutputStream();for(int i=0;i<20;i++){Thread.sleep(400);stream.write('x');stream.flush();}}catch(Exception ignored){}});
   bodyWriter.setDaemon(true);bodyWriter.start();
   start=System.currentTimeMillis();response="";
   try{response=readAll(bodySocket.getInputStream());}catch(Exception ignored){}
   elapsed=System.currentTimeMillis()-start;bodySocket.close();
   check(!response.contains("200 OK"),"trickled body must not be stored: "+response);
   check(elapsed<5000,"body total deadline must be enforced, elapsed="+elapsed);
   System.out.println("Absolute header/body deadline checks passed");
  }finally{http.close();}
 }
 private static String exchange(int port,String request) throws IOException {
  try(Socket socket=new Socket()){
   socket.connect(new InetSocketAddress("127.0.0.1",port),3000);socket.setSoTimeout(5000);
   OutputStream out=socket.getOutputStream();out.write(request.getBytes(StandardCharsets.ISO_8859_1));out.flush();
   return readAll(socket.getInputStream());
  }
 }
 private static String readAll(InputStream input) throws IOException {
  ByteArrayOutputStream buffer=new ByteArrayOutputStream();byte[] bytes=new byte[4096];int count;
  while((count=input.read(bytes))>=0&&buffer.size()<65536)buffer.write(bytes,0,count);
  return new String(buffer.toByteArray(),StandardCharsets.UTF_8);
 }
 private static int freePort() throws IOException {try(ServerSocket socket=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){return socket.getLocalPort();}}
 private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
}
