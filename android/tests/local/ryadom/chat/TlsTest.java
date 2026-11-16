package local.ryadom.chat;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.SSLSocket;

/** JVM check of the Android TLS identity: self-signed certificate, TLS 1.2 handshake, TOFU pinning and reset. */
public final class TlsTest {
 private static final class MemoryStore implements TlsPin.Store {
  final Map<String,String> values=new HashMap<>();
  public String get(String key){return values.get(key);}
  public void put(String key,String value){values.put(key,value);}
  public void remove(String key){values.remove(key);}
 }
 private static final class Server implements AutoCloseable {
  final TlsIdentity identity;final MiniHttp http;
  Server(TlsIdentity identity) throws Exception {
   this.identity=identity;
   String body="{\"app\":\"ryadom\",\"version\":\"0.2.0\",\"fingerprint\":\""+identity.fingerprint+"\"}";
   http=new MiniHttp(Collections.<String>emptyList(),Collections.singletonList("127.0.0.1"),0,identity.context,request->request.json(200,body));
  }
  int port(){return http.port();}
  public void close(){http.close();}
 }
 public static void main(String[] args) throws Exception {
  File root=Files.createTempDirectory("ryadom-tls").toFile();
  try{
   TlsIdentity first=TlsIdentity.ensure(new File(root,"first"));
   TlsIdentity again=TlsIdentity.ensure(new File(root,"first"));
   if(first.fingerprint.length()!=64||!first.fingerprint.matches("[0-9a-f]{64}"))throw new AssertionError("fingerprint format: "+first.fingerprint);
   if(!first.fingerprint.equals(again.fingerprint))throw new AssertionError("identity must persist");
   X509Certificate certificate=first.certificate;
   if(!certificate.getSubjectX500Principal().getName().contains("CN=Ryadom Host"))throw new AssertionError("subject: "+certificate.getSubjectX500Principal());
   if(certificate.getPublicKey().getAlgorithm().equals("RSA")&&((java.security.interfaces.RSAPublicKey)certificate.getPublicKey()).getModulus().bitLength()!=2048)throw new AssertionError("RSA key size");
   if(certificate.getVersion()!=3)throw new AssertionError("certificate version "+certificate.getVersion());
   if(TlsPin.fingerprint(certificate).length()!=64)throw new AssertionError("pin fingerprint");

   Server server=new Server(first);
   try{
    MemoryStore pins=new MemoryStore();
    String key=TlsPin.address("127.0.0.1",server.port());
    Socket tls=connect(server.port(),"127.0.0.1",key,pins);
    try{
     if(!(tls instanceof SSLSocket))throw new AssertionError("TLS socket expected");
     if(!"TLSv1.2".equals(((SSLSocket)tls).getSession().getProtocol()))throw new AssertionError("protocol "+((SSLSocket)tls).getSession().getProtocol());
     if(!first.fingerprint.equalsIgnoreCase(pins.get(key)))throw new AssertionError("first fingerprint must be pinned");
     String response=exchange(tls,"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:"+server.port()+"\r\nConnection: close\r\n\r\n");
     if(!response.startsWith("HTTP/1.1 200"))throw new AssertionError("health status: "+response);
     if(!response.contains("\"app\":\"ryadom\""))throw new AssertionError("health body: "+response);
     if(!response.contains(first.fingerprint))throw new AssertionError("health fingerprint: "+response);
    }finally{try{tls.close();}catch(IOException ignored){}}
    tls=connect(server.port(),"127.0.0.1",key,pins);
    tls.close();
    MemoryStore probePins=new MemoryStore();
    Socket plain=new Socket();plain.connect(new InetSocketAddress("127.0.0.1",server.port()),3000);
    String health=TlsPin.probe(plain,"127.0.0.1",server.port(),key,probePins);
    if(!health.contains("\"app\":\"ryadom\""))throw new AssertionError("probe: "+health);
    if(!first.fingerprint.equals(probePins.get(key)))throw new AssertionError("probe must pin");

    MemoryStore inspectPins=new MemoryStore();
    Socket inspectPlain=new Socket();inspectPlain.connect(new InetSocketAddress("127.0.0.1",server.port()),3000);
    TlsPin.Inspection inspection=TlsPin.inspect(inspectPlain,"127.0.0.1",server.port(),key,inspectPins);
    if(!inspection.firstUse)throw new AssertionError("inspect must report first use");
    if(!first.fingerprint.equals(inspection.fingerprint))throw new AssertionError("inspect fingerprint");
    if(inspectPins.get(key)!=null)throw new AssertionError("inspect must not pin before confirmation");
    inspectPins.put(key,inspection.fingerprint);
    Socket confirmed=connect(server.port(),"127.0.0.1",key,inspectPins);confirmed.close();

    TlsIdentity second=TlsIdentity.ensure(new File(root,"second"));
    if(second.fingerprint.equals(first.fingerprint))throw new AssertionError("second identity must differ");
    Server other=new Server(second);
    try{
     Socket changed=new Socket();changed.connect(new InetSocketAddress("127.0.0.1",other.port()),3000);
     try{
      TlsPin.connect(changed,"127.0.0.1",key,pins);
      throw new AssertionError("changed certificate must be rejected");
     }catch(TlsPin.PinMismatch mismatch){
      if(!mismatch.address().equals(key))throw new AssertionError("mismatch address: "+mismatch.address());
      if(!mismatch.getMessage().contains("Сертификат главного устройства изменился"))throw new AssertionError("message: "+mismatch.getMessage());
     }
     if(!first.fingerprint.equals(pins.get(key)))throw new AssertionError("pin must survive a mismatch");
     pins.remove(key);
     Socket reset=new Socket();reset.connect(new InetSocketAddress("127.0.0.1",other.port()),3000);
     Socket accepted=TlsPin.connect(reset,"127.0.0.1",key,pins);
     accepted.close();
     if(!second.fingerprint.equals(pins.get(key)))throw new AssertionError("reset must pin the new certificate");
    }finally{other.close();}
   }finally{server.close();}

   int port=freePort();
   ChatHost host=new ChatHost(new File(root,"host"),Collections.<String>emptyList(),port,name->new byte[0],()->{});
   try{
    String local=host.localUrl();
    if(!local.startsWith("http://127.0.0.1:"+port+"/#t="))throw new AssertionError("localUrl: "+local);
    String token=local.substring(local.indexOf("#t=")+3);
    String login=request("127.0.0.1",port,"POST","/api/host-login","{\"token\":\""+token+"\"}",null);
    if(!login.startsWith("HTTP/1.1 200"))throw new AssertionError("host-login: "+login);
    String cookie=cookie(login);
    String state=request("127.0.0.1",port,"GET","/api/state",null,cookie);
    if(!state.startsWith("HTTP/1.1 200"))throw new AssertionError("state: "+state);
    if(!state.contains("\"tls\":true"))throw new AssertionError("state must advertise TLS: "+state);
    if(!state.contains(host.tls.fingerprint))throw new AssertionError("state fingerprint: "+state);
    String health=request("127.0.0.1",port,"GET","/api/health",null,null);
    if(!health.contains("\"version\":\""+ChatHost.VERSION+"\""))throw new AssertionError("health version: "+health);
    String replayed=request("127.0.0.1",port,"POST","/api/host-login","{\"token\":\""+token+"\"}",null);
    if(!replayed.startsWith("HTTP/1.1 403"))throw new AssertionError("one-time token: "+replayed);
   }finally{host.close();}
   System.out.println("TLS identity, TOFU pinning and host login checks passed");
  }finally{delete(root);}
 }
 private static Socket connect(int port,String host,String key,TlsPin.Store store) throws IOException {
  Socket plain=new Socket();plain.connect(new InetSocketAddress(host,port),3000);plain.setSoTimeout(5000);
  return TlsPin.connect(plain,host,key,store);
 }
 private static String exchange(Socket socket,String request) throws IOException {
  OutputStream out=socket.getOutputStream();out.write(request.getBytes(StandardCharsets.ISO_8859_1));out.flush();
  return readAll(socket.getInputStream());
 }
 private static String request(String host,int port,String method,String path,String body,String cookie) throws IOException {
  try(Socket socket=new Socket()){
   socket.connect(new InetSocketAddress(host,port),3000);socket.setSoTimeout(8000);
   StringBuilder head=new StringBuilder(method+" "+path+" HTTP/1.1\r\nHost: "+host+":"+port+"\r\nConnection: close\r\n");
   if(cookie!=null)head.append("Cookie: ").append(cookie).append("\r\n");
   if(body!=null)head.append("X-Ryadom: 1\r\nContent-Type: application/json\r\nContent-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
   head.append("\r\n");
   OutputStream out=socket.getOutputStream();out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));if(body!=null)out.write(body.getBytes(StandardCharsets.UTF_8));out.flush();
   return readAll(socket.getInputStream());
  }
 }
 private static String cookie(String response){
  for(String line:response.split("\r\n"))if(line.toLowerCase(Locale.ROOT).startsWith("set-cookie: ryadom_sid="))return line.substring("set-cookie: ".length()).split(";")[0];
  return "";
 }
 private static String readAll(InputStream input) throws IOException {
  ByteArrayOutputStream buffer=new ByteArrayOutputStream();byte[] bytes=new byte[4096];int count;
  while((count=input.read(bytes))>=0&&buffer.size()<65536)buffer.write(bytes,0,count);
  return new String(buffer.toByteArray(),StandardCharsets.UTF_8);
 }
 private static int freePort() throws IOException {try(ServerSocket socket=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){return socket.getLocalPort();}}
 private static void delete(File file){if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)delete(child);}file.delete();}
}
