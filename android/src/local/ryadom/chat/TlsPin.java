package local.ryadom.chat;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import javax.net.ssl.*;

/**
 * TOFU pinning of the host TLS certificate: the first SHA-256 fingerprint seen for an address
 * is remembered, a changed certificate is rejected with a clear message. TLS 1.2 only.
 */
final class TlsPin {
 static final String CHANGED="Сертификат главного устройства изменился. Если главное устройство переустанавливали, сбросьте доверие для этого адреса и подключитесь заново.";
 interface Store {String get(String key);void put(String key,String value);void remove(String key);}
 static final class PinMismatch extends IOException {
  private final String address;
  PinMismatch(String address){super(CHANGED);this.address=address;}
  String address(){return address;}
 }
 private TlsPin(){}
 static String address(String host,int port){return host+":"+port;}
 static String fingerprint(X509Certificate certificate) throws CertificateException {
  try{
   byte[] hash=MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
   StringBuilder text=new StringBuilder(hash.length*2);
   for(byte value:hash)text.append(String.format(Locale.ROOT,"%02x",value));
   return text.toString();
  }catch(GeneralSecurityException e){throw new CertificateException(e);}
 }
 /** Wraps an already connected socket into a TLS 1.2 client socket and verifies the pinned fingerprint. */
 static Socket connect(Socket plain,String peerHost,String pinKey,Store store) throws IOException {
  Pinner pinner=new Pinner(pinKey,store);
  try{
   SSLContext context=SSLContext.getInstance("TLSv1.2");
   context.init(null,new TrustManager[]{pinner},new SecureRandom());
   SSLSocket socket=(SSLSocket)context.getSocketFactory().createSocket(plain,peerHost,plain.getPort(),true);
   socket.setEnabledProtocols(new String[]{"TLSv1.2"});
   socket.setSoTimeout(15000);
   socket.startHandshake();
   socket.setSoTimeout(120000);
   return socket;
  }catch(IOException e){
   try{plain.close();}catch(Exception ignored){}
   if(pinner.failure!=null)throw pinner.failure;
   if(e instanceof SSLException)throw new IOException("Главное устройство не поддерживает защищённое соединение. Обновите приложение Рядом на главном устройстве.",e);
   throw e;
  }catch(GeneralSecurityException e){
   try{plain.close();}catch(Exception ignored){}
   throw new IOException("Не удалось установить защищённое соединение с главным устройством.",e);
  }
 }
 /** Reads /api/health over TLS before joining so a wrong or changed certificate is reported early. */
 static String probe(Socket plain,String peerHost,int peerPort,String pinKey,Store store) throws IOException {
  Socket socket=connect(plain,peerHost,pinKey,store);
  try{
   socket.setSoTimeout(10000);
   OutputStream out=socket.getOutputStream();
   out.write(("GET /api/health HTTP/1.1\r\nHost: "+peerHost+":"+peerPort+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
   out.flush();
   String text=read(socket.getInputStream());
   if(!text.startsWith("HTTP/1.1 200")&&!text.startsWith("HTTP/1.0 200"))throw new IOException("Главное устройство не ответило по защищённому каналу.");
   if(!text.contains("\"app\":\"ryadom\""))throw new IOException("По адресу отвечает не Рядом.");
   return text;
  }finally{try{socket.close();}catch(Exception ignored){}}
 }
 private static String read(InputStream input) throws IOException {
  ByteArrayOutputStream buffer=new ByteArrayOutputStream();
  byte[] bytes=new byte[1024];int header=-1,length=-1;
  while(buffer.size()<8192){
   int count=input.read(bytes);if(count<0)break;
   buffer.write(bytes,0,count);
   String text=new String(buffer.toByteArray(),StandardCharsets.ISO_8859_1);
   if(header<0){
    int end=text.indexOf("\r\n\r\n");
    if(end>=0){
     header=end+4;
     int match=text.toLowerCase(Locale.ROOT).indexOf("\r\ncontent-length:");
     if(match>=0){int start=match+17,stop=text.indexOf('\r',start);if(stop>start)try{length=Integer.parseInt(text.substring(start,stop).trim());}catch(NumberFormatException ignored){}}
    }
   }
   if(header>=0&&length>=0&&buffer.size()-header>=length)break;
  }
  return new String(buffer.toByteArray(),StandardCharsets.UTF_8);
 }
 private static final class Pinner implements X509TrustManager {
  private final String pinKey;private final Store store;volatile PinMismatch failure;
  Pinner(String pinKey,Store store){this.pinKey=pinKey;this.store=store;}
  public void checkClientTrusted(X509Certificate[] chain,String authType) throws CertificateException {throw new CertificateException("Только серверный сертификат");}
  public void checkServerTrusted(X509Certificate[] chain,String authType) throws CertificateException {
   if(chain==null||chain.length==0)throw new CertificateException("Главное устройство не предъявило сертификат");
   String seen;
   try{seen=fingerprint(chain[0]);}catch(CertificateException e){throw e;}
   String known=store.get(pinKey);
   if(known==null||known.isEmpty()){store.put(pinKey,seen);return;}
   if(known.equalsIgnoreCase(seen))return;
   failure=new PinMismatch(pinKey);
   throw new CertificateException(failure.getMessage());
  }
  public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}
 }
}
