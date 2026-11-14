package local.ryadom.chat;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.net.ssl.*;

/**
 * TLS identity of the Android host: a self-signed RSA-2048 certificate for CN=Ryadom Host,
 * generated with JCA and a minimal DER encoder, persisted as PKCS12 in the app data directory.
 * The server context speaks TLS 1.2 only; the fingerprint is pinned by clients (TOFU).
 */
final class TlsIdentity {
 static final String SUBJECT_CN="Ryadom Host";
 static final String VERSION="2";
 static final long VALIDITY_MS=5L*365*24*60*60*1000;
 private static final String OID_SHA256_RSA="1.2.840.113549.1.1.11";
 private static final String OID_RSA="1.2.840.113549.1.1.1";
 private static final String OID_CN="2.5.4.3";
 static final String ALIAS="host";
 final X509Certificate certificate;
 final PrivateKey privateKey;
 final String fingerprint;
 final SSLContext context;
 private TlsIdentity(X509Certificate certificate,PrivateKey privateKey,String fingerprint,SSLContext context){this.certificate=certificate;this.privateKey=privateKey;this.fingerprint=fingerprint;this.context=context;}
 static TlsIdentity ensure(File dir) throws Exception {
  if(!dir.isDirectory()&&!dir.mkdirs()&&!dir.isDirectory())throw new IOException("Не удалось создать каталог TLS");
  File storeFile=new File(dir,"host.p12"),passwordFile=new File(dir,"password.txt"),fingerprintFile=new File(dir,"fingerprint.txt");
  char[] password=password(passwordFile);
  X509Certificate certificate=null;PrivateKey privateKey=null;
  if(storeFile.isFile()){
   try{
    KeyStore store=KeyStore.getInstance("PKCS12");
    try(InputStream in=new FileInputStream(storeFile)){store.load(in,password);}
    privateKey=(PrivateKey)store.getKey(ALIAS,password);
    Certificate stored=store.getCertificate(ALIAS);
    if(stored instanceof X509Certificate)certificate=(X509Certificate)stored;
   }catch(Exception e){certificate=null;privateKey=null;}
  }
  if(certificate==null||privateKey==null){certificate=null;privateKey=null;generate(storeFile,password);KeyStore store=KeyStore.getInstance("PKCS12");try(InputStream in=new FileInputStream(storeFile)){store.load(in,password);}privateKey=(PrivateKey)store.getKey(ALIAS,password);certificate=(X509Certificate)store.getCertificate(ALIAS);if(certificate==null||privateKey==null){storeFile.delete();throw new IOException("Не удалось сохранить TLS-сертификат");}}
  String fingerprint=fingerprint(certificate);
  try{write(fingerprintFile,fingerprint.getBytes(StandardCharsets.UTF_8));}catch(Exception ignored){}
  SSLContext context=SSLContext.getInstance("TLSv1.2");
  context.init(new KeyManager[]{new ServerKeyManager(privateKey,new Certificate[]{certificate})},null,new SecureRandom());
  return new TlsIdentity(certificate,privateKey,fingerprint,context);
 }
 private static void generate(File storeFile,char[] password) throws Exception {
  KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048,new SecureRandom());KeyPair pair=generator.generateKeyPair();
  long now=System.currentTimeMillis();
  byte[] request=request(pair.getPublic(),new BigInteger(63,new SecureRandom()).add(BigInteger.ONE),now-24L*60*60*1000,now+VALIDITY_MS);
  Signature signer=Signature.getInstance("SHA256withRSA");signer.initSign(pair.getPrivate());signer.update(request);byte[] signature=signer.sign();
  byte[] encoded=sequence(request,algorithm(),bitString(signature));
  X509Certificate certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
  KeyStore store=KeyStore.getInstance("PKCS12");store.load(null,null);store.setKeyEntry(ALIAS,pair.getPrivate(),password,new Certificate[]{certificate});
  File temporary=new File(storeFile.getPath()+".tmp");
  try(FileOutputStream out=new FileOutputStream(temporary)){store.store(out,password);out.getFD().sync();}
  try{Files.move(temporary.toPath(),storeFile.toPath(),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}catch(AtomicMoveNotSupportedException e){Files.move(temporary.toPath(),storeFile.toPath(),StandardCopyOption.REPLACE_EXISTING);}
  restrict(storeFile);
 }
 private static byte[] request(java.security.PublicKey publicKey,BigInteger serial,long notBefore,long notAfter) throws Exception {
  byte[] name=sequence(set(sequence(oid(OID_CN),utf8(SUBJECT_CN))));
  RSAPublicKey key=(RSAPublicKey)publicKey;
  byte[] spki=sequence(sequence(oid(OID_RSA),nullValue()),bitString(sequence(integer(key.getModulus()),integer(key.getPublicExponent()))));
  return sequence(explicit(0,integer(new BigInteger(VERSION))),integer(serial),algorithm(),name,sequence(time(notBefore),time(notAfter)),name,spki);
 }
 private static char[] password(File file) {
  try{
   if(file.isFile()){String value=new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8).trim();if(value.length()>=16)return value.toCharArray();}
  }catch(Exception ignored){}
  byte[] bytes=new byte[24];new SecureRandom().nextBytes(bytes);String value=Base64.getEncoder().encodeToString(bytes);
  try{File temporary=new File(file.getPath()+".tmp");write(temporary,value.getBytes(StandardCharsets.UTF_8));restrict(temporary);try{Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING);}catch(AtomicMoveNotSupportedException e){Files.move(temporary.toPath(),file.toPath(),StandardCopyOption.REPLACE_EXISTING);}}catch(Exception ignored){}
  return value.toCharArray();
 }
 private static void write(File file,byte[] content) throws IOException {
  try(FileOutputStream out=new FileOutputStream(file)){out.write(content);out.getFD().sync();}
 }
 private static void restrict(File file){try{file.setReadable(false,false);file.setReadable(true,true);file.setWritable(false,false);file.setWritable(true,true);file.setExecutable(false,false);}catch(Exception ignored){}}
 static String fingerprint(X509Certificate certificate) throws Exception {
  byte[] hash=MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
  StringBuilder text=new StringBuilder(hash.length*2);
  for(byte value:hash)text.append(String.format(Locale.ROOT,"%02x",value));
  return text.toString();
 }
 // Minimal DER encoder: TBSCertificate, Name, validity, SPKI and SHA256withRSA.
 private static byte[] der(int tag,byte[] content){
  ByteArrayOutputStream out=new ByteArrayOutputStream();
  out.write(tag);int length=content.length;
  if(length<128)out.write(length);
  else{int size=0;for(int value=length;value>0;value>>>=8)size++;out.write(0x80|size);for(int shift=(size-1)*8;shift>=0;shift-=8)out.write((length>>>shift)&0xff);}
  out.write(content,0,content.length);return out.toByteArray();
 }
 private static byte[] join(byte[]... parts){ByteArrayOutputStream out=new ByteArrayOutputStream();for(byte[] part:parts)out.write(part,0,part.length);return out.toByteArray();}
 private static byte[] sequence(byte[]... parts){return der(0x30,join(parts));}
 private static byte[] set(byte[]... parts){return der(0x31,join(parts));}
 private static byte[] explicit(int number,byte[] content){return der(0xa0+number,content);}
 private static byte[] integer(BigInteger value){return der(0x02,value.toByteArray());}
 private static byte[] bitString(byte[] value){byte[] content=new byte[value.length+1];System.arraycopy(value,0,content,1,value.length);return der(0x03,content);}
 private static byte[] nullValue(){return new byte[]{0x05,0x00};}
 private static byte[] utf8(String value){return der(0x0c,value.getBytes(StandardCharsets.UTF_8));}
 private static byte[] time(long epoch){
  Calendar calendar=Calendar.getInstance(TimeZone.getTimeZone("UTC"));calendar.setTimeInMillis(epoch);int year=calendar.get(Calendar.YEAR);
  boolean utc=year>=1950&&year<2050;
  SimpleDateFormat format=new SimpleDateFormat(utc?"yyMMddHHmmss'Z'":"yyyyMMddHHmmss'Z'",Locale.US);format.setTimeZone(TimeZone.getTimeZone("UTC"));
  return der(utc?0x17:0x18,format.format(new Date(epoch)).getBytes(StandardCharsets.US_ASCII));
 }
 private static byte[] algorithm(){return sequence(oid(OID_SHA256_RSA),nullValue());}
 private static byte[] oid(String value){
  String[] parts=value.split("\\.");ByteArrayOutputStream out=new ByteArrayOutputStream();
  out.write(40*Integer.parseInt(parts[0])+Integer.parseInt(parts[1]));
  for(int i=2;i<parts.length;i++){
   long number=Long.parseLong(parts[i]);ByteArrayOutputStream digits=new ByteArrayOutputStream();
   digits.write((int)(number&0x7f));number>>>=7;
   while(number>0){digits.write((int)((number&0x7f)|0x80));number>>>=7;}
   byte[] bytes=digits.toByteArray();for(int j=bytes.length-1;j>=0;j--)out.write(bytes[j]);
  }
  return der(0x06,out.toByteArray());
 }
 private static final class ServerKeyManager extends X509ExtendedKeyManager {
  private final PrivateKey key;private final X509Certificate[] chain;
  ServerKeyManager(PrivateKey key,Certificate[] chain){this.key=key;this.chain=new X509Certificate[chain.length];for(int i=0;i<chain.length;i++)this.chain[i]=(X509Certificate)chain[i];}
  public String chooseEngineServerAlias(String keyType,Principal[] issuers,SSLEngine engine){return ALIAS;}
  public String chooseEngineClientAlias(String[] keyType,Principal[] issuers,SSLEngine engine){return null;}
  public String[] getClientAliases(String keyType,Principal[] issuers){return null;}
  public String chooseClientAlias(String[] keyType,Principal[] issuers,java.net.Socket socket){return null;}
  public String[] getServerAliases(String keyType,Principal[] issuers){return new String[]{ALIAS};}
  public String chooseServerAlias(String keyType,Principal[] issuers,java.net.Socket socket){return ALIAS;}
  public X509Certificate[] getCertificateChain(String alias){return ALIAS.equals(alias)?chain.clone():null;}
  public PrivateKey getPrivateKey(String alias){return ALIAS.equals(alias)?key:null;}
 }
}
