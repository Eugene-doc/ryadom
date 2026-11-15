package local.ryadom.chat;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

final class Discovery implements AutoCloseable {
 interface Binder {void bind(DatagramSocket socket) throws IOException;}
 static final int PORT=42800;
 static final class Found {final String name,address;final int port;Found(String n,String a,int p){name=n;address=a;port=p;}public String toString(){return name+" — "+address+":"+port;}}
 final MulticastSocket socket;final List<String> ips;final List<Integer> prefixes;final Binder binder;volatile boolean closed;
 Discovery(List<String> addresses,List<Integer> masks,String name,Binder binding) throws Exception {
  ips=addresses;prefixes=masks;binder=binding;
  MulticastSocket created=new MulticastSocket(null);
  try{
   created.setReuseAddress(true);created.bind(new InetSocketAddress(PORT));
   for(String ip:ips)try{created.joinGroup(new InetSocketAddress("239.255.42.80",PORT),NetworkInterface.getByInetAddress(InetAddress.getByName(ip)));}catch(IOException|RuntimeException ignored){}
  }catch(Exception e){try{created.close();}catch(Exception ignored){}throw e;}
  socket=created;
  Thread thread=new Thread(()->listen(name),"Ryadom discovery");thread.setDaemon(true);thread.start();
 }
 private String nic(String remote){for(int i=0;i<ips.size();i++)try{if(LanNetwork.sameSubnet(InetAddress.getByName(ips.get(i)).getAddress(),prefixes.get(i),remote))return ips.get(i);}catch(Exception ignored){}return null;}
 private void listen(String name){
  int failures=0;
  while(!closed){
   DatagramPacket packet=new DatagramPacket(new byte[1024],1024);
   try{socket.receive(packet);failures=0;}
   catch(Exception e){
    if(closed)return;
    failures=Math.min(failures+1,20);
    try{Thread.sleep(200L*failures);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();return;}
    continue;
   }
   try{handle(packet,name);}catch(Exception ignored){}
  }
 }
 private void handle(DatagramPacket packet,String name) throws Exception {
  String text=new String(packet.getData(),0,packet.getLength(),StandardCharsets.UTF_8);
  if(!text.matches("RYADOM_FIND_V1\\t[0-9a-f]{32}"))return;
  String address=nic(packet.getAddress().getHostAddress());if(address==null)return;
  String response="RYADOM_HERE_V1\t"+text.substring(15)+"\t"+address+"\t4280\t"+Base64.getEncoder().encodeToString(name.getBytes(StandardCharsets.UTF_8));
  byte[] bytes=response.getBytes(StandardCharsets.UTF_8);
  try(DatagramSocket sender=new DatagramSocket(new InetSocketAddress(InetAddress.getByName(address),0))){
   try{binder.bind(sender);}catch(SecurityException|IOException ignored){}
   sender.send(new DatagramPacket(bytes,bytes.length,packet.getAddress(),packet.getPort()));
  }
 }
 /** Each interface is independent: a VPN/multicast failure must not discard replies from another LAN. */
 static List<Found> find(List<String> ips,List<Integer> prefixes,Binder binder) throws Exception {
  Map<String,Found> found=new LinkedHashMap<>();String lastError=null;boolean anySent=false;
  for(int i=0;i<ips.size();i++){
   String ip=ips.get(i);int prefix=prefixes.get(i);
   try{
    byte[] address=InetAddress.getByName(ip).getAddress(),broadcast=address.clone();
    for(int j=0;j<4;j++){int bits=Math.min(8,Math.max(0,prefix-j*8));int mask=bits==0?0:(255<<(8-bits))&255;broadcast[j]=(byte)(address[j]|~mask);}
    try(DatagramSocket socket=new DatagramSocket(new InetSocketAddress(InetAddress.getByName(ip),0))){
     try{binder.bind(socket);}catch(SecurityException|IOException ignored){}
     socket.setBroadcast(true);socket.setSoTimeout(300);
     String nonce=UUID.randomUUID().toString().replace("-","");
     byte[] request=("RYADOM_FIND_V1\t"+nonce).getBytes(StandardCharsets.UTF_8);
     boolean sent=false;
     try{socket.send(new DatagramPacket(request,request.length,InetAddress.getByAddress(broadcast),PORT));sent=true;anySent=true;}
     catch(IOException|SecurityException e){lastError=message(e);}
     try{socket.send(new DatagramPacket(request,request.length,InetAddress.getByName("239.255.42.80"),PORT));sent=true;anySent=true;}
     catch(IOException|SecurityException e){if(lastError==null)lastError=message(e);}
     if(!sent){if(lastError==null)lastError="Не удалось отправить поиск через локальную сеть.";continue;}
     long until=System.currentTimeMillis()+2000;
     while(System.currentTimeMillis()<until){
      DatagramPacket reply=new DatagramPacket(new byte[1024],1024);
      try{socket.receive(reply);}
      catch(SocketTimeoutException ignored){continue;}
      catch(IOException e){lastError=message(e);break;}
      try{parse(reply,nonce,address,prefix,found);}catch(Exception ignored){}
     }
    }
   }catch(Exception e){lastError=message(e);}
  }
  if(found.isEmpty()&&!anySent&&lastError!=null)throw new IOException(lastError);
  return new ArrayList<>(found.values());
 }
 private static void parse(DatagramPacket reply,String nonce,byte[] address,int prefix,Map<String,Found> found) throws Exception {
  String[] p=new String(reply.getData(),0,reply.getLength(),StandardCharsets.UTF_8).split("\t");
  if(p.length!=5||!p[0].equals("RYADOM_HERE_V1")||!p[1].equals(nonce)||!p[2].equals(reply.getAddress().getHostAddress())||!LanNetwork.sameSubnet(address,prefix,p[2]))return;
  int port=Integer.parseInt(p[3]);if(port<1||port>65535)return;
  String name=new String(Base64.getDecoder().decode(p[4]),StandardCharsets.UTF_8);if(name.length()>80)return;
  found.put(p[2]+":"+port,new Found(name,p[2],port));
 }
 private static String message(Exception e){String value=e.getMessage();return value==null||value.isEmpty()?"Не удалось выполнить поиск в локальной сети":value;}
 public void close(){closed=true;socket.close();}
}
