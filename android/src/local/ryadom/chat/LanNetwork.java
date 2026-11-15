package local.ryadom.chat;

import android.content.Context;
import android.net.*;
import java.io.IOException;
import java.net.*;
import java.util.*;

final class LanNetwork {
 final Network network;final List<LinkAddress> addresses;final ConnectivityManager manager;
 LanNetwork(Network n,List<LinkAddress> a,ConnectivityManager m){network=n;addresses=a;manager=m;}
 static LanNetwork select(Context context,String target) throws IOException {
  ConnectivityManager manager=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
  for(Network network:manager.getAllNetworks()){
   NetworkCapabilities c=manager.getNetworkCapabilities(network);LinkProperties p=manager.getLinkProperties(network);
   if(c==null||p==null||c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)||!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)||(!c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)&&!c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)))continue;
   List<LinkAddress> addresses=new ArrayList<>();for(LinkAddress a:p.getLinkAddresses())if(a.getAddress() instanceof Inet4Address&&privateAddress(a.getAddress().getHostAddress()))addresses.add(a);
   if(addresses.isEmpty())continue;LanNetwork candidate=new LanNetwork(network,addresses,manager);if(target==null||candidate.contains(target))return candidate;
  }
  throw new IOException("Не найдена домашняя Wi-Fi / Ethernet сеть для этого адреса. Используйте адрес главного устройства из домашней сети, не адрес Happ.");
 }
 boolean contains(String ip){for(LinkAddress a:addresses)if(sameSubnet(a.getAddress().getAddress(),a.getPrefixLength(),ip))return true;return false;}
 boolean available(){NetworkCapabilities c=manager.getNetworkCapabilities(network);return c!=null&&!c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)&&c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);}
 Socket connect(String host,int port) throws IOException {
  if(!contains(host)||!available())throw new IOException("Локальная сеть недоступна");
  IOException failure=null;
  try{return connect(boundSocket(),host,port);}
  catch(IOException e){
   if(!permissionFailure(e))throw e;
   failure=e;
  }
  // A third-party VPN may reject Network.bindSocket with EPERM. Creating the socket here (rather
  // than via Network.getSocketFactory, which leaked a descriptor on old Android) lets us close it
  // deterministically; the unbound retry follows the system route where Happ can use LAN Direct.
  try{return connect(new Socket(),host,port);}
  catch(IOException e){if(failure!=null)e.addSuppressed(failure);throw e;}
 }
 /** Binds a socket we own, so every failure path can close it. */
 private Socket boundSocket() throws IOException {
  Socket socket=new Socket();
  try{network.bindSocket(socket);return socket;}
  catch(IOException e){close(socket);throw e;}
  catch(SecurityException e){close(socket);throw new IOException("Android запретил привязку к локальной сети",e);}
 }
 private Socket connect(Socket socket,String host,int port) throws IOException {
  boolean success=false;
  try{
   socket.connect(new InetSocketAddress(InetAddress.getByName(host),port),5000);
   socket.setSoTimeout(120000);socket.setTcpNoDelay(true);success=true;return socket;
  }
  catch(IOException e){throw e;}
  catch(SecurityException e){throw new IOException("Android запретил подключение к локальной сети",e);}
  finally{if(!success)close(socket);}
 }
 private static void close(Socket socket){try{socket.close();}catch(Exception ignored){}}
 List<String> ips(){List<String> result=new ArrayList<>();for(LinkAddress a:addresses)result.add(a.getAddress().getHostAddress());return result;}
 static boolean vpnActive(Context context){
  try{
   ConnectivityManager manager=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
   for(Network network:manager.getAllNetworks()){NetworkCapabilities c=manager.getNetworkCapabilities(network);if(c!=null&&c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return true;}
  }catch(Exception ignored){}
  return false;
 }
 static boolean permissionFailure(Throwable error){
  for(Throwable e=error;e!=null;e=e.getCause()){
   if(e instanceof SecurityException)return true;
   String message=e.getMessage();
   if(message!=null&&(message.contains("EPERM")||message.contains("Operation not permitted")||message.contains("Permission denied")))return true;
  }
  return false;
 }
 static boolean sameSubnet(byte[] address,int prefix,String target){try{byte[] b=InetAddress.getByName(target).getAddress();if(b.length!=4||address.length!=4||prefix<1||prefix>32)return false;for(int i=0;i<4;i++){int bits=Math.min(8,Math.max(0,prefix-i*8));int mask=bits==0?0:(255<<(8-bits))&255;if((address[i]&mask)!=(b[i]&mask))return false;}return true;}catch(Exception e){return false;}}
 static boolean privateAddress(String host){String[] parts=host.split("\\.");if(parts.length!=4)return false;int[] n=new int[4];try{for(int i=0;i<4;i++){if(!parts[i].matches("0|[1-9][0-9]{0,2}"))return false;n[i]=Integer.parseInt(parts[i]);if(n[i]>255)return false;}}catch(Exception e){return false;}return n[0]==10||(n[0]==192&&n[1]==168)||(n[0]==172&&n[1]>=16&&n[1]<=31)||(n[0]==169&&n[1]==254);}
}
