package local.ryadom.chat;

import android.content.SharedPreferences;
import java.io.IOException;
import java.net.Socket;

/** Android storage for TLS trust pins: the first fingerprint for "host:port" is remembered forever. */
final class TlsTrust {
 private TlsTrust(){}
 private static TlsPin.Store store(final SharedPreferences preferences){
  return new TlsPin.Store(){
   public String get(String key){return preferences.getString(key,"");}
   public void put(String key,String value){preferences.edit().putString(key,value).apply();}
   public void remove(String key){preferences.edit().remove(key).apply();}
  };
 }
 static Socket connect(Socket plain,String host,int port,SharedPreferences preferences) throws IOException {
  return TlsPin.connect(plain,host,TlsPin.address(host,port),store(preferences));
 }
 static String probe(Socket plain,String host,int port,SharedPreferences preferences) throws IOException {
  return TlsPin.probe(plain,host,port,TlsPin.address(host,port),store(preferences));
 }
 static TlsPin.Inspection inspect(Socket plain,String host,int port,SharedPreferences preferences) throws IOException {
  return TlsPin.inspect(plain,host,port,TlsPin.address(host,port),store(preferences));
 }
 static void remember(SharedPreferences preferences,String key,String fingerprint){store(preferences).put(key,fingerprint);}
 static void reset(SharedPreferences preferences,String address){store(preferences).remove(address);}
}
