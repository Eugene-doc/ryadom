package local.ryadom.chat;

import android.content.Context;
import android.content.SharedPreferences;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Locale;

/** Stable per-install identity; role and IP are deliberately absent. */
final class DeviceIdentity {
 final String id;
 final String token;

 private DeviceIdentity(String id, String token) { this.id = id; this.token = token; }

 static DeviceIdentity load(Context context) {
  SharedPreferences prefs = context.getSharedPreferences("ryadom", Context.MODE_PRIVATE);
  String id = prefs.getString("device_id", "");
  if (id == null || !id.matches("d1-[0-9a-f]{32}")) {
   id = "d1-" + hex(16);
   prefs.edit().putString("device_id", id).apply();
  }
  String token = prefs.getString("device_token", "");
  if (token == null || !token.matches("[0-9a-f]{64}")) {
   token = hex(32);
   prefs.edit().putString("device_token", token).apply();
  }
  return new DeviceIdentity(id, token);
 }

 private static String hex(int bytes) {
  byte[] value = new byte[bytes];
  new SecureRandom().nextBytes(value);
  StringBuilder out = new StringBuilder(bytes * 2);
  for (byte b : value) out.append(String.format(Locale.ROOT, "%02x", b));
  return out.toString();
 }

 String fingerprint() {
  try {
   byte[] digest = MessageDigest.getInstance("SHA-256").digest(id.getBytes(java.nio.charset.StandardCharsets.UTF_8));
   StringBuilder out = new StringBuilder(digest.length * 2);
   for (byte b : digest) out.append(String.format(Locale.ROOT, "%02x", b));
   return out.toString();
  } catch (Exception e) {
   return "";
  }
 }
}
