package local.ryadom.chat;

import java.io.IOException;

/** Verifies the EPERM classification used by the Android VPN fallback. */
public final class NetworkFallbackTest {
 public static void main(String[] args){
  if(!LanNetwork.permissionFailure(new IOException("Binding socket to network 316 failed: EPERM (Operation not permitted)")))throw new AssertionError("EPERM must be recognized");
  if(!LanNetwork.permissionFailure(new SecurityException("denied")))throw new AssertionError("SecurityException must be recognized");
  if(!LanNetwork.permissionFailure(new IOException("wrapper",new IOException("Operation not permitted"))))throw new AssertionError("wrapped EPERM must be recognized");
  if(LanNetwork.permissionFailure(new IOException("Connection refused")))throw new AssertionError("ordinary network errors must not trigger fallback");
  if(LanNetwork.permissionFailure(new IOException("timeout")))throw new AssertionError("timeout must not trigger fallback");
  System.out.println("Android VPN EPERM fallback classification passed");
 }
}
