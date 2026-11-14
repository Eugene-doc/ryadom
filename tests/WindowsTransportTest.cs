using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Ryadom;
class TransportTest {
 static void Main() {
  var nics=LanInterfaces.Read();if(nics.Count==0)throw new Exception("No physical network for testing");
  foreach(var n in nics)Console.WriteLine("Physical: "+n+" index="+n.Index);
  if(nics.Any(n=>n.Name.ToLower().Contains("happ")))throw new Exception("VPN was selected");
  var nic=nics[0];
  using(var destination=new TcpBridge(nic.Address,0,c=>{throw new Exception();},c=>new byte[0],c=>{},s=>LanInterfaces.BindOutput(s,nic.Index))){}
  var listener=new TcpListener(IPAddress.Parse(nic.Address),0);LanInterfaces.BindOutput(listener.Server,nic.Index);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
  var service=Task.Run(()=>{using(var c=listener.AcceptTcpClient()){LanInterfaces.BindOutput(c.Client,nic.Index);var buffer=new byte[4096];int count=c.GetStream().Read(buffer,0,buffer.Length);c.GetStream().Write(buffer,0,count);}});
  using(var tunnel=new TcpBridge("127.0.0.1",0,c=>LanInterfaces.Connect(nic,nic.Address,port),c=>new byte[0],c=>{}))using(var client=new TcpClient("127.0.0.1",tunnel.Port)){client.ReceiveTimeout=5000;byte[] sent=Encoding.UTF8.GetBytes("Local traffic through physical NIC, even with Happ active");client.GetStream().Write(sent,0,sent.Length);byte[] got=new byte[4096];int n=client.GetStream().Read(got,0,got.Length);if(Encoding.UTF8.GetString(got,0,n)!=Encoding.UTF8.GetString(sent))throw new Exception("Transport mismatch");}
  listener.Stop();service.Wait();Console.WriteLine("Physical-interface binding + TCP transfer: PASS");
  using(var discovery=new LanDiscovery(nics,"Ryadom test")){var found=LanDiscovery.Find(nics);if(!found.Any(c=>c.Name=="Ryadom test"))throw new Exception("Discovery failed");Console.WriteLine("LAN broadcast/multicast discovery: PASS");}

  string dir=Path.Combine(Path.GetTempPath(),"RyadomTlsTest"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);
  string fingerprint;using(var certificate=TlsIdentity.EnsureHostCertificate(dir,out fingerprint)) {
   if(fingerprint.Length!=64)throw new Exception("TLS fingerprint mismatch");
   Console.WriteLine("TLS host certificate: "+fingerprint);
   var upstream=new TcpListener(IPAddress.Loopback,0);upstream.Start();int upstreamPort=((IPEndPoint)upstream.LocalEndpoint).Port;
   var echo=Task.Run(()=>{using(var c=upstream.AcceptTcpClient()){var s=c.GetStream();var b=new byte[4096];int n=s.Read(b,0,b.Length);s.Write(b,0,n);}});
   string pinFile=Path.Combine(dir,"pins.txt");
   using(var server=new TcpBridge("127.0.0.1",0,c=>new TcpClient("127.0.0.1",upstreamPort),c=>new byte[0],c=>{},null,true,certificate))
   using(var client=new TcpBridge("127.0.0.1",0,c=>new TcpClient("127.0.0.1",server.Port),c=>new byte[0],c=>{},null,false,null,true,"ryadom.local","127.0.0.1:"+server.Port,null,pinFile)) {
    using(var outer=new TcpClient("127.0.0.1",client.Port)){outer.ReceiveTimeout=5000;byte[] sent=Encoding.UTF8.GetBytes("TLS bridge test");outer.GetStream().Write(sent,0,sent.Length);byte[] got=new byte[256];int n=outer.GetStream().Read(got,0,got.Length);if(n!=sent.Length||Encoding.UTF8.GetString(got,0,n)!=Encoding.UTF8.GetString(sent))throw new Exception("TLS bridge mismatch");}
    Console.WriteLine("TLS bridge with TOFU pinning: PASS");
    using(var hanging=new TcpBridge("127.0.0.1",0,c=>new TcpClient("127.0.0.1",upstreamPort),c=>new byte[0],c=>{},null,true,certificate,false,null,null,null,null,500))
    using(var raw=new TcpClient("127.0.0.1",hanging.Port)) {
     raw.ReceiveTimeout=5000;var sw=Stopwatch.StartNew();bool closed=false;
     try{int n=raw.GetStream().Read(new byte[1],0,1);closed=n<=0;}catch(IOException){closed=true;}catch(SocketException){closed=true;}
     if(!closed||sw.ElapsedMilliseconds>3000)throw new Exception("TLS handshake deadline was not enforced");
     Console.WriteLine("TLS handshake deadline: PASS");
    }
    string pinDirectory=Path.Combine(dir,"pins-as-directory");Directory.CreateDirectory(pinDirectory);
    string pinStoreError;
    if(TlsIdentity.Validate("host",certificate,pinDirectory,out pinStoreError)||string.IsNullOrEmpty(pinStoreError))throw new Exception("Unwritable pin store was accepted");
    Console.WriteLine("TLS pin store failure is reported: PASS");
    string encoded=Convert.ToBase64String(Encoding.UTF8.GetBytes("127.0.0.1:"+server.Port));
    File.WriteAllText(pinFile,encoded+"\t"+"00"+"\n");
    bool rejected=false;
    try{using(var bad=new TcpClient("127.0.0.1",client.Port)){bad.ReceiveTimeout=5000;byte[] sent=Encoding.UTF8.GetBytes("must not pass");bad.GetStream().Write(sent,0,sent.Length);byte[] got=new byte[64];int n=bad.GetStream().Read(got,0,got.Length);if(n<=0)rejected=true;}}
    catch(SocketException){rejected=true;}catch(IOException){rejected=true;}
    if(!rejected)throw new Exception("Changed TLS certificate was not rejected");
    Console.WriteLine("TLS certificate change rejection: PASS");
   }
   upstream.Stop();echo.Wait();
  }
  try{Directory.Delete(dir,true);}catch{}
  var rule=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase){{"enabled","True"},{"direction","Inbound"},{"action","Allow"},{"profile","Private, Domain"},{"program","C:\\app.exe"},{"protocol","TCP"},{"port","4280"},{"remote","LocalSubnet"}};
  var rules=new Dictionary<string,Dictionary<string,string>>{{"Ryadom chat TCP 4280",rule}};
  var ruleProblems=new List<string>();
  if(!FirewallAdvisor.ValidateRule(rules,"Ryadom chat TCP 4280","TCP",4280,"C:\\app.exe",ruleProblems))throw new Exception("Valid firewall rule was rejected: "+string.Join("; ",ruleProblems));
  rule["profile"]="Public";
  if(FirewallAdvisor.ValidateRule(rules,"Ryadom chat TCP 4280","TCP",4280,"C:\\app.exe",ruleProblems))throw new Exception("Public firewall profile was accepted");
  Console.WriteLine("Firewall rule parser: PASS");
 }
}
