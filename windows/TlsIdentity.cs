using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Ryadom {
 // TLS identity of the host and TOFU pinning of the host certificate on clients.
 internal static class TlsIdentity {
  private static readonly SslProtocols Protocols=(SslProtocols)3072; // TLS 1.2 (enum value is missing in .NET 4.0 reference assemblies)
  public static string PinFile { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Ryadom","tls-pins.txt"); } }
  public static string Fingerprint(X509Certificate2 certificate) {
   if(certificate==null)return "";
   using(var sha=SHA256.Create()){byte[] hash=sha.ComputeHash(certificate.RawData);var text=new StringBuilder(hash.Length*2);foreach(byte b in hash)text.Append(b.ToString("x2"));return text.ToString();}
  }
  public static X509Certificate2 EnsureHostCertificate(string dataDir,out string fingerprint) {
   string dir=Path.Combine(dataDir,"tls");Directory.CreateDirectory(dir);
   string pfx=Path.Combine(dir,"host.pfx"),passwordFile=Path.Combine(dir,"password.txt"),fingerprintFile=Path.Combine(dir,"fingerprint.txt");
   if(!File.Exists(pfx)||!File.Exists(passwordFile))Generate(dir,pfx,passwordFile);
   string password=File.ReadAllText(passwordFile).Trim();
   var certificate=new X509Certificate2(pfx,password,X509KeyStorageFlags.Exportable|X509KeyStorageFlags.PersistKeySet);
   fingerprint=Fingerprint(certificate);
   try{File.WriteAllText(fingerprintFile,fingerprint,new UTF8Encoding(false));}catch{}
   return certificate;
  }
  private static string Quote(string value){return "'"+value.Replace("'","''")+"'";}
  private static void Generate(string dir,string pfx,string passwordFile) {
   string script=
    "$ErrorActionPreference='Stop';"+
    "$dir="+Quote(dir)+";"+
    "$pfx="+Quote(pfx)+";"+
    "$passwordFile="+Quote(passwordFile)+";"+
    "if(-not (Test-Path -LiteralPath $passwordFile)){$b=New-Object byte[] 32;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);[IO.File]::WriteAllText($passwordFile,[Convert]::ToBase64String($b))}"+
    "$pwd=(Get-Content -LiteralPath $passwordFile -Raw).Trim();$secure=ConvertTo-SecureString $pwd -AsPlainText -Force;"+
    "$cert=New-SelfSignedCertificate -Type SSLServerAuthentication -Subject 'CN=Ryadom Host' -DnsName 'ryadom.local','localhost' -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation 'Cert:\\CurrentUser\\My' -NotAfter (Get-Date).AddYears(5) -KeyExportPolicy Exportable;"+
    "Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $secure | Out-Null;"+
    "Remove-Item -LiteralPath ('Cert:\\CurrentUser\\My\\'+$cert.Thumbprint) -Force;";
   var start=new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script))){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
   using(var process=Process.Start(start)) {
    string output=process.StandardOutput.ReadToEnd()+process.StandardError.ReadToEnd();
    if(!process.WaitForExit(60000)){try{process.Kill();}catch{}throw new IOException("Не удалось создать TLS-сертификат: превышено время ожидания.");}
    if(process.ExitCode!=0||!File.Exists(pfx))throw new IOException("Не удалось создать TLS-сертификат. "+output.Trim());
   }
  }
  // TOFU: the first seen fingerprint is pinned; a changed certificate is rejected with a clear message.
  public static bool Validate(string pinKey,X509Certificate2 certificate,string pinFile,out string error) {
   error="";
   string fingerprint=Fingerprint(certificate);
   string existing=ReadPin(pinKey,pinFile);
   if(string.IsNullOrEmpty(existing)){WritePin(pinKey,fingerprint,pinFile);return true;}
   if(string.Equals(existing,fingerprint,StringComparison.OrdinalIgnoreCase))return true;
   error="Сертификат главного устройства изменился. Если главное устройство переустанавливали, удалите файл "+pinFile+" и подключитесь заново.";
   return false;
  }
  private static string ReadPin(string key,string file) {
   try {
    if(!File.Exists(file))return null;
    string encoded=Convert.ToBase64String(Encoding.UTF8.GetBytes(key));
    foreach(string line in File.ReadAllLines(file)){string[] parts=line.Split('\t');if(parts.Length==2&&parts[0]==encoded)return parts[1];}
   }catch{}
   return null;
  }
  private static void WritePin(string key,string fingerprint,string file) {
   try {
    string encoded=Convert.ToBase64String(Encoding.UTF8.GetBytes(key));
    var lines=File.Exists(file)?File.ReadAllLines(file).Where(x=>{string[] p=x.Split('\t');return p.Length!=2||p[0]!=encoded;}).ToList():new List<string>();
    lines.Add(encoded+"\t"+fingerprint);
    Directory.CreateDirectory(Path.GetDirectoryName(file));
    File.WriteAllLines(file,lines,new UTF8Encoding(false));
   }catch{}
  }
  // Probe used before joining: performs a TLS handshake and reads /api/health over TLS.
  public static string Probe(LanInterface nic,string host,int port) {
   using(var client=LanInterfaces.Connect(nic,host,port)) {
    client.ReceiveTimeout=15000;client.SendTimeout=15000;
    string pinError=null;
    using(var ssl=new SslStream(client.GetStream(),false,(sender,certificate,chain,errors)=>{if(certificate==null)return false;var cert2=new X509Certificate2(certificate);bool ok=Validate(host+":"+port,cert2,PinFile,out pinError);return ok;})) {
     try{ssl.AuthenticateAsClient(host,null,Protocols,false);}
     catch(AuthenticationException){throw new IOException(pinError??"Главное устройство не поддерживает защищённое соединение. Обновите приложение Рядом на главном устройстве.");}
     byte[] request=Encoding.ASCII.GetBytes("GET /api/health HTTP/1.1\r\nHost: "+host+":"+port+"\r\nConnection: close\r\n\r\n");
     ssl.Write(request,0,request.Length);ssl.Flush();
     var buffer=new byte[2048];int total=0,read;
     while(total<buffer.Length&&(read=ssl.Read(buffer,total,buffer.Length-total))>0)total+=read;
     string text=Encoding.UTF8.GetString(buffer,0,total);
     if(!text.StartsWith("HTTP/1.1 200")&&!text.StartsWith("HTTP/1.0 200"))throw new IOException("Главное устройство не ответило по защищённому каналу.");
     if(!text.Contains("\"app\":\"ryadom\""))throw new IOException("По адресу отвечает не Рядом.");
     return text;
    }
   }
  }
 }
}
