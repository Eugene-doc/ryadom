using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Ryadom {
 internal sealed class ChatApplication : ApplicationContext {
  private static readonly string Data=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Ryadom");
  private static readonly DeviceIdentity Device=DeviceIdentity.Load(Data);
  private static bool chooseAgain;
  private readonly NotifyIcon tray;
  private readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
  private readonly List<TcpBridge> bridges=new List<TcpBridge>();
  private readonly string bridgeKey=NativeKey();
  private readonly RolePicker choice;
  private LanDiscovery discovery;
  private Process host;
  private ChatWindow window;
  private int tries;
  private bool stopping,ready,firewallChecked;
  private string networkStamp=null;
  private X509Certificate2 hostCert;
  private const string BaseUrl="http://127.0.0.1:4280/";
  private static readonly string NativeKeyFile=Path.Combine(Data,"native-key");
  private static readonly string LastHostFile=Path.Combine(Data,"last-host");
  private static void ReadLastHost(out string id,out string fingerprint) {
   id="";fingerprint="";
   try{foreach(string line in File.ReadAllLines(LastHostFile)){int at=line.IndexOf('=');if(at<0)continue;string key=line.Substring(0,at),value=line.Substring(at+1);if(key=="id")id=value;else if(key=="fingerprint")fingerprint=value;}}catch{}
  }
  private static void WriteLastHost(string id,string fingerprint) {
   try{if(string.IsNullOrEmpty(id)||string.IsNullOrEmpty(fingerprint))File.Delete(LastHostFile);else File.WriteAllText(LastHostFile,"id="+id+Environment.NewLine+"fingerprint="+fingerprint+Environment.NewLine,new UTF8Encoding(false));}catch{}
  }
  private static string NativeKey() {
   try{if(File.Exists(NativeKeyFile)){string key=File.ReadAllText(NativeKeyFile).Trim();if(key.Length==64)return key;}}catch{}
   string generated=Guid.NewGuid().ToString("N")+Guid.NewGuid().ToString("N");
   try{Directory.CreateDirectory(Data);File.WriteAllText(NativeKeyFile,generated,new UTF8Encoding(false));}catch{}
   return generated;
  }
  // One-time host login token for the browser; the permanent native key never reaches the command line or URL.
  private static string RequestHostToken() {
   var request=(HttpWebRequest)WebRequest.Create(BaseUrl+"api/local/host-token");
   request.Proxy=null;request.Method="POST";request.Timeout=3000;request.ReadWriteTimeout=3000;request.ContentLength=0;
   request.Headers["X-Ryadom"]="1";request.Headers["X-Ryadom-Native"]=NativeKey();
   using(var response=request.GetResponse())using(var reader=new StreamReader(response.GetResponseStream(),Encoding.UTF8)) {
    string text=reader.ReadToEnd();
    var match=System.Text.RegularExpressions.Regex.Match(text,"\"token\"\\s*:\\s*\"([0-9a-f]{64})\"");
    if(!match.Success)throw new IOException("Не удалось получить токен входа");
    return match.Groups[1].Value;
   }
  }
  [DllImport("shell32.dll", CharSet=CharSet.Unicode)] private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);
  [STAThread] private static void Main(string[] args) {
   SetCurrentProcessExplicitAppUserModelID("Ryadom.Chat");
   WebView2Bootstrap.InstallResolver();
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Directory.CreateDirectory(Data);
   if(args.Length>0&&args[0]=="--firewall-check") {
    string text;try{text=FirewallAdvisor.Inspect().ToString();}catch(Exception e){text="Не удалось проверить брандмауэр: "+e.Message;}text+=Environment.NewLine+"Приложение: "+Application.ExecutablePath;
    if(args.Length>1)File.WriteAllText(args[1],text,new UTF8Encoding(false));else MessageBox.Show(text,"Рядом · брандмауэр и сеть");
    return;
   }
   bool first;
   using(var mutex=new Mutex(true,"Local\\Ryadom.PersonalChat",out first)) {
    if(!first){MessageBox.Show("Рядом уже запущен. Откройте окно чата через значок рядом с часами.","Рядом",MessageBoxButtons.OK,MessageBoxIcon.Information);return;}
    do {chooseAgain=false;try{string lastId,lastFingerprint;ReadLastHost(out lastId,out lastFingerprint);using(var picker=new RolePicker(File.Exists(Path.Combine(Data,"last-target"))?File.ReadAllText(Path.Combine(Data,"last-target")):"",lastId,lastFingerprint)){if(picker.ShowDialog()!=DialogResult.OK)return;using(var app=new ChatApplication(picker))Application.Run(app);}}catch(Exception e){MessageBox.Show("Не удалось запустить Рядом.\n\n"+e.Message,"Рядом",MessageBoxButtons.OK,MessageBoxIcon.Error);}}while(chooseAgain);
   }
  }
  private ChatApplication(RolePicker picker) {
   choice=picker;File.WriteAllText(Path.Combine(Data,"desktop-role"),choice.Hosting?"host":"client");if(!choice.Hosting){File.WriteAllText(Path.Combine(Data,"last-target"),choice.Target+":"+choice.TargetPort);WriteLastHost(choice.TargetHostId,choice.TargetFingerprint);}else{try{File.Delete(Path.Combine(Data,"last-target"));}catch{}WriteLastHost("","");}
   File.Delete(Path.Combine(Data,"choose-role"));
   tray=new NotifyIcon{Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath),Text=choice.Hosting?"Рядом · главное устройство":"Рядом · подключён к чату"};
   var menu=new ContextMenuStrip();menu.Items.Add("Открыть чат",null,(s,e)=>OpenChat(false));if(choice.Hosting){menu.Items.Add("Подключить устройство",null,(s,e)=>OpenChat(true));menu.Items.Add("Настроить брандмауэр",null,(s,e)=>FirewallAdvisor.Configure(Data));menu.Items.Add("Проверить брандмауэр и сеть",null,(s,e)=>FirewallAdvisor.ShowReport(Data));}
   menu.Items.Add("Выбрать другое главное устройство",null,(s,e)=>{if(!choice.Hosting||MessageBox.Show("Остановить этот чат и выбрать главное устройство заново? История будет очищена у всех устройств.","Рядом",MessageBoxButtons.OKCancel)==DialogResult.OK)Stop(true);});
   menu.Items.Add(new ToolStripSeparator());menu.Items.Add("Создать ярлык на рабочем столе",null,(s,e)=>CreateShortcut());menu.Items.Add("Как закрепить на панели задач",null,(s,e)=>MessageBox.Show("Создайте ярлык и перетащите его на панель задач, либо закрепите открытое окно Рядом: правый клик по значку на панели задач → «Закрепить на панели задач».","Рядом",MessageBoxButtons.OK,MessageBoxIcon.Information));menu.Items.Add("Папка с данными",null,(s,e)=>Process.Start("explorer.exe",Data));menu.Items.Add("Выключить Рядом",null,(s,e)=>Stop(false));tray.ContextMenuStrip=menu;tray.DoubleClick+=(s,e)=>OpenChat(false);tray.Visible=true;
   string bin=Path.Combine(Data,"bin");Directory.CreateDirectory(bin);string digest;using(var reader=new StreamReader(Assembly.GetExecutingAssembly().GetManifestResourceStream("HostHash")))digest=reader.ReadToEnd().Trim();
   string executable=Path.Combine(bin,"RyadomHost-"+digest.Substring(0,12)+".exe");
   if(!File.Exists(executable)){string temp=executable+".tmp";using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("Host"))using(var output=File.Create(temp))input.CopyTo(output);File.Move(temp,executable);}
   var start=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Data};
   start.EnvironmentVariables["RYADOM_DATA"]=Data;start.EnvironmentVariables["RYADOM_PORT"]="4280";start.EnvironmentVariables["RYADOM_NO_OPEN"]="1";start.EnvironmentVariables["RYADOM_PARENT_PID"]=Process.GetCurrentProcess().Id.ToString();start.EnvironmentVariables["RYADOM_NATIVE_KEY"]=bridgeKey;start.EnvironmentVariables["RYADOM_LAN_STATE"]=Path.Combine(Data,"lan-state.json");start.EnvironmentVariables["RYADOM_ROLE_SIGNAL"]=Path.Combine(Data,"choose-role");start.EnvironmentVariables["RYADOM_DEVICE_ID"]=Device.Id;start.EnvironmentVariables["RYADOM_DEVICE_TOKEN"]=Device.Token;
   if(choice.Hosting){
    string fingerprint;
    hostCert=TlsIdentity.EnsureHostCertificate(Data,out fingerprint);
    start.EnvironmentVariables["RYADOM_TLS"]="1";
    start.EnvironmentVariables["RYADOM_TLS_FINGERPRINT"]=fingerprint;
    start.EnvironmentVariables["RYADOM_BRIDGE_PORT"]="4282";
    RefreshHostNetworks(choice.Networks);
   }
   else {
    var tunnel=new TcpBridge("127.0.0.1",0,c=>{var live=LanInterfaces.Read().FirstOrDefault(n=>n.Contains(choice.Target));if(live==null)throw new IOException("Нет локальной сети");return LanInterfaces.Connect(live,choice.Target,choice.TargetPort);},c=>new byte[0],c=>{},null,false,null,true,choice.Target,choice.Target+":"+choice.TargetPort,message=>{try{File.AppendAllText(Path.Combine(Data,"network.log"),DateTime.Now+" TLS "+message+Environment.NewLine);}catch{}},TlsIdentity.PinFile);bridges.Add(tunnel);
    start.EnvironmentVariables["RYADOM_ROLE"]="client";start.EnvironmentVariables["RYADOM_TARGET"]="http://"+choice.Target+":"+choice.TargetPort;start.EnvironmentVariables["RYADOM_TUNNEL_PORT"]=tunnel.Port.ToString();
   }
   host=Process.Start(start);timer.Interval=400;timer.Tick+=Tick;timer.Start();
  }
  private void RefreshHostNetworks(List<LanInterface> nics) {
   string stamp=string.Join(";",nics.Select(n=>n.Index+":"+n.Address+":"+n.Mask));if(networkStamp==stamp&&File.Exists(Path.Combine(Data,"lan-state.json")))return;
   foreach(var b in bridges)b.Dispose();bridges.Clear();if(discovery!=null){discovery.Dispose();discovery=null;}
   var active=new List<string>();
   foreach(var nic in nics){try{var local=nic;bridges.Add(new TcpBridge(local.Address,4280,c=>new TcpClient("127.0.0.1",4282),c=>Encoding.ASCII.GetBytes("RYADOM/1 "+bridgeKey+" "+((IPEndPoint)c.Client.RemoteEndPoint).Address+" "+local.Address+"\r\n"),c=>{string peer=((IPEndPoint)c.Client.RemoteEndPoint).Address.ToString();if(!LanInterfaces.Private(peer)||!local.Contains(peer))throw new IOException("Другая подсеть");LanInterfaces.BindOutput(c.Client,local.Index);},socket=>LanInterfaces.BindOutput(socket,local.Index),true,hostCert));active.Add(local.Address);}catch(Exception e){File.AppendAllText(Path.Combine(Data,"network.log"),DateTime.Now+" "+nic.Address+" "+e.Message+Environment.NewLine);}}
   File.WriteAllText(Path.Combine(Data,"lan-state.json"),"{\"addresses\":["+string.Join(",",active.Select(a=>"\""+a+"\""))+"],\"mode\":\"physical-interface\"}",new UTF8Encoding(false));
   if(active.Count>0)try{discovery=new LanDiscovery(nics.Where(n=>active.Contains(n.Address)).ToList(),Environment.MachineName,Device.Id,TlsIdentity.Fingerprint(hostCert));}catch{}
   networkStamp=stamp;
  }
  private void Tick(object sender,EventArgs args) {
   if(stopping)return;if(File.Exists(Path.Combine(Data,"choose-role"))){File.Delete(Path.Combine(Data,"choose-role"));Stop(true);return;}
   if(ready){if(host.HasExited){Stop(false);return;}if(choice.Hosting){if(!firewallChecked){firewallChecked=true;FirewallAdvisor.Advise(Data);}try{RefreshHostNetworks(LanInterfaces.Read());}catch{}}return;}
   tries++;try{var request=(HttpWebRequest)WebRequest.Create(BaseUrl+"api/local/status");request.Proxy=null;request.Timeout=300;request.Headers["X-Ryadom"]="1";request.Headers["X-Ryadom-Native"]=bridgeKey;using(var response=request.GetResponse()){}ready=true;timer.Interval=4000;OpenChat(false);}catch{if(tries>=35||host.HasExited){MessageBox.Show("Не удалось запустить Рядом: порт 4280 занят или локальный доступ заблокирован. Повторите выбор главного устройства.","Рядом");Stop(true);}}
  }
  private void OpenChat(bool connect) {
   bool hosting=File.Exists(Path.Combine(Data,"desktop-role"))&&File.ReadAllText(Path.Combine(Data,"desktop-role"))=="host";string url=BaseUrl+(connect?"?connect=1":"");
   if(hosting)try{url+="#t="+RequestHostToken();}catch(Exception e){try{File.AppendAllText(Path.Combine(Data,"network.log"),DateTime.Now+" host-token "+e.Message+Environment.NewLine);}catch{}}
   try{
    if(window==null||window.IsDisposed){window=new ChatWindow(url,e=>{try{if(window!=null){window.CloseForExit();window.Dispose();}}catch{}window=null;OpenBrowser(url);MessageBox.Show("Не удалось запустить WebView2: "+e.Message+"\n\nОткрыт запасной вариант в браузере. Установите Microsoft Edge WebView2 Runtime.","Рядом",MessageBoxButtons.OK,MessageBoxIcon.Warning);},Device.Id,Device.Token);window.Show();}
    else{window.Navigate(url);window.Show();}
   }catch(Exception e){
    OpenBrowser(url);
    MessageBox.Show("Не удалось открыть собственное окно Рядом: "+e.Message+"\n\nОткрыт запасной вариант в браузере. Установите Microsoft Edge WebView2 Runtime для правильной иконки и панели задач.","Рядом",MessageBoxButtons.OK,MessageBoxIcon.Warning);
   }
  }
  private static void OpenBrowser(string url){
   string edge=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),"Microsoft","Edge","Application","msedge.exe"),chrome=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Google","Chrome","Application","chrome.exe");string browser=File.Exists(edge)?edge:File.Exists(chrome)?chrome:null;
   try{if(browser!=null)Process.Start(new ProcessStartInfo(browser,"--user-data-dir=\""+Path.Combine(Data,"browser")+"\" --no-proxy-server --disable-background-networking --no-first-run --app=\""+url+"\" --window-size=1180,820"){UseShellExecute=true});else Process.Start(url);}catch(Exception e){MessageBox.Show(e.Message,"Рядом");}
  }
  private static void CreateShortcut(){
   string exe=Application.ExecutablePath;
   string script="$s=(New-Object -ComObject WScript.Shell).CreateShortcut([IO.Path]::Combine([Environment]::GetFolderPath('Desktop'),'Рядом.lnk'));$s.TargetPath='"+exe.Replace("'","''")+"';$s.WorkingDirectory='"+Path.GetDirectoryName(exe).Replace("'","''")+"';$s.IconLocation='"+exe.Replace("'","''")+",0';$s.Description='Рядом — личный чат';$s.Save()";
   try{Process.Start(new ProcessStartInfo("powershell.exe","-NoProfile -ExecutionPolicy Bypass -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script))){UseShellExecute=false,CreateNoWindow=true});MessageBox.Show("Ярлык «Рядом» создан на рабочем столе. Его можно закрепить на панели задач.","Рядом",MessageBoxButtons.OK,MessageBoxIcon.Information);}catch(Exception e){MessageBox.Show("Не удалось создать ярлык: "+e.Message,"Рядом",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
  }
  private void Stop(bool changeRole) {
   if(stopping)return;stopping=true;chooseAgain=changeRole;timer.Stop();
   try{var req=(HttpWebRequest)WebRequest.Create(BaseUrl+"api/local/quit");req.Proxy=null;req.Timeout=1500;req.Method="POST";req.Headers["X-Ryadom"]="1";req.Headers["X-Ryadom-Native"]=bridgeKey;req.ContentLength=0;using(var response=req.GetResponse()){}if(host!=null&&!host.HasExited&&!host.WaitForExit(2500))host.Kill();}catch{try{if(host!=null&&!host.HasExited)host.Kill();}catch{}}
   foreach(var b in bridges)b.Dispose();bridges.Clear();if(discovery!=null)discovery.Dispose();if(window!=null){try{window.CloseForExit();window.Dispose();}catch{}window=null;}tray.Visible=false;ExitThread();
  }
  protected override void Dispose(bool disposing){if(disposing){if(!stopping)Stop(false);timer.Dispose();tray.Dispose();if(window!=null){try{window.Dispose();}catch{}window=null;}if(host!=null)host.Dispose();}base.Dispose(disposing);}
 }
}
