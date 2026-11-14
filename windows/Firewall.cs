using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Windows.Forms;

namespace Ryadom {
 internal sealed class FirewallReport {
  public readonly List<string> ThirdParty=new List<string>();
  public readonly List<string> Problems=new List<string>();
  public bool WindowsEnabled;
  public bool RulesOk;
  public bool PublicNetwork;
  public bool NeedsAttention {get {return ThirdParty.Count>0||(WindowsEnabled&&!RulesOk)||PublicNetwork;}}
  public string Names {get {return string.Join(", ",ThirdParty);}}
  public override string ToString() {
   var text=new StringBuilder();
   text.AppendLine("Сторонний брандмауэр: "+(ThirdParty.Count>0?Names:"не обнаружен"));
   text.AppendLine("Брандмауэр Windows (домашняя сеть): "+(WindowsEnabled?"включён":"выключен"));
   text.AppendLine("Правила Рядом (входящие TCP "+FirewallAdvisor.ChatPort+" / UDP "+FirewallAdvisor.DiscoveryPort+"): "+(RulesOk?"оба корректны":"есть проблемы"));
   foreach(var problem in Problems)text.AppendLine("  · "+problem);
   text.Append("Домашняя сеть: "+(PublicNetwork?"общедоступная (Public) — правила для частных сетей не действуют":"частная"));
   return text.ToString();
  }
 }
 internal static class FirewallAdvisor {
  public const int ChatPort=4280;
  public const int DiscoveryPort=42800;
  private const string RuleTcp="Ryadom chat TCP 4280";
  private const string RuleUdp="Ryadom discovery UDP 42800";
  private static readonly string[] BuiltIn={"windows firewall","windows defender firewall","брандмауэр windows","брандмауэр защитника windows","брандмауэр microsoft defender"};
  // Windows Security Center keeps uninstalled products registered for a long time, so a product with a missing executable is ignored.
  public static FirewallReport Inspect() {
   var report=new FirewallReport();
   try {
    using(var searcher=new ManagementObjectSearcher(@"root\SecurityCenter2","SELECT displayName,pathToSignedProductExe FROM FirewallProduct"))
    using(var rows=searcher.Get())
    foreach(ManagementObject row in rows) {
     string name=(Convert.ToString(row["displayName"])??"").Trim();
     string path=Convert.ToString(row["pathToSignedProductExe"])??"";
     if(name.Length==0||BuiltIn.Any(x=>name.IndexOf(x,StringComparison.OrdinalIgnoreCase)>=0))continue;
     if(path.Length>0&&path.IndexOf("://",StringComparison.Ordinal)<0&&!File.Exists(path))continue;
     if(!report.ThirdParty.Contains(name))report.ThirdParty.Add(name);
    }
   } catch{}
   var profiles=new Dictionary<string,bool>();var categories=new List<uint>();
   try {
    using(var searcher=new ManagementObjectSearcher(@"root\StandardCimv2","SELECT Name,Enabled FROM MSFT_NetFirewallProfile"))
    using(var rows=searcher.Get())
    foreach(ManagementObject row in rows) {
     string profile=Convert.ToString(row["Name"])??"";
     if(profile.Length>0)profiles[profile]=Convert.ToUInt32(row["Enabled"])!=0;
    }
   } catch{}
   try {
    var lan=LanInterfaces.Read().Select(n=>n.Name).ToList();
    using(var searcher=new ManagementObjectSearcher(@"root\StandardCimv2","SELECT InterfaceAlias,NetworkCategory FROM MSFT_NetConnectionProfile"))
    using(var rows=searcher.Get())
    foreach(ManagementObject row in rows) {
     string alias=Convert.ToString(row["InterfaceAlias"])??"";
     if(lan.Contains(alias))categories.Add(Convert.ToUInt32(row["NetworkCategory"]));
    }
   } catch{}
   if(categories.Count>0) {
    report.PublicNetwork=categories.Contains(0);
    report.WindowsEnabled=categories.Any(c=>{string name=c==2?"Domain":c==1?"Private":"Public";bool enabled;return profiles.TryGetValue(name,out enabled)&&enabled;});
   } else report.WindowsEnabled=profiles.Values.Any(x=>x);
   CheckRules(report);
   return report;
  }
  private static void CheckRules(FirewallReport report) {
   report.Problems.Clear();
   string exe=Application.ExecutablePath;
   string output=RunPowerShell(Script(
    "$exe="+Quote(exe)+";"+
    "$names=@("+Quote(RuleTcp)+","+Quote(RuleUdp)+");"+
    "foreach($name in $names){"+
    "$r=Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue|Select-Object -First 1;"+
    "if(-not $r){'MISSING'+[char]9+$name;continue}"+
    "$a=$r|Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue;"+
    "$p=$r|Get-NetFirewallPortFilter -ErrorAction SilentlyContinue;"+
    "$ad=$r|Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue;"+
    "'RULE'+[char]9+$name+[char]9+$r.Enabled+[char]9+$r.Direction+[char]9+$r.Action+[char]9+$r.Profile+[char]9+$a.Program+[char]9+$p.Protocol+[char]9+$p.LocalPort+[char]9+$ad.RemoteAddress"+
    "};"));
   if(output==null) { report.Problems.Add("не удалось прочитать правила брандмауэра"); return; }
   var rules=new Dictionary<string,Dictionary<string,string>>();
   foreach(string line in output.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries)) {
    string[] parts=line.Split('\t');
    if(parts.Length<2)continue;
    if(parts[0]=="MISSING"){report.Problems.Add("правило «"+parts[1]+"» не найдено");continue;}
    if(parts[0]!="RULE"||parts.Length<10)continue;
    var values=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
    values["enabled"]=parts[2];values["direction"]=parts[3];values["action"]=parts[4];values["profile"]=parts[5];values["program"]=parts[6];values["protocol"]=parts[7];values["port"]=parts[8];values["remote"]=parts[9];
    rules[parts[1]]=values;
   }
   bool tcpOk=ValidateRule(rules,RuleTcp,"TCP",ChatPort,exe,report.Problems);
   bool udpOk=ValidateRule(rules,RuleUdp,"UDP",DiscoveryPort,exe,report.Problems);
   report.RulesOk=tcpOk&&udpOk;
   if(report.PublicNetwork&&report.RulesOk)report.Problems.Add("сеть общедоступная: правила для частных сетей сейчас не действуют");
  }
  internal static bool ValidateRule(Dictionary<string,Dictionary<string,string>> rules,string name,string protocol,int port,string exe,List<string> problems) {
   Dictionary<string,string> rule;if(!rules.TryGetValue(name,out rule)){if(!problems.Any(p=>p.Contains(name)))problems.Add("правило «"+name+"» не найдено");return false;}
   bool ok=true;
   if(!string.Equals(rule["enabled"],"True",StringComparison.OrdinalIgnoreCase)){problems.Add(name+": правило выключено");ok=false;}
   if(!string.Equals(rule["direction"],"Inbound",StringComparison.OrdinalIgnoreCase)){problems.Add(name+": направление не Inbound");ok=false;}
   if(!string.Equals(rule["action"],"Allow",StringComparison.OrdinalIgnoreCase)){problems.Add(name+": действие не Allow");ok=false;}
   if(!string.Equals(rule["protocol"],protocol,StringComparison.OrdinalIgnoreCase)){problems.Add(name+": протокол не "+protocol);ok=false;}
   if(!string.Equals(rule["port"].Trim(),port.ToString(),StringComparison.OrdinalIgnoreCase)){problems.Add(name+": порт не "+port);ok=false;}
   if(!string.Equals(rule["program"].Trim(),exe,StringComparison.OrdinalIgnoreCase)){problems.Add(name+": разрешено другое приложение");ok=false;}
   string profile=rule["profile"]??"";
   var profiles=profile.Split(',').Select(x=>x.Trim()).Where(x=>x.Length>0).ToList();
   if(profiles.Count==0||profiles.Any(x=>!string.Equals(x,"Private",StringComparison.OrdinalIgnoreCase)&&!string.Equals(x,"Domain",StringComparison.OrdinalIgnoreCase))){problems.Add(name+": профиль не только частная сеть");ok=false;}
   string remote=rule["remote"]??"";
   var remotes=remote.Split(',').Select(x=>x.Trim()).Where(x=>x.Length>0).ToList();
   if(remotes.Count==0||remotes.Any(x=>!string.Equals(x,"LocalSubnet",StringComparison.OrdinalIgnoreCase))){problems.Add(name+": удалённые адреса не ограничены локальной сетью");ok=false;}
   return ok;
  }
  private static string Quote(string value){return "'"+value.Replace("'","''")+"'";}
  private static string Script(string body){return "$ErrorActionPreference='SilentlyContinue';"+body;}
  private static string RunPowerShell(string script) {
   try {
    var start=new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script))){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
    using(var process=Process.Start(start)) {
     string output=process.StandardOutput.ReadToEnd()+process.StandardError.ReadToEnd();
     if(!process.WaitForExit(20000)){try{process.Kill();}catch{}return null;}
     return process.ExitCode==0?output:null;
    }
   } catch{return null;}
  }
  // Called once per application build. The detailed rules check runs on every start and is always available from the tray.
  public static void Advise(string dataDir) {
   FirewallReport report;
   try{report=Inspect();}catch{return;}
   string exe=Application.ExecutablePath;
   string marker=Path.Combine(dataDir,"firewall-state.json");
   string fingerprint;
   try{fingerprint=exe+"|"+new FileInfo(exe).Length+"|"+File.GetLastWriteTimeUtc(exe).Ticks;}
   catch{return;}
   string seen="";try{if(File.Exists(marker))seen=File.ReadAllText(marker).Trim();}catch{}
   string[] parts=seen.Split('|'); string seenFingerprint=parts.Length>=3?string.Join("|",parts.Take(parts.Length-1)):seen;
   bool alreadyHandled=seenFingerprint==fingerprint;
   try {
    if(report.ThirdParty.Count>0) {
     if(!alreadyHandled) {
      string text="Обнаружен установленный сторонний брандмауэр: "+report.Names+"."+Environment.NewLine+Environment.NewLine+
       "Это не доказывает, что он блокирует Рядом, но если телефон не подключается, проверьте в нём входящие правила для Ryadom-Windows.exe:"+Environment.NewLine+
       "• TCP "+ChatPort+" — чат"+Environment.NewLine+
       "• UDP "+DiscoveryPort+" — поиск в локальной сети"+Environment.NewLine+Environment.NewLine+
       "Правила брандмауэра Windows при этом могут не действовать: входящие фильтрует установленный продукт."+Environment.NewLine+
       "Подробный отчёт: меню значка Рядом → «Проверить брандмауэр и сеть»."+(report.PublicNetwork?Environment.NewLine+Environment.NewLine+"Сеть считается общедоступной — смените профиль на «Частная» в параметрах Windows.":"");
      MessageBox.Show(text,"Рядом · брандмауэр",MessageBoxButtons.OK,MessageBoxIcon.Warning);
      File.WriteAllText(marker,fingerprint+"|thirdparty",new UTF8Encoding(false));
     }
    } else if(report.WindowsEnabled&&!report.RulesOk) {
     if(!alreadyHandled) {
      var answer=MessageBox.Show("Брандмауэр Windows включён, а правила для Рядом отсутствуют или настроены неверно."+Environment.NewLine+Environment.NewLine+
       "Добавить входящие правила TCP "+ChatPort+" и UDP "+DiscoveryPort+" только для частной локальной сети? Потребуется подтверждение администратора."+
       (report.PublicNetwork?Environment.NewLine+Environment.NewLine+"Сеть сейчас «Общедоступная»: правило для частных сетей не начнёт действовать, пока вы не смените профиль сети на «Частная».":""),
       "Рядом · брандмауэр",MessageBoxButtons.YesNo,MessageBoxIcon.Question);
      if(answer==DialogResult.Yes) {
       string installError;
       if(InstallRules(exe,out installError))File.WriteAllText(marker,fingerprint+"|added",new UTF8Encoding(false));
       else { MessageBox.Show("Не удалось настроить правила: "+installError,"Рядом · брандмауэр",MessageBoxButtons.OK,MessageBoxIcon.Warning); }
      } else File.WriteAllText(marker,fingerprint+"|declined",new UTF8Encoding(false));
     }
    } else if(report.PublicNetwork&&!alreadyHandled) {
     MessageBox.Show("Домашняя сеть сейчас считается «Общедоступной». Брандмауэры по умолчанию блокируют в нём входящие подключения, и правило для частных сетей не действует."+Environment.NewLine+Environment.NewLine+
      "Параметры Windows → Сеть и Интернет → Ethernet или Wi-Fi → свойства сети → «Частная», затем перезапустите Рядом.",
      "Рядом · брандмауэр",MessageBoxButtons.OK,MessageBoxIcon.Warning);
     File.WriteAllText(marker,fingerprint+"|public",new UTF8Encoding(false));
    }
   } catch{}
  }
  public static void Configure(string dataDir) {
   FirewallReport report;
   try{report=Inspect();}catch(Exception e){MessageBox.Show("Не удалось проверить брандмауэр: "+e.Message,"Рядом",MessageBoxButtons.OK,MessageBoxIcon.Warning);return;}
   if(report.ThirdParty.Count>0) {
    MessageBox.Show("Входящие подключения может фильтровать сторонний брандмауэр: "+report.Names+"."+Environment.NewLine+Environment.NewLine+
     "Разрешите Ryadom-Windows.exe входящие TCP "+ChatPort+" и UDP "+DiscoveryPort+" из локальной сети в настройках этого продукта. Правила брандмауэра Windows здесь не помогут.",
     "Рядом · брандмауэр",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    return;
   }
   if(!report.WindowsEnabled) {
    MessageBox.Show("Брандмауэр Windows выключен — входящие подключения не фильтруются. Правила не требуются.","Рядом · брандмауэр",MessageBoxButtons.OK,MessageBoxIcon.Information);
    return;
   }
   string extra=report.PublicNetwork?Environment.NewLine+Environment.NewLine+"Сеть сейчас «Общедоступная»: после установки правила смените профиль сети на «Частная», иначе правило не подействует.":"";
   var answer=MessageBox.Show("Добавить входящие правила для Ryadom-Windows.exe?"+Environment.NewLine+"TCP "+ChatPort+" и UDP "+DiscoveryPort+", только частная локальная сеть. Потребуется подтверждение администратора."+extra,"Рядом · брандмауэр",MessageBoxButtons.YesNo,MessageBoxIcon.Question);
   if(answer!=DialogResult.Yes)return;
   string installError2;
   if(InstallRules(Application.ExecutablePath,out installError2)) {
    string marker=Path.Combine(dataDir,"firewall-state.json");
    try{string exe=Application.ExecutablePath;File.WriteAllText(marker,exe+"|"+new FileInfo(exe).Length+"|"+File.GetLastWriteTimeUtc(exe).Ticks+"|added",new UTF8Encoding(false));}catch{}
    MessageBox.Show("Правила добавлены. Если сеть «Общедоступная», смените её профиль на «Частная».","Рядом · брандмауэр",MessageBoxButtons.OK,MessageBoxIcon.Information);
   } else MessageBox.Show("Не удалось добавить правила: "+installError2,"Рядом · брандмауэр",MessageBoxButtons.OK,MessageBoxIcon.Warning);
  }
  public static void ShowReport() {
   FirewallReport report;
   try{report=Inspect();}catch(Exception e){MessageBox.Show("Не удалось проверить брандмауэр: "+e.Message,"Рядом",MessageBoxButtons.OK,MessageBoxIcon.Warning);return;}
   MessageBox.Show(report.ToString()+Environment.NewLine+Environment.NewLine+"Настроить правила можно в меню значка Рядом → «Настроить брандмауэр».","Рядом · брандмауэр и сеть",MessageBoxButtons.OK,report.NeedsAttention?MessageBoxIcon.Warning:MessageBoxIcon.Information);
  }
  // Rules are written by one elevated PowerShell session: temp rules are verified first, then old rules are replaced.
  public static bool InstallRules(string exePath,out string error) {
   error="";
   string script="#create temp rules and verify them before replacing old rules"+Environment.NewLine+
    "$ErrorActionPreference='Stop'"+Environment.NewLine+
    "$exe="+Quote(exePath)+Environment.NewLine+
    "$tcp="+Quote(RuleTcp)+";$udp="+Quote(RuleUdp)+Environment.NewLine+
    "$tmpTcp=$tcp+' (temp)';$tmpUdp=$udp+' (temp)'"+Environment.NewLine+
    "Remove-NetFirewallRule -DisplayName $tmpTcp,$tmpUdp -ErrorAction SilentlyContinue"+Environment.NewLine+
    "New-NetFirewallRule -DisplayName $tmpTcp -Direction Inbound -Action Allow -Program $exe -Protocol TCP -LocalPort "+ChatPort+" -Profile Private,Domain -RemoteAddress LocalSubnet -Enabled True | Out-Null"+Environment.NewLine+
    "New-NetFirewallRule -DisplayName $tmpUdp -Direction Inbound -Action Allow -Program $exe -Protocol UDP -LocalPort "+DiscoveryPort+" -Profile Private,Domain -RemoteAddress LocalSubnet -Enabled True | Out-Null"+Environment.NewLine+
    "function Check($name,$protocol,$port){"+Environment.NewLine+
    "  $r=Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue|Select-Object -First 1;if(-not $r){return $false}"+Environment.NewLine+
    "  $a=$r|Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue;$p=$r|Get-NetFirewallPortFilter -ErrorAction SilentlyContinue"+Environment.NewLine+
    "  return ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow' -and $a.Program -eq $exe -and $p.Protocol -eq $protocol -and \"$($p.LocalPort)\" -eq \"$port\")"+Environment.NewLine+
    "}"+Environment.NewLine+
    "if(-not (Check $tmpTcp 'TCP' "+ChatPort+")){Remove-NetFirewallRule -DisplayName $tmpTcp,$tmpUdp -ErrorAction SilentlyContinue;throw 'Проверка TCP-правила не прошла'}"+Environment.NewLine+
    "if(-not (Check $tmpUdp 'UDP' "+DiscoveryPort+")){Remove-NetFirewallRule -DisplayName $tmpTcp,$tmpUdp -ErrorAction SilentlyContinue;throw 'Проверка UDP-правила не прошла'}"+Environment.NewLine+
    "$backTcp=$tcp+' (backup)';$backUdp=$udp+' (backup)'"+Environment.NewLine+
    "Remove-NetFirewallRule -DisplayName $backTcp,$backUdp -ErrorAction SilentlyContinue"+Environment.NewLine+
    "if(Get-NetFirewallRule -DisplayName $tcp -ErrorAction SilentlyContinue){Set-NetFirewallRule -DisplayName $tcp -NewDisplayName $backTcp}"+Environment.NewLine+
    "if(Get-NetFirewallRule -DisplayName $udp -ErrorAction SilentlyContinue){Set-NetFirewallRule -DisplayName $udp -NewDisplayName $backUdp}"+Environment.NewLine+
    "try{"+Environment.NewLine+
    " Set-NetFirewallRule -DisplayName $tmpTcp -NewDisplayName $tcp"+Environment.NewLine+
    " Set-NetFirewallRule -DisplayName $tmpUdp -NewDisplayName $udp"+Environment.NewLine+
    " if(-not (Check $tcp 'TCP' "+ChatPort+")){throw 'Проверка TCP после установки не прошла'}"+Environment.NewLine+
    " if(-not (Check $udp 'UDP' "+DiscoveryPort+")){throw 'Проверка UDP после установки не прошла'}"+Environment.NewLine+
    " Remove-NetFirewallRule -DisplayName $backTcp,$backUdp -ErrorAction SilentlyContinue"+Environment.NewLine+
    " Write-Output 'OK'"+Environment.NewLine+
    "}catch{"+Environment.NewLine+
    " Remove-NetFirewallRule -DisplayName $tmpTcp,$tmpUdp -ErrorAction SilentlyContinue"+Environment.NewLine+
    " Remove-NetFirewallRule -DisplayName $tcp,$udp -ErrorAction SilentlyContinue"+Environment.NewLine+
    " if(Get-NetFirewallRule -DisplayName $backTcp -ErrorAction SilentlyContinue){Set-NetFirewallRule -DisplayName $backTcp -NewDisplayName $tcp}"+Environment.NewLine+
    " if(Get-NetFirewallRule -DisplayName $backUdp -ErrorAction SilentlyContinue){Set-NetFirewallRule -DisplayName $backUdp -NewDisplayName $udp}"+Environment.NewLine+
    " throw"+Environment.NewLine+
    "}";
   try {
    var start=new ProcessStartInfo("powershell.exe","-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script))){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden};
    int exitCode;
    using(var process=Process.Start(start)){
     if(process==null){error="не удалось запустить настройку";return false;}
     if(!process.WaitForExit(120000)){try{process.Kill();}catch{}error="настройка не завершилась за 2 минуты";return false;}
     exitCode=process.ExitCode;
    }
    if(exitCode!=0){error="настройка отменена или завершилась с кодом "+exitCode;return false;}
   } catch(Exception e){error=e.Message;return false;}
   var report=Inspect();
   if(report.RulesOk)return true;
   error=report.Problems.Count>0?string.Join("; ",report.Problems):"правила не подтверждены";
   return false;
  }
  public static bool RulesAreValid() { try { return Inspect().RulesOk; } catch { return false; } }
 }
}
