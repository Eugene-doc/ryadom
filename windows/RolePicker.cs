using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Ryadom {
 internal sealed class RolePicker : Form {
  public bool Hosting;public string Target="";public int TargetPort=4280;public string TargetHostId="",TargetFingerprint="";public LanInterface Network;
  public List<LanInterface> Networks;
  private readonly TextBox address=new TextBox();private readonly ListBox chats=new ListBox();private readonly Label status=new Label();private readonly Button search=new Button();
  private readonly string previousHostId,previousFingerprint;private FoundChat selected;
  public RolePicker(string previous) : this(previous,"",""){}
  public RolePicker(string previous,string previousHostId,string previousFingerprint) {
   this.previousHostId=previousHostId??"";this.previousFingerprint=previousFingerprint??"";
   Text="Рядом 0.4.2 · выбор главного устройства";ClientSize=new Size(525,550);MinimumSize=new Size(540,580);StartPosition=FormStartPosition.CenterScreen;BackColor=Color.FromArgb(245,248,242);Font=new Font("Segoe UI",10);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;
   var title=new Label{Text="Кто сегодня главный?",Font=new Font("Segoe UI",23),ForeColor=Color.FromArgb(35,76,49),Bounds=new Rectangle(30,25,465,45)};Controls.Add(title);
   Controls.Add(new Label{Text="Создайте чат на этом устройстве или выберите уже запущенный.\nПровод и Wi-Fi подходят: нужен один домашний роутер.",Bounds=new Rectangle(32,80,465,50),ForeColor=Color.FromArgb(100,121,91)});
   var create=new Button{Text="Создать чат на этом компьютере",Bounds=new Rectangle(32,145,460,48),BackColor=Color.FromArgb(23,107,86),ForeColor=Color.White,FlatStyle=FlatStyle.Flat};Controls.Add(create);
   create.Click+=(s,e)=>{try{Networks=LanInterfaces.Read();Hosting=true;DialogResult=DialogResult.OK;}catch(Exception ex){status.Text="Не удалось определить сетевой адаптер: "+ex.Message;}};
   Controls.Add(new Label{Text="ИЛИ ПОДКЛЮЧИТЬСЯ",Bounds=new Rectangle(32,215,310,25),Font=new Font("Segoe UI",9),ForeColor=Color.Gray});
   search.Text="Найти в сети";search.Bounds=new Rectangle(357,207,135,34);Controls.Add(search);search.Click+=async(s,e)=>await Search();
   chats.Bounds=new Rectangle(32,250,460,100);chats.BorderStyle=BorderStyle.FixedSingle;Controls.Add(chats);chats.SelectedIndexChanged+=(s,e)=>{selected=chats.SelectedItem as FoundChat;if(selected!=null){address.Text=selected.Address+":"+selected.Port;TargetHostId=selected.HostId;TargetFingerprint=selected.TlsFingerprint;}};
   address.Bounds=new Rectangle(32,367,305,30);address.Text=previous;Controls.Add(address);var join=new Button{Text="Подключиться",Bounds=new Rectangle(348,364,144,36)};Controls.Add(join);join.Click+=(s,e)=>Join();address.TextChanged+=(s,e)=>{if(selected!=null&&address.Text!=selected.Address+":"+selected.Port){selected=null;TargetHostId="";TargetFingerprint="";}};
   status.Bounds=new Rectangle(32,412,460,65);status.ForeColor=Color.FromArgb(130,102,78);Controls.Add(status);
   if(LanInterfaces.IsLocal(HostOf(previous))){address.Text="";status.Text="Сохранённый адрес относится к этому компьютеру. Выберите другое главное устройство.";}
   Controls.Add(new Label{Text="История принадлежит текущему чату.\nПри завершении главного она очищается у всех устройств.\nHapp может оставаться включённым.",Bounds=new Rectangle(32,478,465,65),ForeColor=Color.Gray,Font=new Font("Segoe UI",9)});
   Shown+=async(s,e)=>await Search();AcceptButton=join;
  }
  private static string HostOf(string value){if(string.IsNullOrWhiteSpace(value))return "";string text=value.Trim();int colon=text.LastIndexOf(':');return colon>0?text.Substring(0,colon):text;}
  private async Task Search(){search.Enabled=false;status.Text="Ищем чаты через Wi-Fi и Ethernet…";try{var found=await Task.Run(()=>{Networks=LanInterfaces.Read();return LanDiscovery.Find(Networks);});if(IsDisposed)return;var visible=found.Where(item=>!LanInterfaces.IsLocal(item.Address)).ToList();chats.Items.Clear();foreach(var item in visible)chats.Items.Add(item);var remembered=!string.IsNullOrEmpty(previousHostId)?visible.FirstOrDefault(item=>item.HostId==previousHostId):null;if(remembered!=null){chats.SelectedItem=remembered;status.Text="Сохранённое главное найдено по идентичности. Проверьте адрес и подключитесь.";}else status.Text=visible.Count>0?"Выберите устройство или введите его адрес вручную.":found.Count>0?"Найден только этот компьютер. Он уже главный — выберите другое устройство или создайте чат здесь.":"Чаты не найдены. Создайте чат на другом устройстве или введите его адрес. Проверьте изоляцию клиентов / гостевую сеть роутера.";}catch(Exception e){if(!IsDisposed)status.Text=e.Message;}finally{if(!IsDisposed)search.Enabled=true;}}
  private void Join(){
   try{
    Uri uri;string input=address.Text.Trim();if(input.StartsWith("https://",StringComparison.OrdinalIgnoreCase))input="http://"+input.Substring(8);else if(!input.StartsWith("http://",StringComparison.OrdinalIgnoreCase))input="http://"+input;
    if(!Uri.TryCreate(input,UriKind.Absolute,out uri)||uri.Scheme!="http"||uri.UserInfo!=""||uri.Query!=""||uri.Fragment!=""||uri.AbsolutePath!="/"||!LanInterfaces.Private(uri.Host))throw new Exception("Введите локальный адрес, например 192.168.1.38:4280.");
    if(LanInterfaces.IsLocal(uri.Host))throw new Exception("Этот компьютер уже является главным устройством. Нельзя подключиться к самому себе: выберите другое устройство или оставьте текущую роль.");
    Networks=LanInterfaces.Read();Network=Networks.FirstOrDefault(n=>n.Contains(uri.Host));if(Network==null)throw new Exception("Адрес не относится к вашей проводной или Wi-Fi подсети. Используйте домашний адрес, не адрес Happ.");
    int port=uri.IsDefaultPort?4280:uri.Port;string fingerprint;bool firstUse;
    try{TlsIdentity.Probe(Network,uri.Host,port,out fingerprint,out firstUse);}
    catch(TlsIdentity.PinMismatchException mismatch){
     var reset=MessageBox.Show(this,mismatch.Message+"\n\nСбросить доверие для "+mismatch.PinKey+"? После этого подключитесь снова и проверьте новый отпечаток.","Сертификат главного изменился",MessageBoxButtons.YesNo,MessageBoxIcon.Warning);
     if(reset==DialogResult.Yes){string error;if(!TlsIdentity.Forget(mismatch.PinKey,TlsIdentity.PinFile,out error))throw new Exception(error);status.Text="Доверие сброшено. Подключитесь снова и проверьте отпечаток сертификата.";}
     return;
    }
    catch(Exception tls){throw new Exception("Нет защищённого соединения с главным устройством: "+tls.Message+". Проверьте входящие TCP 4280 / UDP 42800 на главном, профиль сети «Частная» и правила ESET/Happ.");}
    if(selected!=null&&!string.IsNullOrEmpty(selected.TlsFingerprint)&&!string.Equals(selected.TlsFingerprint,fingerprint,StringComparison.OrdinalIgnoreCase))throw new Exception("Отпечаток найденного главного не совпал с сертификатом. Возможно, адрес занял другой компьютер. Обновите поиск и проверьте отпечаток.");
    if(firstUse){
     string confirm="Впервые подключаетесь к "+uri.Host+":"+port+".\n\nОтпечаток сертификата:\n"+TlsIdentity.FormatFingerprint(fingerprint)+"\n\nСверьте отпечаток на главном устройстве: Настройки → Безопасность. Доверять этому устройству?";
     if(MessageBox.Show(this,confirm,"Проверка сертификата",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes){status.Text="Подключение отменено: сертификат не подтверждён.";return;}
     string error;if(!TlsIdentity.Remember(uri.Host+":"+port,fingerprint,TlsIdentity.PinFile,out error))throw new Exception("Не удалось сохранить доверие: "+error);
    }
    Target=uri.Host;TargetPort=port;Hosting=false;TargetFingerprint=fingerprint;if(selected!=null)TargetHostId=selected.HostId;DialogResult=DialogResult.OK;
   }catch(Exception e){status.Text=e.Message;}
  }
 }
}
