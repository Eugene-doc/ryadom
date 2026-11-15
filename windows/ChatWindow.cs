using System;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Ryadom {
 // WebView2 is shipped as embedded managed assemblies plus WebView2Loader.dll extracted to a stable
 // per-user folder, so Ryadom-Windows.exe remains a single portable file.
 internal static class WebView2Bootstrap {
  private static bool prepared;
  public static void InstallResolver() {
   AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => {
    string name = new AssemblyName(args.Name).Name;
    string resource = name == "Microsoft.Web.WebView2.Core" ? "WebView2.Core.dll" : name == "Microsoft.Web.WebView2.WinForms" ? "WebView2.WinForms.dll" : null;
    if (resource == null) return null;
    using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)) {
     if (input == null) return null;
     byte[] bytes = new byte[input.Length]; int offset = 0;
     while (offset < bytes.Length) { int read = input.Read(bytes, offset, bytes.Length - offset); if (read <= 0) break; offset += read; }
     return Assembly.Load(bytes);
    }
   };
  }
  public static void Prepare() {
   if (prepared) return;
   string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Ryadom", "webview2");
   Directory.CreateDirectory(folder);
   string loader = Path.Combine(folder, "WebView2Loader.dll");
   if (!File.Exists(loader)) {
    using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream("WebView2Loader.dll")) {
     if (input == null) throw new InvalidOperationException("В сборке нет WebView2Loader.dll");
     string temporary = loader + ".tmp";
     using (FileStream output = File.Create(temporary)) input.CopyTo(output);
     File.Move(temporary, loader);
    }
   }
   CoreWebView2Environment.SetLoaderDllFolderPath(folder);
   prepared = true;
  }
 }
 internal sealed class ChatWindow : Form {
  private WebView2 view;
  private readonly Label version = new Label();
  private readonly string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "Рядом");
  private readonly Action<Exception> failure;
  private string pendingUrl;
  private bool allowClose, failed;
  private volatile bool scriptsReady;
  public ChatWindow(string url) : this(url, null) { }
  public ChatWindow(string url, Action<Exception> onFailure) {
   failure = onFailure;
   WebView2Bootstrap.Prepare();
   try { if (string.IsNullOrEmpty(CoreWebView2Environment.GetAvailableBrowserVersionString())) throw new InvalidOperationException("WebView2 Runtime не установлен"); }
   catch (Exception e) { throw new InvalidOperationException("Для окна Рядом нужен Microsoft Edge WebView2 Runtime. Установите его и повторите запуск.", e); }
   view = new WebView2();
   string profile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Ryadom", "webview2-data");
   Directory.CreateDirectory(profile);
   view.CreationProperties = new CoreWebView2CreationProperties { UserDataFolder = profile };
   pendingUrl = url;
   Text = "Рядом";
   Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
   BackColor = Color.FromArgb(245, 246, 243);
   ClientSize = new Size(1180, 820);
   MinimumSize = new Size(720, 520);
   Panel toolbar = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = Color.FromArgb(241, 243, 239) };
   version.AutoSize = true; version.Text = "Рядом " + VersionText();
   version.Location = new Point(14, 13); version.ForeColor = Color.FromArgb(90, 110, 94);
   Button openDownloads = new Button { Text = "Открыть загрузки", AutoSize = true, Location = new Point(150, 7), FlatStyle = FlatStyle.Flat };
   openDownloads.Click += (s, e) => OpenDownloads();
   toolbar.Controls.Add(version); toolbar.Controls.Add(openDownloads);
   view.Dock = DockStyle.Fill;
   Controls.Add(view); Controls.Add(toolbar);
   Directory.CreateDirectory(downloads);
   Load += (s, e) => Initialize();
   FormClosing += (s, e) => { if (!allowClose) { e.Cancel = true; Hide(); } };
  }
  public void Navigate(string url) {
   pendingUrl = url;
   if (scriptsReady && view.CoreWebView2 != null) view.CoreWebView2.Navigate(url);
   Show(); if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal; Activate();
  }
  public void CloseForExit() { allowClose = true; Close(); }
  private void Initialize() {
   view.CoreWebView2InitializationCompleted += (s, e) => {
    if (!e.IsSuccess) { Fail(e.InitializationException); return; }
    CoreWebView2 core = view.CoreWebView2;
    core.Settings.AreDefaultContextMenusEnabled = false;
    core.Settings.IsStatusBarEnabled = false;
    core.Settings.AreDevToolsEnabled = false;
    core.Settings.IsZoomControlEnabled = true;
    core.WebMessageReceived += (a, b) => { if (b.TryGetWebMessageAsString() == "openDownloads") OpenDownloads(); };
    core.DownloadStarting += (a, b) => {
     string name = Path.GetFileName(b.ResultFilePath);
     if (string.IsNullOrEmpty(name)) name = "file";
     name = name.Replace('/', '_').Replace('\\', '_');
     if (name.Length > 120) name = name.Substring(name.Length - 120);
     string path;
     do { path = Path.Combine(downloads, DateTime.Now.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + "-" + name); } while (File.Exists(path) || File.Exists(path + ".crdownload"));
     b.ResultFilePath = path; b.Handled = true; lastDownload = path;
    };
    core.AddScriptToExecuteOnDocumentCreatedAsync("window.ryadom={appVersion:'" + VersionText().Replace("'", "\\'") + "',openDownloads:function(){window.chrome.webview.postMessage('openDownloads');}};").ContinueWith(task => {
     if (task.IsFaulted) { Fail(task.Exception); return; }
     scriptsReady = true;
     if (string.IsNullOrEmpty(pendingUrl)) return;
     try { BeginInvoke(new Action(() => { if (view.CoreWebView2 != null) view.CoreWebView2.Navigate(pendingUrl); })); } catch { }
    });
   };
   try { view.EnsureCoreWebView2Async(null); }
   catch (Exception e) { Fail(e); }
  }
  private void Fail(Exception e) {
   if (InvokeRequired) { try { BeginInvoke(new Action(() => Fail(e))); } catch { } return; }
   if (failed) return; failed = true;
   try { Hide(); } catch { }
   if (failure != null) { try { failure(e); } catch { } }
   else MessageBox.Show("Не удалось запустить WebView2: " + e.Message, "Рядом", MessageBoxButtons.OK, MessageBoxIcon.Warning);
  }
  private static string VersionText() {
   Version value = Assembly.GetExecutingAssembly().GetName().Version;
   return value.Major + "." + value.Minor + "." + value.Build;
  }
  private string lastDownload;
  private void OpenDownloads() {
   Directory.CreateDirectory(downloads);
   try {
    if (!string.IsNullOrEmpty(lastDownload) && File.Exists(lastDownload)) System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + lastDownload + "\"");
    else System.Diagnostics.Process.Start("explorer.exe", "\"" + downloads + "\"");
   } catch (Exception e) { MessageBox.Show("Не удалось открыть папку загрузок: " + e.Message, "Рядом", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
  }
 }
}
