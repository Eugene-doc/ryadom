using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Ryadom {
 // Loopback IPC is a fallback for a normal-integrity second process when the first
 // instance was started elevated: a high-integrity named pipe is not writable from
 // a normal process, but a loopback socket is not subject to that check.
 internal sealed class LoopbackActivation : IDisposable {
  private static string EndpointFile {
   get {
    WindowsIdentity identity = WindowsIdentity.GetCurrent();
    string sid = identity.User == null ? "user" : identity.User.Value;
    return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Ryadom", "activate-endpoint." + Process.GetCurrentProcess().SessionId + "." + sid + ".txt");
   }
  }
  private readonly TcpListener listener;
  private readonly Thread thread;
  private readonly Control dispatcher;
  private readonly Action onActivation;
  private readonly string secret;
  private volatile bool stopped;

  [DllImport("user32.dll")]
  private static extern bool AllowSetForegroundWindow(int processId);

  internal LoopbackActivation(Control dispatcher, Action onActivation) {
   this.dispatcher = dispatcher;
   this.onActivation = onActivation;
   secret = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
   TcpListener created = null;
   Thread createdThread = null;
   try {
    created = new TcpListener(IPAddress.Loopback, 0);
    created.Start();
    int port = ((IPEndPoint)created.LocalEndpoint).Port;
    Directory.CreateDirectory(Path.GetDirectoryName(EndpointFile));
    File.WriteAllText(EndpointFile, port + Environment.NewLine + secret + Environment.NewLine, new UTF8Encoding(false));
    createdThread = new Thread(Listen) { IsBackground = true, Name = "Ryadom activation loopback" };
    createdThread.Start();
   } catch {
    try { if (created != null) created.Stop(); } catch { }
    created = null; createdThread = null;
   }
   listener = created;
   thread = createdThread;
  }

  internal static bool TrySignal(int timeoutMilliseconds) {
   try {
    string[] lines = File.ReadAllLines(EndpointFile);
    if (lines.Length < 2) return false;
    int port;
    if (!int.TryParse(lines[0], out port) || port < 1 || port > 65535) return false;
    using (TcpClient client = new TcpClient()) {
     client.ReceiveTimeout = timeoutMilliseconds;
     client.SendTimeout = timeoutMilliseconds;
     client.Connect(IPAddress.Loopback, port);
     using (NetworkStream stream = client.GetStream()) {
      stream.ReadTimeout = timeoutMilliseconds;
      stream.WriteTimeout = timeoutMilliseconds;
      using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, false, 1024, true))
      using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false), 1024, true)) {
       writer.AutoFlush = true;
       writer.WriteLine(lines[1]);
       string pidText = reader.ReadLine();
       int pid;
       if (pidText == null || !int.TryParse(pidText, out pid)) return false;
       AllowSetForegroundWindow(pid);
       writer.WriteLine("activate");
       return reader.ReadLine() == "1";
      }
     }
    }
   } catch { return false; }
  }

  private void Listen() {
   while (!stopped) {
    TcpClient client = null;
    try {
     client = listener.AcceptTcpClient();
     client.ReceiveTimeout = 3000;
     client.SendTimeout = 3000;
     using (NetworkStream stream = client.GetStream())
     using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, false, 1024, true))
     using (StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false), 1024, true)) {
      writer.AutoFlush = true;
      string proof = reader.ReadLine();
      if (proof != secret) { writer.WriteLine("0"); continue; }
      writer.WriteLine(Process.GetCurrentProcess().Id.ToString());
      if (reader.ReadLine() != "activate") { writer.WriteLine("0"); continue; }
      bool accepted = false;
      try {
       if (dispatcher != null && dispatcher.IsHandleCreated && !dispatcher.IsDisposed) {
        ManualResetEventSlim completed = new ManualResetEventSlim(false);
        dispatcher.BeginInvoke(new Action(delegate {
         try { onActivation(); accepted = true; } catch { } finally { completed.Set(); }
        }));
        if (completed.Wait(2000)) accepted = true;
       }
      } catch { }
      writer.WriteLine(accepted ? "1" : "0");
     }
    } catch { if (stopped) break; }
    finally { if (client != null) try { client.Close(); } catch { } }
   }
  }

  public void Dispose() {
   stopped = true;
   if (listener != null) try { listener.Stop(); } catch { }
   if (thread != null) try { if (thread.IsAlive) thread.Join(500); } catch { }
   try { File.Delete(EndpointFile); } catch { }
  }
 }
}
