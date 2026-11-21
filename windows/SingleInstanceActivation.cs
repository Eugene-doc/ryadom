using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Ryadom {
 // A small per-user pipe is used instead of a bare event: the second process sends
 // its foreground permission to the process that owns the single-instance mutex.
 internal sealed class SingleInstanceActivation : IDisposable {
  private readonly NamedPipeServerStream server;
  private readonly LoopbackActivation loopback;
  private readonly Thread listener;
  private readonly Control dispatcher;
  private readonly Action onActivation;
  private volatile bool stopped;

  [DllImport("user32.dll")]
  private static extern bool AllowSetForegroundWindow(int processId);

  private SingleInstanceActivation(string pipeName, Control dispatcher, Action onActivation) {
   this.dispatcher = dispatcher;
   this.onActivation = onActivation;
   PipeSecurity security = new PipeSecurity();
   security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.FullControl, AccessControlType.Allow));
   server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security);
   loopback = new LoopbackActivation(dispatcher, onActivation);
   listener = new Thread(Listen) { IsBackground = true, Name = "Ryadom activation" };
   listener.Start();
  }

  private static string CurrentSid() {
   WindowsIdentity identity = WindowsIdentity.GetCurrent();
   return identity.User == null ? "user" : identity.User.Value;
  }

  internal static string GetMutexName() {
   return @"Local\Ryadom.PersonalChat." + Process.GetCurrentProcess().SessionId + "." + CurrentSid();
  }

  internal static string GetPipeName() {
   return "Ryadom.PersonalChat.Activate.v1." + Process.GetCurrentProcess().SessionId + "." + CurrentSid();
  }

  internal static SingleInstanceActivation Start(Control dispatcher, Action onActivation) {
   return new SingleInstanceActivation(GetPipeName(), dispatcher, onActivation);
  }

  internal static bool TrySignal(int timeoutMilliseconds) {
   try {
    using (NamedPipeClientStream client = new NamedPipeClientStream(".", GetPipeName(), PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Identification)) {
     client.Connect(1000);
     byte[] pidBytes = ReadExactly(client, 4, 1500);
     int pid = BitConverter.ToInt32(pidBytes, 0);
     AllowSetForegroundWindow(pid);
     client.WriteByte(1);
     client.Flush();
     if (ReadExactly(client, 1, 1500)[0] == 1) return true;
    }
   } catch { }
   return LoopbackActivation.TrySignal(timeoutMilliseconds);
  }

  private void Listen() {
   while (!stopped) {
    try {
     server.WaitForConnection();
     if (stopped) break;
     byte[] pid = BitConverter.GetBytes(Process.GetCurrentProcess().Id);
     server.Write(pid, 0, pid.Length);
     server.Flush();
     int command = ReadByteWithTimeout(server, 3000);
     byte ack = 0;
     if (command == 1) {
      try {
       if (dispatcher != null && dispatcher.IsHandleCreated && !dispatcher.IsDisposed) {
        ManualResetEventSlim completed = new ManualResetEventSlim(false);
        dispatcher.BeginInvoke(new Action(delegate {
         try { onActivation(); } catch { } finally { completed.Set(); }
        }));
        if (completed.Wait(2000)) ack = 1;
       }
      } catch { }
     }
     server.WriteByte(ack);
     server.Flush();
    } catch { if (stopped) break; }
    finally {
     try { if (server.IsConnected) server.Disconnect(); } catch { }
    }
   }
  }

  private static int ReadByteWithTimeout(Stream stream, int timeoutMilliseconds) {
   Task<int> read = Task.Factory.StartNew(delegate { return stream.ReadByte(); });
   if (!read.Wait(timeoutMilliseconds)) throw new TimeoutException();
   return read.Result;
  }

  private static byte[] ReadExactly(Stream stream, int count, int timeoutMilliseconds) {
   Task<byte[]> read = Task.Factory.StartNew(delegate { return ReadExactly(stream, count); });
   if (!read.Wait(timeoutMilliseconds)) throw new TimeoutException();
   return read.Result;
  }

  private static byte[] ReadExactly(Stream stream, int count) {
   byte[] value = new byte[count];
   int offset = 0;
   while (offset < count) {
    int read = stream.Read(value, offset, count - offset);
    if (read <= 0) throw new EndOfStreamException();
    offset += read;
   }
   return value;
  }

  public void Dispose() {
   stopped = true;
   try { server.Dispose(); } catch { }
   try { if (loopback != null) loopback.Dispose(); } catch { }
   try { if (listener != null && listener.IsAlive) listener.Join(500); } catch { }
  }
 }
}
