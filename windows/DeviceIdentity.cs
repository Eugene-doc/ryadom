using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Ryadom {
 // Stable per-install identity. It is intentionally independent from the role and from IP addresses.
 internal sealed class DeviceIdentity {
  public readonly string Id;
  public readonly string Token;

  private DeviceIdentity(string id, string token) { Id = id; Token = token; }

  public static DeviceIdentity Load(string dataDir) {
   Directory.CreateDirectory(dataDir);
   string id = Read(Path.Combine(dataDir, "device-id"));
   if (!Regex.IsMatch(id, "^d1-[0-9a-f]{32}$")) {
    id = "d1-" + Guid.NewGuid().ToString("N");
    Write(Path.Combine(dataDir, "device-id"), id);
   }
   string token = Read(Path.Combine(dataDir, "device-token"));
   if (!Regex.IsMatch(token, "^[0-9a-f]{64}$")) {
    token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
    Write(Path.Combine(dataDir, "device-token"), token);
   }
   return new DeviceIdentity(id, token);
  }

  private static string Read(string path) {
   try { return File.Exists(path) ? File.ReadAllText(path).Trim().ToLowerInvariant() : ""; } catch { return ""; }
  }

  private static void Write(string path, string value) {
   string temporary = path + ".tmp";
   File.WriteAllText(temporary, value, new UTF8Encoding(false));
   try { File.Move(temporary, path); } catch { try { File.Copy(temporary, path, true); File.Delete(temporary); } catch {} }
  }
 }
}
