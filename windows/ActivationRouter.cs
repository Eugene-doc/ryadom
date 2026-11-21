using System;
using System.Windows.Forms;

namespace Ryadom {
 // Requests may arrive while RolePicker is modal, while the host process is still
 // starting, or while ChatApplication is between role changes. Keep one pending
 // request and deliver it to whichever UI is currently active.
 internal sealed class ActivationRouter {
  private RolePicker picker;
  private ChatApplication application;
  private bool pending;

  internal void SetPicker(RolePicker value) {
   picker = value;
   if (value != null && pending) ActivatePicker();
  }

  internal void ClearPicker(RolePicker value) {
   if (ReferenceEquals(picker, value)) picker = null;
  }

  internal void SetApplication(ChatApplication value) {
   application = value;
   if (value != null && pending && value.RequestOpenChat()) pending = false;
  }

  internal void ClearApplication(ChatApplication value) {
   if (ReferenceEquals(application, value)) application = null;
  }

  internal void Request() {
   pending = true;
   if (application != null && application.RequestOpenChat()) { pending = false; return; }
   if (picker != null) ActivatePicker();
  }

  private void ActivatePicker() {
   if (picker == null || picker.IsDisposed) return;
   picker.Show();
   if (picker.WindowState == FormWindowState.Minimized) picker.WindowState = FormWindowState.Normal;
   picker.Activate();
  }
 }
}
