import logging
import os
import subprocess
import sys

log = logging.getLogger("kvmshare.notify")
_PS = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$n = $t.GetElementsByTagName('text')
$n.Item(0).AppendChild($t.CreateTextNode($env:KVM_T)) | Out-Null
$n.Item(1).AppendChild($t.CreateTextNode($env:KVM_B)) | Out-Null
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('KvmShare').Show([Windows.UI.Notifications.ToastNotification]::new($t))
"""


def notify(title: str, body: str):
    """Toast on Windows (text passed via environment: no script injection); log elsewhere.
    Never called with clipboard contents."""
    log.info("notify: %s - %s", title, body)
    if sys.platform != "win32":
        return
    try:
        env = dict(os.environ, KVM_T=title[:100], KVM_B=body[:300])
        subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", _PS],
                         env=env, creationflags=0x08000000, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass
