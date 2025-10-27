## **QNAP Share Link Nautilus Extension**


🔗 Generate QNAP File Station share links directly from Ubuntu Nautilus (GNOME Files) — right-click any file/folder stored on your NFS mounted QNAP NAS and instantly get a copy-ready sharing link.

Supports both:

🌐 myQNAPcloud SmartShare links

🏠 Local NAS share links served directly from your QNAP address

Ideal for media teams, remote collaboration, VFX pipelines, or anyone using NFS-mounted QNAP storage.

![Demo](/docs/screenshot.png)
<br>

✨ **Features**

✔ Adds “Share via QNAP Link” to Nautilus right-click menu
✔ Secure authentication with GNOME Keyring
✔ Supports expiration, password protection, and upload-allowed folder shares
✔ Configurable NAS mount + remote folder mapping
✔ Cloud sharing via myQNAPcloud SmartShare
✔ Local sharing via NAS share.cgi (no cloud dependency)
✔ Multi-file selection support
✔ Debug logging 


📦 **Requirements**

Ubuntu 22.04+ (GNOME / Nautilus)

Install dependencies:

sudo apt update
sudo apt install -y \
    python3-nautilus \
    python3-gi \
    python3-requests \
    python3-keyring \
    python3-secretstorage \
    gnome-keyring \
    seahorse


Ensure your keyring unlocks automatically at login.

On QNAP NAS:

Enable File Station

If using cloud links → install & enable CloudLink + myQNAPcloud, publish File Station service

Only QNAP user accounts without 2FA can be used at the moment.

<br><br>

🚀 **Installation**

Place the extension in Nautilus's extension directory:

mkdir -p ~/.local/share/nautilus-python/extensions

cp qnap_share_extension.py ~/.local/share/nautilus-python/extensions/

rm -rf ~/.local/share/nautilus-python/extensions/__pycache__

killall nautilus 2>/dev/null; setsid nautilus >/dev/null 2>&1 & disown


Restart Nautilus (it auto-reloads).

<br><br>

🧩 **First-Time Setup**

On first use, the extension prompts you to configure:

QNAP server URL

Local NFS mount path

NAS root path on QNAP

Default link type:

🏠 Local NAS URL

🌐 myQNAPcloud SmartShare

Then log in with your QNAP credentials — you can enable Keep me logged in to store password securely in GNOME Keyring.

<br><br>

🖱 **Using the Extension**

Right-click any file or folder → Share via QNAP Link

You can customize sharing options:

Expiration	Never / 3 / 7 / 30 days
Link Password	Optional access code
Allow Uploads	Available for folder shares
Verify SSL	Toggle certificate check

Generated link(s) are automatically copied to clipboard ✅

🔧 Configuration File

Stored at:

~/.config/qnap_share/config.json


Contains mount mapping, default settings, and preferences.


📝 Debug Logging

Enabled by default →

~/.config/qnap_share/debug.log

<br><br>

🧱 Tested With
Component	Version
Ubuntu	22.04 LTS
GNOME	42+
Nautilus	42+
QNAP QTS	5.x

NFS-mounted shares required.

