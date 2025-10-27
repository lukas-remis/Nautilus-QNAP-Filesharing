# Nautilus extension: "Share via QNAP" (GTK3, Nautilus 3.x)
# - File Station v5 API (get_share_link / get_share_list)
# - First-run setup dialog (QNAP URL, Local mount root, NAS root, Link host: Local or myQNAPcloud)
# - Share popup: read-only URL + inline Settings (gear) button to edit config
# - myQNAPcloud: return the exact SmartShare URL from QNAP API (host/link_url) to avoid empty listings
# - NFS path map (configurable): e.g. /media/qnap -> /Public
# - Dialog: expiration (never/3/7/30), link password, uploads for folders
# - "Keep me logged in": securely stores password (python-keyring; falls back to SecretStorage)
#
from __future__ import annotations
import os, json, datetime, base64 as _b64, re as _re, urllib.parse as _up
from urllib.parse import urlparse
from typing import List, Optional, Tuple

try:
    import requests
except Exception:
    requests = None

try:
    import keyring
    HAS_KEYRING = True
except Exception:
    HAS_KEYRING = False

try:
    import secretstorage
    HAS_SECRETSTORAGE = True
except Exception:
    HAS_SECRETSTORAGE = False

import gi
gi.require_version('Nautilus', '3.0')
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Nautilus, GObject, Gtk, Gdk
import xml.etree.ElementTree as ET

CONFIG_DIR  = os.path.join(os.path.expanduser('~'), '.config', 'qnap_share')
CONFIG_PATH = os.path.join(CONFIG_DIR, 'config.json')
DEBUG_PATH  = os.path.join(CONFIG_DIR, 'debug.log')

DEFAULT_CONFIG = {
    "base_url": "https://your-qnap.url",
    "verify_ssl": True,
    "local_mounts": [ { "mount_root": "/media/qnap", "nas_root": "/Public" } ],
    "share": { "expire_days": 0, "password": "" },
    "debug": True,
    "last_username": "",
    "keep_logged_in": False,
    "link_target": "local"  # "local" or "cloud"
}

def ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)

def config_exists() -> bool:
    return os.path.exists(CONFIG_PATH)

def load_config():
    ensure_config_dir()
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        data = {}
    merged = DEFAULT_CONFIG.copy()
    for k, v in data.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            mv = merged[k].copy(); mv.update(v); merged[k] = mv
        else:
            merged[k] = v
    return merged

def save_config(cfg):
    ensure_config_dir()
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)

def log_debug(msg: str):
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        ensure_config_dir()
        with open(DEBUG_PATH, 'a', encoding='utf-8') as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass

def _endpoint_from_base_url(base_url: str) -> str:
    try:
        u = urlparse(base_url)
        host = u.hostname or ""
        port = u.port
        if not host:
            return base_url.rstrip("/")
        return f"{host}:{port}" if port else host
    except Exception:
        return base_url.rstrip("/")

def kr_get(base_url: str, username: str) -> Optional[str]:
    if not (HAS_KEYRING and username):
        return None
    try:
        service = f"qnap_share:{_endpoint_from_base_url(base_url)}"
        return keyring.get_password(service, username)
    except Exception:
        return None

def kr_set(base_url: str, username: str, password: str) -> bool:
    if not (HAS_KEYRING and username):
        return False
    try:
        service = f"qnap_share:{_endpoint_from_base_url(base_url)}"
        keyring.set_password(service, username, password)
        return True
    except Exception:
        return False

def kr_del(base_url: str, username: str) -> bool:
    if not (HAS_KEYRING and username):
        return False
    try:
        service = f"qnap_share:{_endpoint_from_base_url(base_url)}"
        keyring.delete_password(service, username)
        return True
    except Exception:
        return False

def _ss_service():
    if not HAS_SECRETSTORAGE:
        return None
    try:
        bus = secretstorage.dbus_init()
        return secretstorage.SecretService(bus)
    except Exception:
        return None

def _ss_collection():
    ss = _ss_service()
    if not ss:
        return None
    try:
        coll = secretstorage.get_default_collection(ss)
        try:
            if hasattr(coll, "is_locked") and coll.is_locked():
                coll.unlock()
        except Exception:
            pass
        return coll
    except Exception:
        return None

def ss_get(base_url: str, username: str) -> Optional[str]:
    ss = _ss_service()
    if not ss or not username:
        return None
    attrs = {"app": "qnap_share", "endpoint": _endpoint_from_base_url(base_url), "username": username}
    try:
        items = ss.search_items(attrs)
        for it in items:
            return it.get_secret()
    except Exception:
        return None
    return None

def ss_set(base_url: str, username: str, password: str) -> bool:
    coll = _ss_collection()
    if not coll or not username:
        return False
    attrs = {"app": "qnap_share", "endpoint": _endpoint_from_base_url(base_url), "username": username}
    try:
        label = f"QNAP Credentials ({attrs['endpoint']} {username})"
        coll.create_item(label, attrs, password, replace=True)
        return True
    except Exception:
        return False

def ss_del(base_url: str, username: str) -> bool:
    ss = _ss_service()
    if not ss or not username:
        return False
    attrs = {"app": "qnap_share", "endpoint": _endpoint_from_base_url(base_url), "username": username}
    try:
        for it in ss.search_items(attrs):
            it.delete()
        return True
    except Exception:
        return False

def pw_load(base_url: str, username: str) -> Optional[str]:
    return kr_get(base_url, username) or ss_get(base_url, username)

def pw_save(base_url: str, username: str, password: str) -> bool:
    return kr_set(base_url, username, password) or ss_set(base_url, username, password)

def pw_delete(base_url: str, username: str) -> bool:
    ok1 = kr_del(base_url, username)
    ok2 = ss_del(base_url, username)
    return ok1 or ok2

def parse_qnap_sid(xml_text: str) -> Optional[str]:
    try:
        root = ET.fromstring(xml_text)
        sid = root.findtext('authSid')
        if sid: return sid
        qdoc = root.find('QDocRoot')
        if qdoc is not None:
            return qdoc.findtext('authSid')
    except ET.ParseError:
        pass
    return None

def copy_to_clipboard(text: str):
    try:
        cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        cb.set_text(text, -1); cb.store()
    except Exception:
        pass

def map_local_to_nas(local_path: str, cfg) -> Optional[str]:
    if not local_path: return None
    local_path = os.path.abspath(local_path)
    for m in cfg.get('local_mounts', []):
        root = os.path.abspath(m.get('mount_root', '/'))
        nas_root = m.get('nas_root', '/')
        if local_path == root.rstrip('/') or local_path.startswith(root.rstrip('/') + '/'):
            rel = local_path[len(root):]
            if not nas_root.startswith('/'): nas_root = '/' + nas_root
            return (nas_root.rstrip('/') + rel) or '/'
    return None

def _extract_ssid_from_link(link: str) -> Optional[str]:
    try:
        u = _up.urlparse(link or '')
        q = _up.parse_qs(u.query)
        if 'ssid' in q and q['ssid']:
            return q['ssid'][0]
    except Exception:
        pass
    m = _re.search(r"[?&]ssid=([A-Za-z0-9_-]+)", link or '')
    if m: return m.group(1)
    return None

def _local_share_url(base_url: str, link: Optional[str], ssid: Optional[str]) -> str:
    base = (base_url or '').rstrip('/')
    ss = ssid or _extract_ssid_from_link(link or '')
    if ss:
        return f"{base}/share.cgi?ssid={ss}"
    return f"{base}/"

class InitialSetupDialog(Gtk.Dialog):
    def __init__(self, parent):
        Gtk.Dialog.__init__(self, title='Share via QNAP – Setup', parent=parent, flags=0)
        self.set_default_size(500, 340); self.set_border_width(10)
        box = self.get_content_area()
        grid = Gtk.Grid(column_spacing=10, row_spacing=12)
        for fn in (grid.set_margin_left, grid.set_margin_right, grid.set_margin_top, grid.set_margin_bottom): fn(10)

        self.entry_url   = Gtk.Entry(); self.entry_url.set_text(DEFAULT_CONFIG["base_url"]); self.entry_url.set_width_chars(40)
        self.entry_local = Gtk.Entry(); self.entry_local.set_text(DEFAULT_CONFIG["local_mounts"][0]["mount_root"]); self.entry_local.set_width_chars(40)
        self.entry_nas   = Gtk.Entry(); self.entry_nas.set_text(DEFAULT_CONFIG["local_mounts"][0]["nas_root"]); self.entry_nas.set_width_chars(40)

        self.combo_link = Gtk.ComboBoxText()
        self.combo_link.append_text('Use local NAS URL')
        self.combo_link.append_text('Use myQNAPcloud URL')
        self.combo_link.set_active(0)

        def row(y, label, w):
            lbl = Gtk.Label(label=label); lbl.set_xalign(0)
            grid.attach(lbl, 0, y, 1, 1); grid.attach(w, 1, y, 2, 1)

        y = 0
        row(y, 'QNAP URL:', self.entry_url); y += 1
        row(y, 'Local mount point:', self.entry_local); y += 1
        row(y, 'QNAP root:', self.entry_nas); y += 1
        row(y, 'Link host:', self.combo_link); y += 1

        box.pack_start(grid, True, True, 0)
        self.add_button('Cancel', Gtk.ResponseType.CANCEL)
        self.add_button('Save', Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.show_all()

    def preset(self, cfg: dict):
        self.entry_url.set_text((cfg.get('base_url') or '').rstrip('/'))
        lm = (cfg.get('local_mounts') or DEFAULT_CONFIG['local_mounts'])[0]
        self.entry_local.set_text(lm.get('mount_root', '/'))
        self.entry_nas.set_text(lm.get('nas_root', '/'))
        self.combo_link.set_active(1 if (cfg.get('link_target') or 'local') == 'cloud' else 0)

    def get_values(self):
        url = self.entry_url.get_text().strip().rstrip('/')
        mroot = os.path.abspath(self.entry_local.get_text().strip()) or '/'
        nas = self.entry_nas.get_text().strip() or '/'
        if not nas.startswith('/'):
            nas = '/' + nas
        li = self.combo_link.get_active()
        link_target = 'cloud' if li == 1 else 'local'
        return url, mroot, nas, link_target

class LoginDialog(Gtk.Dialog):
    def __init__(self, parent, base_url: str, verify_ssl: bool, debug_default: bool,
                 files: List[Nautilus.FileInfo], last_username: str, stored_pwd: Optional[str],
                 keyring_available: bool, keep_logged_in: bool,
                 settings_callback):
        Gtk.Dialog.__init__(self, title='Share via QNAP – Sign in', parent=parent, flags=0)
        self.set_default_size(500, 480); self.set_border_width(10)
        self.settings_callback = settings_callback
        self.current_base_url = base_url
        box = self.get_content_area()

        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        for fn in (grid.set_margin_left, grid.set_margin_right, grid.set_margin_top, grid.set_margin_bottom): fn(10)

        url_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        url_label_lbl = Gtk.Label(label='QNAP URL:'); url_label_lbl.set_xalign(0)
        self.url_value = Gtk.Label(label=self.current_base_url); self.url_value.set_xalign(0); self.url_value.set_selectable(True)
        settings_btn = Gtk.Button()
        try:
            img = Gtk.Image.new_from_icon_name("emblem-system-symbolic", Gtk.IconSize.BUTTON)
        except Exception:
            img = Gtk.Image.new_from_icon_name("preferences-system", Gtk.IconSize.BUTTON)
        settings_btn.set_tooltip_text("Open settings"); settings_btn.add(img)
        settings_btn.connect('clicked', self.on_settings_clicked)

        url_box.pack_start(url_label_lbl, False, False, 0)
        url_box.pack_start(self.url_value, True, True, 0)
        url_box.pack_end(settings_btn, False, False, 0)

        self.entry_user = Gtk.Entry(); self.entry_user.set_placeholder_text('e.g. admin'); self.entry_user.set_width_chars(40)
        if last_username: self.entry_user.set_text(last_username)
        self.entry_pass = Gtk.Entry(); self.entry_pass.set_visibility(False); self.entry_pass.set_width_chars(40)
        if stored_pwd: self.entry_pass.set_text(stored_pwd)

        self.chk_keep = Gtk.CheckButton(label='Keep me logged in')
        self.chk_keep.set_active(bool(stored_pwd) or bool(keep_logged_in))
        self.chk_keep.set_sensitive(keyring_available)

        sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        sep.set_margin_top(12)     # space above
        sep.set_margin_bottom(12)  # space below

        self.combo_expire = Gtk.ComboBoxText()
        for label in ('Never','3 days','7 days','30 days'): self.combo_expire.append_text(label)
        self.combo_expire.set_active(0)

        self.entry_link_pwd = Gtk.Entry(); self.entry_link_pwd.set_placeholder_text('optional password for the link'); self.entry_link_pwd.set_width_chars(40)

        allow_uploads_enabled = False
        if len(files) == 1:
            try: allow_uploads_enabled = files[0].is_directory()
            except Exception: allow_uploads_enabled = False
        self.chk_uploads = Gtk.CheckButton(label='Allow file uploads (folders only)')
        self.chk_uploads.set_active(False); self.chk_uploads.set_sensitive(allow_uploads_enabled)

        self.chk_verify = Gtk.CheckButton(label='Verify SSL certificate'); self.chk_verify.set_active(verify_ssl)

        y = 0
        grid.attach(url_box, 0, y, 3, 1); y += 1
        def row(label, widget):
            nonlocal y
            lbl = Gtk.Label(label=label); lbl.set_xalign(0)
            grid.attach(lbl, 0, y, 1, 1); grid.attach(widget, 1, y, 2, 1); y += 1
        row('Username:', self.entry_user)
        row('Password:', self.entry_pass)
        grid.attach(self.chk_keep, 1, y, 2, 1); y += 1
        grid.attach(sep, 0, y, 3, 1); y += 1
        row('Link expiration:', self.combo_expire)
        row('Link password:', self.entry_link_pwd)
        grid.attach(self.chk_uploads, 1, y, 2, 1); y += 1
        grid.attach(self.chk_verify, 1, y, 2, 1); y += 1

        box.pack_start(grid, True, True, 0)
        self.add_button('Cancel', Gtk.ResponseType.CANCEL)
        self.add_button('Create link', Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.show_all()

    def on_settings_clicked(self, btn):
        try:
            updated_cfg, stored_pwd_for_user = self.settings_callback()
        except Exception:
            updated_cfg, stored_pwd_for_user = None, None
        if updated_cfg:
            self.current_base_url = (updated_cfg.get('base_url') or '').rstrip('/')
            self.url_value.set_text(self.current_base_url)
            if stored_pwd_for_user and not self.entry_pass.get_text():
                self.entry_pass.set_text(stored_pwd_for_user)

    def get_values(self) -> Tuple[Tuple[str, str, str], dict, bool, bool]:
        expire_map = {0: 0, 1: 3, 2: 7, 3: 30}
        idx = self.combo_expire.get_active()
        days = expire_map.get(idx, 0)
        opts = {
            "expire_days": days,
            "password": self.entry_link_pwd.get_text() or "",
            "allow_uploads": self.chk_uploads.get_active(),
            "keep_logged_in": self.chk_keep.get_active(),
        }
        return (
            self.current_base_url.strip().rstrip('/'),
            self.entry_user.get_text().strip(),
            self.entry_pass.get_text(),
        ), opts, self.chk_verify.get_active(), self.chk_keep.get_active()

def error_dialog(parent, message: str):
    try:
        md = Gtk.MessageDialog(parent=parent, flags=0, type=Gtk.MessageType.ERROR,
                               buttons=Gtk.ButtonsType.OK, message_format='Share via QNAP – Error')
        md.format_secondary_text(message); md.run(); md.destroy()
    except Exception:
        pass

class QnapClient:
    def __init__(self, base_url: str, verify_ssl: bool, debug: bool, link_target: str = "local"):
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.debug = debug
        self.link_target = (link_target or "local").lower()
        self.sid: Optional[str] = None
        self.s = requests.Session() if requests else None
        if self.s:
            self.s.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Nautilus-QNAP-Share/2.8',
                'Accept': '*/*',
                'Referer': self.base_url,
                'Origin': self.base_url,
            })

    def _post(self, path: str, data: dict):
        url = f"{self.base_url}{path}"
        # Sanitize sensitive fields before logging
        try:
            safe = {k: ('xxxxxxxxxx' if k in ('pwd','password','access_code') else v) for k, v in (data or {}).items()}
        except Exception:
            safe = {'_': 'log_sanitizer_failed'}
        log_debug(f"POST {url} data={safe}")
        try:
            r = self.s.post(url, data=data, verify=self.verify_ssl, timeout=20)
            body = r.text[:1000].replace('\n', r'\n')
            log_debug(f" -> {r.status_code} {r.reason} | {body}")
            return r
        except Exception as e:
            log_debug(f" !! request error: {e}")
            return None

    def login(self, username: str, password: str):
        if not self.s:
            raise RuntimeError('python3-requests is required. Install with: sudo apt install python3-requests')
        b64pwd = _b64.b64encode(password.encode('utf-8')).decode('ascii')
        r = self._post('/cgi-bin/authLogin.cgi', {
            'user': username,
            'pwd': b64pwd,
            'serviceKey': '1',
            'service': '1',
        })
        if not r:
            raise RuntimeError('Network error during login.')
        sid = parse_qnap_sid(r.text)
        if not sid:
            raise RuntimeError('Failed to authenticate. No SID returned.')
        self.sid = sid

    def _format_link(self, data: dict, raw_link: Optional[str], ssid: Optional[str]) -> str:
        if self.link_target == 'cloud':
            host = (data.get('host') or '').replace('\\/', '/').strip() if isinstance(data, dict) else ''
            if host:
                return host
            if raw_link and 'myqnapcloud.com' in raw_link:
                return raw_link
            if ssid:
                return f"https://www.myqnapcloud.com/share/{ssid}"
            return raw_link or ''
        return _local_share_url(self.base_url, raw_link, ssid)

    def create_share_link(self, nas_path: str, expire_days: int = 0, access_code: str = '', allow_uploads: bool = False) -> str:
        if not self.sid:
            raise RuntimeError('Not authenticated.')
        nas_path = nas_path.rstrip('/')
        folder, fname = os.path.split(nas_path)
        if not folder: folder = '/'
        option = '2' if allow_uploads else '1'
        payload = {
            'func': 'get_share_link', 'sid': self.sid, 'c': '1',
            'path': folder, 'file_total': '1', 'file_name': fname,
            'option': option, 'ssl': 'true',
        }
        if expire_days and expire_days > 0:
            expire_ts = int((datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)).timestamp())
            payload['expire_time'] = str(expire_ts)
        if access_code:
            payload['access_code'] = access_code

        r = self._post('/cgi-bin/filemanager/utilRequest.cgi', payload)
        if not r:
            raise RuntimeError('Request error creating share link.')
        try:
            data = r.json()
        except Exception:
            raise RuntimeError('Unexpected NAS response when creating share link.')
        if isinstance(data, dict) and str(data.get('status')) in ('1', 'true'):
            links = data.get('links') or data.get('datas') or data.get('data')
            raw = None; ssid = data.get('ssid')
            if isinstance(links, list) and links:
                item = links[0]
                raw = (item.get('link_url') or item.get('download_link') or item.get('share_link') or '').replace('\\/', '/').strip() or None
                ssid = ssid or item.get('ssid') or item.get('share_id')
            return self._format_link(data, raw, ssid)
        return self.get_share_link_from_list(folder, fname)

    def get_share_link_from_list(self, folder: str, fname: str) -> str:
        r = self._post('/cgi-bin/filemanager/utilRequest.cgi', {
            'func': 'get_share_list', 'sid': self.sid,
            'dir': 'ASC', 'limit': '100', 'sort': 'start_time', 'start': '0',
        })
        if not r:
            raise RuntimeError('Failed to query share list.')
        try:
            data = r.json()
        except Exception:
            raise RuntimeError('Unexpected NAS response from get_share_list.')
        for item in (data.get('datas') or data.get('data') or []):
            if not isinstance(item, dict): continue
            if item.get('filename') in (f"{folder}/{fname}", f"{folder.rstrip('/')}/{fname}"):
                raw = (item.get('download_link') or item.get('link_url') or item.get('share_link') or '').replace('\\/', '/').strip() or None
                ssid = item.get('ssid') or item.get('share_id')
                return self._format_link(data, raw, ssid)
        raise RuntimeError('Share link not found in NAS response.')

class QnapShareExtension(GObject.GObject, Nautilus.MenuProvider):
    def __init__(self):
        super().__init__()
        self.config = None

    def _eligible_selection(self, files: List[Nautilus.FileInfo]) -> bool:
        if not files:
            return False
        if self.config is None:
            return True
        for f in files:
            loc = f.get_location()
            if not loc: return False
            path = loc.get_path()
            if not path or map_local_to_nas(path, self.config) is None: return False
        return True

    def get_file_items(self, window: Nautilus.Window, files: List[Nautilus.FileInfo]):
        try:
            if not self._eligible_selection(files):
                return []
        except Exception:
            return []
        item = Nautilus.MenuItem(
            name='QnapShareExtension::ShareViaQnap',
            label='Share via QNAP Link',
            tip='Generate a QNAP File Station share link and copy to clipboard',
        )
        item.connect('activate', self.on_share_activate, window, files)
        return [item]

    def _open_settings_dialog(self, window: Nautilus.Window) -> Optional[dict]:
        cfg = self.config or load_config()
        dlg = InitialSetupDialog(window)
        try:
            dlg.preset(cfg)
        except Exception:
            pass
        resp = dlg.run()
        if resp != Gtk.ResponseType.OK:
            dlg.destroy()
            return None
        base_url, mount_root, nas_root, link_target = dlg.get_values()
        dlg.destroy()
        cfg['base_url'] = base_url
        cfg['local_mounts'] = [ { "mount_root": mount_root, "nas_root": nas_root } ]
        cfg['link_target'] = link_target
        save_config(cfg)
        self.config = cfg
        return cfg

    def _settings_callback_factory(self, window: Nautilus.Window, last_user: str):
        def _cb():
            new_cfg = self._open_settings_dialog(window)
            if not new_cfg:
                return None, None
            stored_pwd = pw_load((new_cfg.get('base_url') or '').rstrip('/'), last_user) if last_user else None
            return new_cfg, stored_pwd
        return _cb

    def _run_first_time_setup(self, window: Nautilus.Window) -> Optional[dict]:
        dlg = InitialSetupDialog(window)
        resp = dlg.run()
        if resp != Gtk.ResponseType.OK:
            dlg.destroy()
            return None
        base_url, mount_root, nas_root, link_target = dlg.get_values()
        dlg.destroy()
        cfg = DEFAULT_CONFIG.copy()
        cfg['base_url'] = base_url
        cfg['local_mounts'] = [ { "mount_root": mount_root, "nas_root": nas_root } ]
        cfg['link_target'] = link_target
        save_config(cfg)
        return cfg

    def on_share_activate(self, menu, window: Nautilus.Window, files: List[Nautilus.FileInfo]):
        if not config_exists():
            cfg = self._run_first_time_setup(window)
            if cfg is None:
                return
            self.config = cfg
        elif self.config is None:
            self.config = load_config()

        cfg = self.config
        base_url = (cfg.get('base_url') or '').rstrip('/')
        verify   = bool(cfg.get('verify_ssl', True))
        link_target = (cfg.get('link_target') or 'local').lower()

        last_user = cfg.get("last_username", "") or ""
        stored_pwd = pw_load(base_url, last_user) if last_user else None

        dlg = LoginDialog(
            parent=window, base_url=base_url, verify_ssl=verify, debug_default=True,
            files=files, last_username=last_user, stored_pwd=stored_pwd,
            keyring_available=(HAS_KEYRING or HAS_SECRETSTORAGE),
            keep_logged_in=bool(cfg.get("keep_logged_in", False)),
            settings_callback=self._settings_callback_factory(window, last_user)
        )
        resp = dlg.run()
        if resp != Gtk.ResponseType.OK:
            dlg.destroy(); return
        (base_url, user, pwd), share_opts, verify, keep = dlg.get_values()
        dlg.destroy()

        cfg = load_config()
        self.config = cfg
        cfg['base_url']       = base_url.rstrip('/')
        cfg['verify_ssl']     = verify
        cfg['share']          = { "expire_days": int(share_opts.get("expire_days", 0)), "password": share_opts.get("password", "") }
        cfg['last_username']  = user
        cfg['keep_logged_in'] = bool(keep)
        save_config(cfg)

        # IMPORTANT: pick up a possibly changed link_target from Settings immediately
        link_target = (self.config.get('link_target') or 'local').lower()

        if user:
            if keep and pwd:
                if not pw_save(cfg['base_url'], user, pwd):
                    error_dialog(window, "Could not store password in GNOME Keyring / Secret Service.")
            elif not keep:
                pw_delete(cfg['base_url'], user)

        try:
            effective_pwd = pwd or pw_load(cfg['base_url'], user) or ""
            client = QnapClient(base_url=cfg['base_url'], verify_ssl=verify, debug=True, link_target=link_target)
            client.login(user, effective_pwd)
        except Exception as e:
            error_dialog(window, f'Login failed: {e}'); return

        links = []
        for f in files:
            loc = f.get_location()
            if not loc:
                continue
            path = loc.get_path()
            nas_path = map_local_to_nas(path, cfg)
            if nas_path is None:
                error_dialog(window, f'Selected path is not under a configured mount: {path}')
                return
            try:
                allow_uploads = share_opts.get("allow_uploads", False) and f.is_directory()
            except Exception:
                allow_uploads = False
            try:
                link = client.create_share_link(
                    nas_path=nas_path,
                    expire_days=int(cfg.get('share', {}).get('expire_days', 0)),
                    access_code=cfg.get('share', {}).get('password', ''),
                    allow_uploads=allow_uploads
                )
                links.append(link)
            except Exception as e:
                error_dialog(window, f'Failed to create link for {os.path.basename(path)}: {e}')
                return

        if not links:
            error_dialog(window, 'No links were generated.'); return

        out = "\n".join(links)
        copy_to_clipboard(out)
        md = Gtk.MessageDialog(parent=window, flags=0, type=Gtk.MessageType.INFO,
                               buttons=Gtk.ButtonsType.OK, message_format='QNAP Share Link')
        md.format_secondary_text(f'Link(s) copied to clipboard:\n{out}')
        md.run(); md.destroy()