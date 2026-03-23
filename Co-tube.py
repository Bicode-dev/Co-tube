# pylint: disable=line-too-long,too-many-lines
"""YT-DL — Téléchargeur YouTube CO-FLIX + extraction cookies Chrome native (DPAPI/AES)."""

import os
import sys
import shutil
import signal
import sqlite3
import base64
import json as _json
import subprocess
import tempfile
import time
import traceback

try:
    import ctypes
    import ctypes.wintypes
except ImportError:
    ctypes = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    import tty
    import termios
    import select
except ImportError:
    tty = termios = select = None

VERSION = "1.2"

# ─────────────────────────────────────────────────────────────────────────────
# Navigateurs supportés
# ─────────────────────────────────────────────────────────────────────────────
BROWSERS = ["chrome", "firefox", "edge", "brave", "opera", "chromium", "vivaldi", "safari"]

BROWSER_LABELS = {
    "chrome":   "🌐  Google Chrome",
    "firefox":  "🦊  Mozilla Firefox",
    "edge":     "🔷  Microsoft Edge",
    "brave":    "🦁  Brave",
    "opera":    "🎭  Opera",
    "chromium": "🔵  Chromium",
    "vivaldi":  "🎻  Vivaldi",
    "safari":   "🧭  Safari  (macOS uniquement)",
}

# Chemins User Data par navigateur (Windows)
def _build_chrome_paths():
    la = os.environ.get("LOCALAPPDATA", "")
    ap = os.environ.get("APPDATA", "")
    return {
        "chrome":   os.path.join(la, "Google", "Chrome", "User Data"),
        "edge":     os.path.join(la, "Microsoft", "Edge", "User Data"),
        "brave":    os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data"),
        "opera":    os.path.join(ap, "Opera Software", "Opera Stable"),
        "chromium": os.path.join(la, "Chromium", "User Data"),
        "vivaldi":  os.path.join(la, "Vivaldi", "User Data"),
    }

CHROMIUM_BASED = {"chrome", "edge", "brave", "opera", "chromium", "vivaldi"}

# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires généraux
# ─────────────────────────────────────────────────────────────────────────────
def _is_termux():
    return (os.name != "nt" and (
        "ANDROID_STORAGE" in os.environ
        or "com.termux" in os.environ.get("PREFIX", "")
    ))

def _is_android():
    """Détecte Android : Termux ET Pydroid3 (et autres runners Python Android)."""
    if _is_termux():
        return True
    # Pydroid3 / QPython / autres : pas de var Termux mais le stockage Android est présent
    if os.name != "nt" and os.path.isdir("/storage/emulated/0"):
        return True
    return False

def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def _config_path():
    return os.path.join(_base_dir(), "ytdl_config.json")

def _load_config():
    try:
        with open(_config_path(), encoding="utf-8") as f:
            return _json.load(f)
    except Exception:
        return {}

def _save_config(data):
    try:
        existing = _load_config()
        existing.update(data)
        with open(_config_path(), "w", encoding="utf-8") as f:
            _json.dump(existing, f, indent=2)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# Installation automatique des dépendances
# ─────────────────────────────────────────────────────────────────────────────
def _install_if_missing(package, pip_name=None):
    pip_name = pip_name or package
    try:
        __import__(package)
    except ImportError:
        print(f"  \033[36mℹ  \033[0mInstallation de {pip_name}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"  \033[32m✔  \033[0m{pip_name} installé.")

def setup_dependencies():
    _install_if_missing("yt_dlp", "yt-dlp")
    _install_if_missing("imageio_ffmpeg", "imageio-ffmpeg")
    # Cryptographie AES pour les cookies Chrome v80+
    _install_if_missing("Cryptodome", "pycryptodomex")

# ─────────────────────────────────────────────────────────────────────────────
# FFmpeg
# ─────────────────────────────────────────────────────────────────────────────
def setup_ffmpeg():
    exe_name = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"
    found = shutil.which("ffmpeg")
    if found:
        return found
    try:
        import imageio_ffmpeg
        src = imageio_ffmpeg.get_ffmpeg_exe()
        tmp_dir = os.path.join(tempfile.gettempdir(), "ytdl_ffmpeg")
        os.makedirs(tmp_dir, exist_ok=True)
        dst = os.path.join(tmp_dir, exe_name)
        if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(src):
            shutil.copy2(src, dst)
            if os.name != "nt":
                os.chmod(dst, 0o755)
        return dst
    except Exception:
        pass
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  EXTRACTION NATIVE DES COOKIES CHROME
#  ✔ Fonctionne MÊME si Chrome est ouvert (sqlite3 backup API)
#  ✔ Déchiffrement complet : DPAPI + AES-256-GCM (Chrome v80+)
# ═════════════════════════════════════════════════════════════════════════════

def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    """Déchiffre des données avec l'API DPAPI Windows (CryptUnprotectData)."""
    if os.name != "nt" or ctypes is None:
        raise RuntimeError("DPAPI uniquement disponible sur Windows")

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    blob_in  = _BLOB(len(ciphertext),
                     ctypes.cast(ctypes.c_char_p(ciphertext), ctypes.POINTER(ctypes.c_char)))
    blob_out = _BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise RuntimeError("CryptUnprotectData a échoué (DPAPI)")
    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return result


def _get_chrome_aes_key(user_data_dir: str) -> bytes:
    """
    Lit la clé AES-256 depuis Local State et la déchiffre via DPAPI.
    Cette clé est utilisée par Chrome >= 80 pour chiffrer les cookies.
    """
    local_state = os.path.join(user_data_dir, "Local State")
    if not os.path.isfile(local_state):
        raise FileNotFoundError(f"Local State introuvable : {local_state}")

    with open(local_state, encoding="utf-8") as f:
        state = _json.load(f)

    enc_key_b64 = state["os_crypt"]["encrypted_key"]
    enc_key     = base64.b64decode(enc_key_b64)[5:]   # strip b"DPAPI" prefix (5 bytes)
    return _dpapi_decrypt(enc_key)


def _decrypt_cookie_value(enc_value: bytes, aes_key: bytes) -> str:
    """
    Déchiffre une valeur de cookie Chrome :
      - Préfixe b'v10' / b'v20' → AES-256-GCM (Chrome >= 80)
      - Autres                  → DPAPI legacy
    """
    if not enc_value:
        return ""

    prefix = enc_value[:3]
    if prefix in (b"v10", b"v20"):
        try:
            from Cryptodome.Cipher import AES
            nonce      = enc_value[3:15]          # 12 octets
            ciphertext = enc_value[15:-16]
            tag        = enc_value[-16:]
            cipher     = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8", errors="replace")
        except Exception:
            return ""

    # Ancien format (Chrome < 80) : DPAPI brut
    try:
        return _dpapi_decrypt(enc_value).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _chrome_ts_to_unix(ts: int) -> int:
    """Convertit un timestamp Chrome (µs depuis 1601-01-01) en secondes Unix."""
    if not ts:
        return 0
    return max(0, ts // 1_000_000 - 11_644_473_600)


def _sqlite_copy_safe(src_path: str) -> str:
    """
    Copie la base SQLite vers un dossier temporaire.
    Si Chrome est ouvert et verrouille le fichier, utilise
    la sqlite3 Backup API avec le mode 'immutable=1' (lecture seule
    sans verrou exclusif).
    Retourne le chemin de la copie.
    """
    tmp_dir  = tempfile.mkdtemp(prefix="cotube_ck_")
    dst_path = os.path.join(tmp_dir, "Cookies")

    # Tentative de copie classique (Chrome fermé)
    try:
        shutil.copy2(src_path, dst_path)
        for ext in ("-wal", "-shm", "-journal"):
            s = src_path + ext
            if os.path.exists(s):
                shutil.copy2(s, dst_path + ext)
        return dst_path
    except (PermissionError, OSError):
        pass  # Chrome ouvert → verrou → on utilise l'API backup

    # Backup API (lit les pages sqlite directement, contourne le verrou)
    try:
        src_uri = f"file:{src_path}?immutable=1"
        con_src = sqlite3.connect(src_uri, uri=True)
        con_dst = sqlite3.connect(dst_path)
        con_src.backup(con_dst)
        con_src.close()
        con_dst.close()
        return dst_path
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(
            f"Impossible de lire la base cookies (Chrome ouvert ?) : {e}"
        ) from e


def extract_chrome_cookies_to_txt(
    browser: str = "chrome",
    domains: tuple = (".youtube.com", ".google.com"),
    profile_subdir: str = "Default",
) -> str:
    """
    Extrait les cookies YouTube du navigateur Chromium vers un cookies.txt Netscape.

    Fonctionne MÊME si Chrome est ouvert grâce à sqlite3 backup API.
    Déchiffrement complet : DPAPI (clé master) + AES-256-GCM (valeurs).

    Retourne le chemin du fichier temporaire cookies.txt.
    """
    # ── Localiser le dossier User Data ───────────────────────────────────────
    if os.name == "nt":
        user_data_dir = _build_chrome_paths().get(browser, "")
    elif sys.platform == "darwin":
        home = os.path.expanduser("~")
        _mac = {
            "chrome":   os.path.join(home, "Library", "Application Support", "Google", "Chrome"),
            "chromium": os.path.join(home, "Library", "Application Support", "Chromium"),
            "brave":    os.path.join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
            "edge":     os.path.join(home, "Library", "Application Support", "Microsoft Edge"),
            "vivaldi":  os.path.join(home, "Library", "Application Support", "Vivaldi"),
        }
        user_data_dir = _mac.get(browser, "")
    else:
        home = os.path.expanduser("~")
        _lin = {
            "chrome":   os.path.join(home, ".config", "google-chrome"),
            "chromium": os.path.join(home, ".config", "chromium"),
            "brave":    os.path.join(home, ".config", "BraveSoftware", "Brave-Browser"),
            "edge":     os.path.join(home, ".config", "microsoft-edge"),
            "vivaldi":  os.path.join(home, ".config", "vivaldi"),
        }
        user_data_dir = _lin.get(browser, "")

    if not user_data_dir or not os.path.isdir(user_data_dir):
        raise RuntimeError(
            f"{BROWSER_LABELS.get(browser, browser)} introuvable.\n"
            f"  Chemin attendu : {user_data_dir or '(inconnu)'}\n"
            f"  Assurez-vous que {BROWSER_LABELS.get(browser, browser)} est installé."
        )

    profile_dir  = os.path.join(user_data_dir, profile_subdir)
    cookies_path = os.path.join(profile_dir, "Cookies")

    if not os.path.isfile(cookies_path):
        raise RuntimeError(
            f"Base de cookies introuvable : {cookies_path}\n"
            f"  Assurez-vous d'avoir lancé {BROWSER_LABELS.get(browser, browser)} au moins une fois."
        )

    # ── Clé AES (Windows uniquement) ────────────────────────────────────────
    aes_key = None
    if os.name == "nt":
        aes_key = _get_chrome_aes_key(user_data_dir)

    # ── Copie sécurisée de la DB ─────────────────────────────────────────────
    tmp_cookies = _sqlite_copy_safe(cookies_path)
    tmp_parent  = os.path.dirname(tmp_cookies)

    try:
        con = sqlite3.connect(tmp_cookies)
        cur = con.cursor()

        # Détecter les colonnes disponibles
        cur.execute("SELECT name FROM pragma_table_info('cookies')")
        cols = {r[0] for r in cur.fetchall()}

        has_plaintext = "value" in cols
        enc_col       = "encrypted_value" if "encrypted_value" in cols else "value"

        domain_placeholders = " OR ".join(["host_key LIKE ?" for _ in domains])
        like_args           = [f"%{d.lstrip('.')}" for d in domains]

        select_cols = f"host_key, name, path, expires_utc, is_secure, {'value, ' if has_plaintext else ''}{enc_col}"
        cur.execute(f"SELECT {select_cols} FROM cookies WHERE {domain_placeholders}", like_args)
        rows = cur.fetchall()
        con.close()
    finally:
        shutil.rmtree(tmp_parent, ignore_errors=True)

    if not rows:
        raise RuntimeError(
            "Aucun cookie YouTube trouvé dans " + BROWSER_LABELS.get(browser, browser) + ".\n"
            "  Connectez-vous à YouTube dans ce navigateur, puis réessayez."
        )

    # ── Écriture Netscape cookies.txt ────────────────────────────────────────
    out = os.path.join(tempfile.gettempdir(), f"cotube_yt_{int(time.time())}.txt")

    written = 0
    with open(out, "w", encoding="utf-8") as f:
        f.write("# Netscape HTTP Cookie File\n")
        f.write("# Extrait automatiquement par CO-TUBE\n\n")

        for row in rows:
            if has_plaintext:
                host_key, name, path, exp_ts, is_secure, plain_val, enc_val = row
                value = plain_val if plain_val else (
                    _decrypt_cookie_value(enc_val or b"", aes_key) if aes_key else "")
            else:
                host_key, name, path, exp_ts, is_secure, enc_val = row
                value = _decrypt_cookie_value(enc_val or b"", aes_key) if aes_key else ""

            if not value:
                continue

            exp_unix      = _chrome_ts_to_unix(exp_ts or 0)
            include_subdom = "TRUE" if host_key.startswith(".") else "FALSE"
            secure_str     = "TRUE" if is_secure else "FALSE"

            f.write(f"{host_key}\t{include_subdom}\t{path}\t"
                    f"{secure_str}\t{exp_unix}\t{name}\t{value}\n")
            written += 1

    if written == 0:
        os.unlink(out)
        raise RuntimeError(
            "Cookies trouvés mais tous vides après déchiffrement.\n"
            "  La clé DPAPI a peut-être changé. Reconnectez-vous à YouTube."
        )

    return out


# ─────────────────────────────────────────────────────────────────────────────
# ConsoleUI
# ─────────────────────────────────────────────────────────────────────────────
class ConsoleUI:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RED    = '\033[31m'
    GREEN  = '\033[32m'
    YELLOW = '\033[33m'
    CYAN   = '\033[36m'

    BANNER = '\033[36m' + r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██████╗       ████████╗██╗   ██╗██████╗ ███████╗   ║
║  ██╔════╝██╔═══██╗         ██╔══╝██║   ██║██╔══██╗██╔════╝   ║
║  ██║     ██║   ██║█████╗   ██║   ██║   ██║██████╔╝█████╗     ║
║  ██║     ██║   ██║╚════╝   ██║   ██║   ██║██╔══██╗██╔══╝     ║
║  ╚██████╗╚██████╔╝         ██║   ╚██████╔╝██████╔╝███████╗   ║
║   ╚═════╝ ╚═════╝          ╚═╝    ╚═════╝ ╚═════╝ ╚══════╝   ║
║                                                              ║
║            🎬  CO-TUBE  DOWNLOADER  v1.2  🎬                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝""" + '\033[0m'

    MAX_VISIBLE = 8

    @staticmethod
    def enable_ansi():
        if os.name == "nt" and ctypes:
            try:
                ctypes.windll.kernel32.SetConsoleMode(
                    ctypes.windll.kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass

    @staticmethod
    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def display_len(s):
        count = 0
        for ch in s:
            cp = ord(ch)
            if cp in (0xFE0E, 0xFE0F, 0x200D, 0x20E3): continue
            if 0x0300 <= cp <= 0x036F: continue
            wide = (0x1F000 <= cp <= 0x1FFFF or 0x2600 <= cp <= 0x27BF
                    or 0x2B00 <= cp <= 0x2BFF or 0xFE30 <= cp <= 0xFE4F
                    or 0x2E80 <= cp <= 0x2EFF or 0x3000 <= cp <= 0x9FFF
                    or 0xF900 <= cp <= 0xFAFF or 0xAC00 <= cp <= 0xD7AF)
            count += 2 if wide else 1
        return count

    @staticmethod
    def show_menu(options, title="MENU", selected_index=0, subtitle=""):
        box_w = 62
        ConsoleUI.clear()
        print(ConsoleUI.BANNER)
        if subtitle:
            print(f"\n  {ConsoleUI.DIM}{subtitle}{ConsoleUI.RESET}")
        else:
            print()

        visible = min(len(options), ConsoleUI.MAX_VISIBLE)
        half    = visible // 2
        top     = max(0, min(selected_index - half, len(options) - visible))
        h_line  = "═" * box_w
        tl = ConsoleUI.display_len(title)
        tpl = max(0, (box_w - tl) // 2)
        tpr = max(0, box_w - tl - tpl)

        print(f"  ╔{h_line}╗")
        print(f"  ║{' '*tpl}{ConsoleUI.BOLD}{ConsoleUI.CYAN}{title}{ConsoleUI.RESET}{' '*tpr}║")
        print(f"  ╠{h_line}╣")

        if top > 0:
            aw = f"▲  {top} élément(s) plus haut"
            print(f"  ║  {ConsoleUI.CYAN}{aw}{ConsoleUI.RESET}{' '*(box_w-2-ConsoleUI.display_len(aw))}║")
        else:
            print(f"  ║{' '*box_w}║")

        inner = box_w - 4
        max_t = inner - 3
        for i in range(top, top + visible):
            raw = options[i]
            if ConsoleUI.display_len(raw) > max_t:
                acc, w = [], 0
                for ch in raw:
                    cw = 2 if ConsoleUI.display_len(ch) == 2 else 1
                    if w + cw > max_t - 1: break
                    acc.append(ch); w += cw
                raw = "".join(acc) + "…"
            prefix = "▶  " if i == selected_index else "   "
            vt = prefix + raw
            pr = " " * max(0, inner - ConsoleUI.display_len(vt))
            if i == selected_index:
                print(f"  ║  {ConsoleUI.CYAN}{ConsoleUI.BOLD}{vt}{ConsoleUI.RESET}{pr}  ║")
            else:
                print(f"  ║  {vt}{pr}  ║")

        remaining = len(options) - top - visible
        if remaining > 0:
            aw = f"▼  {remaining} élément(s) plus bas"
            print(f"  ║  {ConsoleUI.CYAN}{aw}{ConsoleUI.RESET}{' '*(box_w-2-ConsoleUI.display_len(aw))}║")
        else:
            print(f"  ║{' '*box_w}║")

        print(f"  ╠{h_line}╣")
        nav = "↑ ↓  Naviguer   ↵  Valider   Échap  Retour"
        print(f"  ║  {ConsoleUI.YELLOW}{nav}{ConsoleUI.RESET}{' '*(box_w-2-ConsoleUI.display_len(nav))}║")
        print(f"  ╚{h_line}╝")

    @staticmethod
    def show_menu_termux(options, title="MENU", subtitle=""):
        ConsoleUI.clear()
        print(f"{ConsoleUI.CYAN}\n  {'═'*54}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.BOLD}{ConsoleUI.CYAN}🎬  CO-TUBE  —  {title}{ConsoleUI.RESET}")
        if subtitle: print(f"  {ConsoleUI.DIM}{subtitle}{ConsoleUI.RESET}")
        print(f"{ConsoleUI.CYAN}  {'═'*54}{ConsoleUI.RESET}\n")
        for i, opt in enumerate(options, 1):
            print(f"  {ConsoleUI.CYAN}{ConsoleUI.BOLD}[{i}]{ConsoleUI.RESET}  {opt}")
        print(f"  {ConsoleUI.CYAN}{ConsoleUI.BOLD}[0]{ConsoleUI.RESET}  {ConsoleUI.DIM}Retour{ConsoleUI.RESET}")
        print(f"\n{ConsoleUI.CYAN}  {'─'*54}{ConsoleUI.RESET}")

    @staticmethod
    def get_key():
        if os.name == "nt":
            if msvcrt.kbhit():
                key = msvcrt.getch()
                if key == b'\xe0':
                    key = msvcrt.getch()
                    if key == b'H': return 'UP'
                    if key == b'P': return 'DOWN'
                elif key == b'\r':   return 'ENTER'
                elif key == b'\x1b': return 'ESC'
        else:
            fd = sys.stdin.fileno()
            try:
                old = termios.tcgetattr(fd)
            except Exception:
                return None
            try:
                tty.setraw(fd)
                if select.select([sys.stdin], [], [], 0.05)[0]:
                    ch = sys.stdin.read(1)
                    if ch == '\x1b':
                        if select.select([sys.stdin], [], [], 0.05)[0]:
                            more = sys.stdin.read(2)
                            if more == '[A': return 'UP'
                            if more == '[B': return 'DOWN'
                        return 'ESC'
                    if ch in ('\r', '\n'): return 'ENTER'
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        return None

    @staticmethod
    def flush_keys():
        if os.name == "nt":
            while msvcrt.kbhit(): msvcrt.getch()
        else:
            try: termios.tcflush(sys.stdin, termios.TCIFLUSH)
            except Exception: pass

    @staticmethod
    def navigate(options, title="MENU", subtitle=""):
        if not options: return -1
        if _is_termux():
            while True:
                ConsoleUI.show_menu_termux(options, title, subtitle)
                try:
                    raw = input(f"  {ConsoleUI.YELLOW}▶  {ConsoleUI.RESET}Choix : ").strip()
                except (EOFError, OSError):
                    return -1
                if raw in ("0", ""): return -1
                if raw.isdigit():
                    idx = int(raw) - 1
                    if 0 <= idx < len(options): return idx
                ConsoleUI.warn(f"Choix invalide — entrez un nombre entre 1 et {len(options)}")
                time.sleep(0.8)
        else:
            selected = 0
            while True:
                ConsoleUI.show_menu(options, title, selected, subtitle)
                while True:
                    key = ConsoleUI.get_key()
                    if key: break
                    time.sleep(0.03)
                if key == 'UP':    selected = (selected - 1) % len(options)
                elif key == 'DOWN': selected = (selected + 1) % len(options)
                elif key == 'ENTER': return selected
                elif key == 'ESC':   return -1

    @staticmethod
    def input_screen(title, prompt_text, subtitle=""):
        ConsoleUI.clear()
        print(ConsoleUI.BANNER)
        print(f"\n  {ConsoleUI.CYAN}{ConsoleUI.BOLD}{'─'*58}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.BOLD}{title}{ConsoleUI.RESET}")
        if subtitle: print(f"  {ConsoleUI.DIM}{subtitle}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}\n")
        try:
            return input(f"  {ConsoleUI.YELLOW}▶  {ConsoleUI.RESET}{prompt_text} : ").strip()
        except (EOFError, OSError):
            return ""

    @staticmethod
    def result_screen(lines, pause=True):
        ConsoleUI.clear()
        print(ConsoleUI.CYAN + "\n  " + "═"*58 + ConsoleUI.RESET)
        for line in lines: print(line)
        print(ConsoleUI.CYAN + "\n  " + "═"*58 + ConsoleUI.RESET)
        if pause:
            try: input(f"\n  {ConsoleUI.DIM}Appuyez sur Entrée pour continuer...{ConsoleUI.RESET}")
            except (EOFError, OSError): pass

    @staticmethod
    def info(m):    print(f"  {ConsoleUI.CYAN}ℹ  {ConsoleUI.RESET}{m}")
    @staticmethod
    def success(m): print(f"  {ConsoleUI.GREEN}✔  {ConsoleUI.RESET}{m}")
    @staticmethod
    def warn(m):    print(f"  {ConsoleUI.YELLOW}⚠  {ConsoleUI.RESET}{m}")
    @staticmethod
    def sep():      print(f"\n  {ConsoleUI.DIM}{'─'*54}{ConsoleUI.RESET}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Cookies — helpers config
# ─────────────────────────────────────────────────────────────────────────────
def _cookie_summary(cfg):
    method  = cfg.get("cookie_method", "browser")
    browser = cfg.get("cookie_browser", "")
    cfile   = cfg.get("cookie_file", "")

    if method == "file" and cfile and os.path.isfile(cfile):
        return f"📄  Fichier : {os.path.basename(cfile)}"
    if browser:
        label = BROWSER_LABELS.get(browser, browser)
        return f"🍪  {label}"
    return f"\033[2mAucun cookie\033[0m"


def _apply_cookies(ydl_opts: dict, cfg: dict, verbose: bool = False) -> str | None:
    """
    Injecte les paramètres cookies dans ydl_opts.
    - Navigateurs Chromium : extraction native SQLite+DPAPI → cookiefile
    - Firefox/Safari       : cookiesfrombrowser (yt-dlp natif)
    - Fichier              : cookiefile direct
    Retourne une description de la source, ou None si désactivé.
    """
    method  = cfg.get("cookie_method", "browser")
    browser = cfg.get("cookie_browser", "")
    cfile   = cfg.get("cookie_file", "")

    if method == "file" and cfile and os.path.isfile(cfile):
        ydl_opts["cookiefile"] = cfile
        return "fichier"

    if browser:
        if browser in CHROMIUM_BASED:
            if verbose:
                ConsoleUI.info(f"Extraction cookies {BROWSER_LABELS.get(browser, browser)}...")
            try:
                cookie_txt = extract_chrome_cookies_to_txt(browser=browser)
                ydl_opts["cookiefile"] = cookie_txt
                if verbose:
                    ConsoleUI.success("Cookies extraits avec succès (Chrome peut rester ouvert).")
                return browser
            except Exception as e:
                if verbose:
                    ConsoleUI.warn(f"Extraction native échouée : {e}")
                    ConsoleUI.warn("Tentative de lecture directe par yt-dlp (nécessite Chrome fermé)...")
                ydl_opts["cookiesfrombrowser"] = (browser, None, None, None)
                return f"{browser}-fallback"
        else:
            # Firefox, Safari : yt-dlp gère nativement
            ydl_opts["cookiesfrombrowser"] = (browser, None, None, None)
            return browser

    return None




# ─────────────────────────────────────────────────────────────────────────────
# Téléchargement
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Rendu de progression du téléchargement
# ─────────────────────────────────────────────────────────────────────────────
class _DownloadRenderer:  # pylint: disable=too-many-instance-attributes
    """Affiche la progression sur 4 lignes fixes (ANSI \033[A\r).

    Ligne 1 : TOTAL  — pourcentage global + ETA globale
    Ligne 2 : Séparateur
    Ligne 3 : Étape courante (subs / vidéo / merge) + ETA
    Ligne 4 : Barre de progression de l'étape courante

    Le rendu est basé sur des appels \r + \033[A pour remonter de ligne
    sans faire défiler le terminal.
    """

    _CYAN   = "\033[36m"
    _GREEN  = "\033[32m"
    _YELLOW = "\033[33m"
    _BOLD   = "\033[1m"
    _DIM    = "\033[2m"
    _RESET  = "\033[0m"
    _UP     = "\033[A"   # remonter d'une ligne

    _BAR_W  = 30         # largeur de la barre de progression

    def __init__(self, n_subs: int, titre: str,
                 want_subs: bool = False, audio_mode: bool = False) -> None:
        self._n_subs         = n_subs
        self._want_subs      = want_subs
        self._audio_mode     = audio_mode    # True = MP3 (pas de merge vidéo)
        self._titre          = titre[:50]
        self._total_pct      = 0.0          # % total (0-100)
        self._total_eta      = ""
        self._step_label     = ""           # "Sous-titres", "Vidéo", "Merge"
        self._step_pct       = 0.0
        self._step_eta       = ""
        self._step_spd       = ""           # vitesse courante (vidéo uniquement)
        self._sub_done       = 0            # nombre de subs téléchargés
        self._printed        = False        # True après le premier rendu
        self._phase          = "init"       # "subs" | "video" | "merge"
        self._video_bytes    = 0            # octets vidéo téléchargés
        self._merge_start    = 0.0          # timestamp début merge
        self._merge_thread   = None         # thread animation merge
        self._video_total    = 0            # octets vidéo totaux

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _bar(pct: float, width: int = 30) -> str:
        """Génère une barre de progression ASCII."""
        filled = int(width * min(pct, 100) / 100)
        return "█" * filled + "░" * (width - filled)

    @staticmethod
    def _fmt_eta(seconds) -> str:
        """Formate un nombre de secondes en mm:ss ou hh:mm:ss."""
        try:
            secs = int(float(seconds))
        except (TypeError, ValueError):
            return "--:--"
        if secs <= 0:
            return "--:--"
        h, rem = divmod(secs, 3600)
        m, s   = divmod(rem, 60)
        if h:
            return f"{h}h{m:02d}m{s:02d}s"
        return f"{m:02d}m{s:02d}s"

    @staticmethod
    def _fmt_speed(speed) -> str:
        """Formate une vitesse en Ko/s ou Mo/s."""
        try:
            bps = float(speed)
        except (TypeError, ValueError):
            return ""
        if bps >= 1_000_000:
            return f"{bps/1_000_000:.1f} Mo/s"
        return f"{bps/1_000:.0f} Ko/s"

    # ── Mise à jour depuis le hook yt-dlp ────────────────────────────────────

    def on_progress(self, d: dict) -> None:  # pylint: disable=too-many-branches
        """Appelé à chaque tick de yt-dlp (progress_hook)."""
        status   = d.get("status", "")
        filename = d.get("filename", "")

        is_sub = (
            filename.endswith((".vtt", ".srt", ".ttml", ".srv1", ".srv2", ".srv3"))
            or d.get("info_dict", {}).get("_type") == "subtitle"
        )

        if status == "downloading":
            downloaded = d.get("downloaded_bytes") or 0
            total      = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
            pct        = (downloaded / total * 100) if total > 0 else 0
            eta_raw    = d.get("eta")
            speed      = d.get("speed")
            eta_str    = self._fmt_eta(eta_raw)
            spd_str    = self._fmt_speed(speed)

            if is_sub:
                self._phase      = "subs"
                self._step_label = (
                    f"Sous-titres  ({self._sub_done + 1}/{self._n_subs})"
                    if self._n_subs else "Sous-titres"
                )
                self._step_pct   = pct
                self._step_eta   = ""
                self._step_spd   = ""
                # Total : proportion subs dans l'ensemble (subs = ~5 % du total)
                sub_weight = 5.0
                self._total_pct  = min(
                    sub_weight * (self._sub_done / max(self._n_subs, 1))
                    + sub_weight / max(self._n_subs, 1) * (pct / 100),
                    sub_weight,
                )
                self._total_eta  = ""

            else:
                self._phase       = "audio" if self._audio_mode else "video"
                self._video_bytes = downloaded
                self._video_total = total
                self._step_label  = "Audio" if self._audio_mode else "Vidéo"
                self._step_pct    = pct
                self._step_eta    = eta_str
                self._step_spd    = spd_str
                self._total_pct   = pct   # audio = 100 % du total
                self._total_eta   = eta_str

        elif status == "finished":
            if is_sub:
                self._sub_done  += 1
                self._step_pct   = 100.0
            else:
                self._phase      = "merge"
                if self._audio_mode:
                    self._step_label = "Conversion en MP3"
                elif self._want_subs:
                    self._step_label = "Combinaison vidéo + audio + sous-titres"
                else:
                    self._step_label = "Combinaison vidéo + audio"
                self._step_pct   = 0.0
                self._step_eta   = ""
                self._step_spd   = ""
                self._total_pct  = 95.0 if not self._audio_mode else 98.0
                self._total_eta  = ""

        elif status == "error":
            pass  # erreurs gérées par _Logger, on n'interrompt pas le rendu

        self._render()

    def on_postprocessor(self, d: dict) -> None:  # pylint: disable=too-many-branches
        """Appelé au début et à la fin de chaque postprocesseur.

        yt-dlp ne remonte pas de progression intermédiaire pendant ffmpeg :
        on reçoit uniquement "started" puis "finished".
        → On lance un thread qui anime la barre en fonction du temps écoulé.
        """
        import threading  # pylint: disable=import-outside-toplevel
        status = d.get("status", "")
        if status == "started":
            pp = d.get("postprocessor", "")
            if "Merge" in pp or "EmbedSubtitle" in pp or "Metadata" in pp \
                    or "ExtractAudio" in pp:
                self._phase      = "merge"
                if self._audio_mode:
                    self._step_label = "Conversion en MP3"
                elif self._want_subs:
                    self._step_label = "Combinaison vidéo + audio + sous-titres"
                else:
                    self._step_label = "Combinaison vidéo + audio"
                self._step_spd   = ""
                self._merge_start = time.monotonic()
                # Lance le thread d'animation (s'arrête seul quand merge fini)
                self._merge_thread = threading.Thread(
                    target=self._animate_merge, daemon=True
                )
                self._merge_thread.start()
        elif status == "finished":
            # Arrêter l'animation et afficher 100 %
            self._merge_start = 0.0   # signal d'arrêt pour le thread
            if self._merge_thread and self._merge_thread.is_alive():
                self._merge_thread.join(timeout=2)
            self._step_pct  = 100.0
            self._total_pct = 100.0
            self._step_eta  = ""
            self._total_eta = ""
            self._render()

    # ── Animation merge ──────────────────────────────────────────────────────

    def _animate_merge(self) -> None:
        """Thread daemon : anime la barre de merge basé sur le temps écoulé.

        Sans info réelle de ffmpeg, on simule une progression logarithmique
        qui démarre vite puis ralentit (réaliste pour un stream copy).
        S'arrête quand _merge_start est remis à 0 (signal "finished").
        """
        # Durée estimée : ~2s pour stream copy, ~30s si re-encode
        # On monte jusqu'à 95 % max, jamais 100 % (réservé au finished)
        while self._merge_start > 0:
            elapsed = time.monotonic() - self._merge_start
            # Progression logarithmique : monte vite au début, plafonne vers 95 %
            # log(1 + elapsed) / log(1 + ref) capped à 0.95
            ref = 15.0  # secondes de référence pour atteindre ~80 %
            import math  # pylint: disable=import-outside-toplevel
            raw = math.log(1 + elapsed) / math.log(1 + ref)
            pct = min(raw * 95.0, 95.0)
            self._step_pct  = pct
            # Total : 95 % (fin vidéo) → 99 % progressivement
            self._total_pct = 95.0 + pct / 95.0 * 4.0
            # ETA estimée
            if pct < 90:
                remaining = ref * math.exp((1 - pct / 95.0) * math.log(1 + ref)) - 1
                self._step_eta = self._fmt_eta(max(0, remaining - elapsed))
            else:
                self._step_eta = ""
            self._render()
            time.sleep(0.25)

    # ── Rendu terminal ────────────────────────────────────────────────────────

    def _render(self) -> None:  # pylint: disable=too-many-locals
        """Réécrit les 4 lignes de progression sur place.

        Utilise \033[K (erase to end of line) pour effacer les résidus
        de texte plus long de la ligne précédente (évite les artefacts).
        """
        import sys  # pylint: disable=import-outside-toplevel

        C   = self._CYAN
        G   = self._GREEN
        Y   = self._YELLOW
        B   = self._BOLD
        D   = self._DIM
        R   = self._RESET
        UP  = self._UP
        EL  = "\033[K"   # Erase to end of Line — efface les résidus
        W   = 58

        # ── Ligne 1 : TOTAL ─────────────────────────────────────────────────
        total_bar = self._bar(self._total_pct, self._BAR_W)
        total_eta = f"  ETA {self._total_eta}" if self._total_eta else ""
        l1 = (
            f"  {B}TOTAL{R}  "
            f"{C}[{total_bar}]{R}  "
            f"{B}{self._total_pct:5.1f}%{R}"
            f"{D}{total_eta}{R}{EL}"
        )

        # ── Ligne 2 : Séparateur ─────────────────────────────────────────────
        l2 = f"  {D}{'─' * W}{R}{EL}"

        # ── Lignes 3-4 : Étape (label + barre) ──────────────────────────────
        step_bar = self._bar(self._step_pct, self._BAR_W)
        # ETA et vitesse sont stockés séparément pour éviter les artefacts
        step_extra = ""
        if self._step_eta:
            step_extra = f"  ETA {self._step_eta}"
        if self._step_spd:
            step_extra += f"  {self._step_spd}"

        color = (
            Y if self._phase == "subs"
            else G if self._phase in ("video", "audio")
            else C
        )
        l3 = (
            f"  {color}{self._step_label}{R}{EL}\n"
            f"  {color}[{step_bar}]{R}  "
            f"{B}{self._step_pct:5.1f}%{R}"
            f"{D}{step_extra}{R}{EL}"
        )

        if not self._printed:
            sys.stdout.write(f"\n{l1}\n{l2}\n{l3}\n")
            self._printed = True
        else:
            # 4 lignes à remonter : l1, l2, label, barre
            sys.stdout.write(f"{UP}{UP}{UP}{UP}\r{l1}\n{l2}\n{l3}\n")

        sys.stdout.flush()

    def finish(self) -> None:
        """Affiche l'état final (100 %) et saute une ligne."""
        import sys  # pylint: disable=import-outside-toplevel
        self._total_pct  = 100.0
        self._step_pct   = 100.0
        self._step_eta   = ""
        self._total_eta  = ""
        if self._phase != "merge":
            self._step_label = "Terminé"
            self._phase      = "merge"
        self._render()
        sys.stdout.write("\n")
        sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Téléchargement principal
# ─────────────────────────────────────────────────────────────────────────────
def do_download(url, mode, dest_dir, ffmpeg_exe, cfg):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Télécharge la vidéo en MP4 (meilleure qualité).
    - Sous-titres manuels intégrés dans le MP4 (sélectionnables dans VLC)
    - Progression en temps réel sur 4 lignes fixes (pas de scroll)
    - Téléchargement dans .cotube_tmp/, un seul MP4 déplacé vers dest_dir
    - Nettoyage complet du dossier temp à la fin
    """
    import yt_dlp  # pylint: disable=import-outside-toplevel

    os.makedirs(dest_dir, exist_ok=True)
    tmp_dir = os.path.join(dest_dir, ".cotube_tmp")
    shutil.rmtree(tmp_dir, ignore_errors=True)
    os.makedirs(tmp_dir, exist_ok=True)

    # ── Logger silencieux sauf 429 ────────────────────────────────────────────
    class _Logger:  # pylint: disable=too-few-public-methods
        """Logger yt-dlp : silence sauf erreurs non-429."""
        def debug(self, msg):    # pylint: disable=no-self-use
            """Silence."""
        def warning(self, msg):  # pylint: disable=no-self-use
            """Silence."""
        def error(self, msg):    # pylint: disable=no-self-use
            """Affiche uniquement les erreurs non-429."""
            if "429" not in msg:
                print(f"\n  \033[31m✖  {msg}\033[0m")

    # ─────────────────────────────────────────────────────────────────────────
    # MODE AUDIO : MP3 simple
    # ─────────────────────────────────────────────────────────────────────────
    if mode == "audio":
        label = "Audio MP3"
        renderer = _DownloadRenderer(n_subs=0, titre="Audio", audio_mode=True)
        ydl_opts = {
            "format":          "bestaudio/best",
            "outtmpl":         os.path.join(tmp_dir, "%(title)s.%(ext)s"),
            "noplaylist":      True,
            "logger":          _Logger(),
            "quiet":           True,
            "no_warnings":     True,
            "progress_hooks":  [renderer.on_progress],
            "postprocessor_hooks": [renderer.on_postprocessor],
        }
        if ffmpeg_exe:
            ydl_opts["ffmpeg_location"] = os.path.dirname(ffmpeg_exe)
            ydl_opts["postprocessors"]  = [{"key": "FFmpegExtractAudio",
                                            "preferredcodec": "mp3",
                                            "preferredquality": "192"}]
        # Récupération rapide du titre pour l'affichage
        audio_titre = ""
        audio_duree = ""
        try:
            _info_opts = {"quiet": True, "no_warnings": True, "logger": _Logger()}
            if ffmpeg_exe:
                _info_opts["ffmpeg_location"] = os.path.dirname(ffmpeg_exe)
            _apply_cookies(_info_opts, cfg)
            with yt_dlp.YoutubeDL(_info_opts) as _ydl_q:
                _info = _ydl_q.extract_info(url, download=False)
            audio_titre = _info.get("title", "")[:55]
            _dur = _info.get("duration", 0)
            _m, _s = divmod(int(_dur), 60)
            audio_duree = f"{_m}m {_s:02d}s"
            renderer._titre = audio_titre  # pylint: disable=protected-access
        except Exception:  # pylint: disable=broad-except
            pass

        ConsoleUI.clear()
        print(ConsoleUI.BANNER)
        print(f"\n  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.BOLD}TÉLÉCHARGEMENT EN COURS — {label}{ConsoleUI.RESET}")
        if audio_titre:
            print(f"  {ConsoleUI.DIM}Titre       : {audio_titre}{ConsoleUI.RESET}")
        if audio_duree:
            print(f"  {ConsoleUI.DIM}Durée       : {audio_duree}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.DIM}Destination : {dest_dir}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")
        _apply_cookies(ydl_opts, cfg, verbose=True)
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.download([url])
        except yt_dlp.utils.DownloadError as exc:
            print()
            ConsoleUI.result_screen([f"  {ConsoleUI.RED}✖  Erreur : {exc}{ConsoleUI.RESET}"])
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return
        renderer.finish()
        _finalise(tmp_dir, dest_dir, mode, label, ConsoleUI)
        return

    # ─────────────────────────────────────────────────────────────────────────
    # MODE VIDÉO : MP4 + sous-titres intégrés
    # ─────────────────────────────────────────────────────────────────────────

    # Étape 1 — Analyse
    ConsoleUI.clear()
    print(ConsoleUI.BANNER)
    print(f"\n  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.BOLD}ANALYSE DE LA VIDÉO...{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}\n")

    manual_sub_langs = []
    titre = "video"

    try:
        info_opts = {"quiet": True, "no_warnings": True, "logger": _Logger()}
        if ffmpeg_exe:
            info_opts["ffmpeg_location"] = os.path.dirname(ffmpeg_exe)
        _apply_cookies(info_opts, cfg)
        with yt_dlp.YoutubeDL(info_opts) as ydl_q:
            info = ydl_q.extract_info(url, download=False)
        titre            = info.get("title", "video")
        duree            = info.get("duration", 0)
        m_dur, s_dur     = divmod(int(duree), 60)
        manual_sub_langs = sorted((info.get("subtitles") or {}).keys())

        ConsoleUI.info(f"Titre       : {titre}")
        ConsoleUI.info(f"Durée       : {m_dur}m {s_dur:02d}s")
        if manual_sub_langs:
            preview = manual_sub_langs[:10]
            more    = len(manual_sub_langs) - len(preview)
            ConsoleUI.info(
                f"Sous-titres : {ConsoleUI.BOLD}{len(manual_sub_langs)} langue(s) "
                f"— {', '.join(preview)}"
                + (f"  (+{more})" if more else "")
                + ConsoleUI.RESET
            )
        else:
            ConsoleUI.info("Sous-titres : aucun sous-titre manuel")
        ConsoleUI.sep()
    except Exception as exc:  # pylint: disable=broad-except
        ConsoleUI.warn(f"Analyse partielle ({exc}) — format par défaut.")

    # Sous-titres toujours activés si disponibles
    want_subs = bool(manual_sub_langs)

    if want_subs:
        label = "MP4 — meilleure qualité + sous-titres intégrés"
    else:
        label = "MP4 — meilleure qualité"

    # Étape 2 — Renderer de progression
    renderer = _DownloadRenderer(
        n_subs=len(manual_sub_langs),
        titre=titre,
        want_subs=want_subs,
    )

    # Étape 3 — Options yt-dlp
    sub_pp  = [{"key": "FFmpegEmbedSubtitle", "already_have_subtitle": False}]

    ydl_opts = {
        # Priorité : deux streams séparés (meilleure qualité) → stream copy
        # Fallback : format déjà muxé mp4 (aucun merge nécessaire)
        "format":               "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best",
        "outtmpl":              os.path.join(tmp_dir, "%(title)s.%(ext)s"),
        "noplaylist":           True,
        "logger":               _Logger(),
        "quiet":                True,
        "no_warnings":          True,
        "merge_output_format":  "mp4",
        "ignoreerrors":         True,
        "writesubtitles":       want_subs,
        "writeautomaticsub":    False,
        "subtitleslangs":       ["all"] if want_subs else [],
        "keepvideo":            False,
        # stream copy : ffmpeg copie les streams sans réencoder → quasi instantané
        "postprocessor_args":   {"merger": ["-c", "copy"]},
        "progress_hooks":       [renderer.on_progress],
        "postprocessor_hooks":  [renderer.on_postprocessor],
        "postprocessors":       sub_pp if want_subs else [],
    }
    if ffmpeg_exe:
        ydl_opts["ffmpeg_location"] = os.path.dirname(ffmpeg_exe)
    _apply_cookies(ydl_opts, cfg, verbose=True)

    print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.BOLD}TÉLÉCHARGEMENT EN COURS{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.DIM}Format  : {label}{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.DIM}Sortie  : {dest_dir}{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")

    # Étape 4 — Téléchargement
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])

    renderer.finish()
    _finalise(tmp_dir, dest_dir, mode, label, ConsoleUI)


def _finalise(tmp_dir, dest_dir, mode, label, UI):
    """Déplace UNIQUEMENT le fichier final (mp4/mp3) vers dest_dir.
    Supprime tous les fichiers temporaires et le dossier .cotube_tmp.
    """
    UI.info("Finalisation...")

    final_ext = ".mp3" if mode == "audio" else ".mp4"
    final_file = None
    moved_name = None

    if os.path.isdir(tmp_dir):
        # Chercher le fichier final (mp4 ou mp3), ignorer les .temp.* et .vtt/.srt
        candidates = [
            f for f in os.listdir(tmp_dir)
            if f.endswith(final_ext)
            and ".temp." not in f
            and ".part" not in f
        ]
        if candidates:
            # Prendre le plus gros (= le fichier mergé, pas un fragment)
            candidates.sort(key=lambda f: os.path.getsize(os.path.join(tmp_dir, f)), reverse=True)
            src = os.path.join(tmp_dir, candidates[0])
            dst = os.path.join(dest_dir, candidates[0])
            # Éviter l'écrasement
            if os.path.exists(dst):
                base, ext = os.path.splitext(candidates[0])
                i = 2
                while os.path.exists(dst):
                    dst = os.path.join(dest_dir, f"{base} ({i}){ext}")
                    i += 1
            try:
                shutil.move(src, dst)
                final_file = dst
                moved_name = os.path.basename(dst)
                UI.success(f"Fichier créé : {moved_name}")
            except Exception as e:
                UI.warn(f"Erreur déplacement : {e}")

        # Nettoyage complet du dossier temp (vtt, srt, temp.mp4, fragments…)
        shutil.rmtree(tmp_dir, ignore_errors=True)

    if not final_file:
        UI.result_screen([
            f"  \033[31m✖  Aucun fichier {final_ext} trouvé dans le dossier temp.\033[0m",
            f"  {UI.DIM}Le téléchargement a peut-être échoué silencieusement.{UI.RESET}",
        ])
        return

    lines = [
        f"  {UI.GREEN}✔  Téléchargement terminé !{UI.RESET}",
        f"  {UI.DIM}Format : {label}{UI.RESET}",
        "",
        f"  {UI.CYAN}📂  {dest_dir}{UI.RESET}",
        f"  {UI.DIM}   • {moved_name}{UI.RESET}",
    ]
    if mode == "video":
        lines += [
            "",
            f"  {UI.CYAN}ℹ  Sous-titres intégrés — sélectionnables dans VLC :{UI.RESET}",
            f"  {UI.DIM}   Sous-titres › Piste sous-titres{UI.RESET}",
        ]
    UI.result_screen(lines)


def menu_download(dest_dir, ffmpeg_exe, cfg):
    url = ConsoleUI.input_screen(
        "TÉLÉCHARGER UNE VIDÉO", "Collez le lien YouTube",
        subtitle="Exemple : https://www.youtube.com/watch?v=...",
    )
    if not url: return
    if not url.startswith(("http://", "https://")):
        ConsoleUI.result_screen([f"  {ConsoleUI.RED}✖  Lien invalide.{ConsoleUI.RESET}",
                                 f"  {ConsoleUI.DIM}Collez une URL complète.{ConsoleUI.RESET}"])
        return

    cookie_info = _cookie_summary(cfg)
    choice = ConsoleUI.navigate(
        ["🎬  Meilleure qualité  (toutes pistes audio + sous-titres, MKV)", "🎵  Audio seulement  (MP3)", "🔙  Retour"],
        "CHOISIR LE FORMAT",
        subtitle=f"URL : {url[:55]}{'…' if len(url)>55 else ''}  |  {cookie_info}",
    )
    if choice in (2, -1): return

    try:
        do_download(url, "video" if choice == 0 else "audio", dest_dir[0], ffmpeg_exe, cfg)
    except KeyboardInterrupt:
        ConsoleUI.result_screen([f"  {ConsoleUI.YELLOW}⚠  Téléchargement annulé.{ConsoleUI.RESET}"])
    except Exception as e:
        ConsoleUI.result_screen([
            f"  {ConsoleUI.RED}✖  Erreur : {e}{ConsoleUI.RESET}",
            f"  {ConsoleUI.DIM}Si l'erreur persiste : Paramètres → Cookies → Tester.{ConsoleUI.RESET}",
        ])


# ─────────────────────────────────────────────────────────────────────────────
# Menu cookies
# ─────────────────────────────────────────────────────────────────────────────
def menu_cookies(cfg, ffmpeg_exe):
    while True:
        summary = _cookie_summary(cfg)
        choice = ConsoleUI.navigate(
            [
                "🌐  Utiliser les cookies d'un navigateur  (Chrome ouvert = OK)",
                "📄  Charger un fichier cookies.txt",
                "🧪  Tester les cookies actuels",
                "🗑️   Désactiver les cookies",
                "❓  Aide & conseils anti-bot",
                "🔙  Retour",
            ],
            "GESTION DES COOKIES", subtitle=f"Actuel : {summary}",
        )

        if choice == 0:
            b_opts = [BROWSER_LABELS[b] for b in BROWSERS] + ["🔙  Retour"]
            bc = ConsoleUI.navigate(
                b_opts, "CHOISIR LE NAVIGATEUR",
                subtitle="Chromium/Chrome/Edge/Brave : extraction native — navigateur peut rester ouvert",
            )
            if bc in (-1, len(BROWSERS)): continue
            sel = BROWSERS[bc]
            cfg.update({"cookie_browser": sel, "cookie_method": "browser", "cookie_file": ""})
            _save_config(cfg)
            ConsoleUI.result_screen([
                f"  {ConsoleUI.GREEN}✔  {BROWSER_LABELS[sel]} sélectionné.{ConsoleUI.RESET}",
                f"  {ConsoleUI.CYAN}ℹ  CO-TUBE lit la base SQLite directement —{ConsoleUI.RESET}",
                f"  {ConsoleUI.CYAN}   le navigateur peut rester ouvert.{ConsoleUI.RESET}",
                f"  {ConsoleUI.YELLOW}⚠  Assurez-vous d'être connecté à YouTube.{ConsoleUI.RESET}",
            ])

        elif choice == 1:
            path = ConsoleUI.input_screen(
                "FICHIER COOKIES.TXT", "Chemin complet vers le fichier",
                subtitle="Ex: C:\\Users\\Moi\\cookies.txt",
            )
            if not path: continue
            path = os.path.expanduser(path.strip('"').strip("'"))
            if not os.path.isfile(path):
                ConsoleUI.result_screen([f"  {ConsoleUI.RED}✖  Fichier introuvable : {path}{ConsoleUI.RESET}"])
                continue
            cfg.update({"cookie_file": path, "cookie_method": "file", "cookie_browser": ""})
            _save_config(cfg)
            ConsoleUI.result_screen([
                f"  {ConsoleUI.GREEN}✔  Fichier cookies chargé !{ConsoleUI.RESET}",
                f"  {ConsoleUI.CYAN}📄  {path}{ConsoleUI.RESET}",
            ])

        elif choice == 2:
            ConsoleUI.clear()
            print(ConsoleUI.BANNER)
            print(f"\n  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")
            print(f"  {ConsoleUI.BOLD}TEST DES COOKIES\n")
            try:
                import yt_dlp
                opts = {"quiet": True, "no_warnings": True, "skip_download": True}
                if ffmpeg_exe: opts["ffmpeg_location"] = os.path.dirname(ffmpeg_exe)
                src = _apply_cookies(opts, cfg, verbose=True)
                if not src:
                    raise RuntimeError("Aucun cookie configuré.")
                with yt_dlp.YoutubeDL(opts) as ydl:
                    ydl.extract_info("https://www.youtube.com/watch?v=dQw4w9WgXcQ", download=False)
                ConsoleUI.result_screen([
                    f"  {ConsoleUI.GREEN}✔  Cookies fonctionnels ! (source : {src}){ConsoleUI.RESET}",
                    f"  {ConsoleUI.DIM}Vidéos âge restreint et membres accessibles.{ConsoleUI.RESET}",
                ])
            except Exception as e:
                ConsoleUI.result_screen([
                    f"  {ConsoleUI.RED}✖  Test échoué : {e}{ConsoleUI.RESET}",
                    f"  {ConsoleUI.YELLOW}⚠  Vérifiez que vous êtes connecté à YouTube.{ConsoleUI.RESET}",
                ])

        elif choice == 3:
            cfg.pop("cookie_browser", None)
            cfg.pop("cookie_file", None)
            cfg.pop("cookie_method", None)
            _save_config({"cookie_browser": "", "cookie_file": "", "cookie_method": ""})
            ConsoleUI.result_screen([
                f"  {ConsoleUI.GREEN}✔  Cookies désactivés.{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}Seules les vidéos publiques seront accessibles.{ConsoleUI.RESET}",
            ])

        elif choice == 4:
            ConsoleUI.result_screen([
                f"  {ConsoleUI.BOLD}{ConsoleUI.CYAN}POURQUOI DES COOKIES ?{ConsoleUI.RESET}",
                "",
                f"  {ConsoleUI.DIM}• Erreur 'Sign in to confirm you're not a bot'{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}• Vidéos avec restriction d'âge{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}• Contenu membres / YouTube Premium{ConsoleUI.RESET}",
                "",
                f"  {ConsoleUI.YELLOW}MÉTHODE 1 — Navigateur (le plus simple){ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}CO-TUBE lit la base SQLite de Chrome/Edge/Brave{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}même si le navigateur est ouvert (Backup API).{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}→ Connectez-vous à YouTube dans Chrome, c'est tout.{ConsoleUI.RESET}",
                "",
                f"  {ConsoleUI.YELLOW}MÉTHODE 2 — Fichier cookies.txt{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}Extension 'Get cookies.txt LOCALLY' (Chrome/Firefox){ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}YouTube → exporter → charger le fichier ici.{ConsoleUI.RESET}",
                "",
                f"  {ConsoleUI.YELLOW}ASTUCE COOKIES STABLES (anti-rotation YouTube){ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}1. Ouvrir Chrome en navigation PRIVÉE{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}2. Se connecter à YouTube{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}3. Aller sur youtube.com/robots.txt{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}4. Exporter cookies → fermer la fenêtre privée{ConsoleUI.RESET}",
                f"  {ConsoleUI.DIM}Ces cookies ne seront jamais renouvelés.{ConsoleUI.RESET}",
            ])

        elif choice in (5, -1):
            return


# ─────────────────────────────────────────────────────────────────────────────
# Menu paramètres
# ─────────────────────────────────────────────────────────────────────────────
def menu_settings(dest_dir, cfg, ffmpeg_exe):
    while True:
        csummary = _cookie_summary(cfg)
        choice = ConsoleUI.navigate(
            ["📁  Changer le dossier de téléchargement",
             "📂  Ouvrir le dossier actuel",
             f"🍪  Cookies  [{csummary}]",
             "🔙  Retour"],
            "PARAMÈTRES", subtitle=f"Dossier : {dest_dir[0]}",
        )
        if choice in (-1, 3): return

        if choice == 0:
            new = ConsoleUI.input_screen("DOSSIER DE TÉLÉCHARGEMENT", "Nouveau chemin complet",
                                         subtitle=f"Actuel : {dest_dir[0]}")
            if new:
                try:
                    os.makedirs(new, exist_ok=True)
                    dest_dir[0] = os.path.abspath(new)
                    _save_config({"dest_dir": dest_dir[0]})
                    ConsoleUI.result_screen([f"  {ConsoleUI.GREEN}✔  Dossier mis à jour !{ConsoleUI.RESET}",
                                             f"  {ConsoleUI.CYAN}📂  {dest_dir[0]}{ConsoleUI.RESET}"])
                except Exception as e:
                    ConsoleUI.result_screen([f"  {ConsoleUI.RED}✖  {e}{ConsoleUI.RESET}"])

        elif choice == 1:
            try:
                if os.name == "nt":    os.startfile(dest_dir[0])
                elif _is_termux():     subprocess.run(["termux-open", dest_dir[0]], check=False)
                else:                  subprocess.run(["xdg-open", dest_dir[0]], check=False)
                time.sleep(1)
            except Exception as e:
                ConsoleUI.result_screen([f"  {ConsoleUI.RED}✖  {e}{ConsoleUI.RESET}"])

        elif choice == 2:
            menu_cookies(cfg, ffmpeg_exe)


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────────────────────────────────────
def main():
    ConsoleUI.enable_ansi()
    if os.name == "nt":
        os.system("title 🎬 CO-TUBE DOWNLOADER 🎬")

    ConsoleUI.clear()
    print(ConsoleUI.BANNER)
    print(f"\n  {ConsoleUI.DIM}⏳ Chargement, veuillez patienter...{ConsoleUI.RESET}\n")

    steps   = [("yt-dlp + dépendances", setup_dependencies), ("FFmpeg", setup_ffmpeg)]
    results = {}
    bar_w   = 40

    for idx, (label, fn) in enumerate(steps):
        pct    = int((idx / len(steps)) * 100)
        filled = pct * bar_w // 100
        pbar   = "█" * filled + "░" * (bar_w - filled)
        print(f"\r  {ConsoleUI.CYAN}[{pbar}]{ConsoleUI.RESET}  {label}...", end="", flush=True)
        results[label] = fn()

    print(f"\r  {ConsoleUI.CYAN}[{'█'*bar_w}]{ConsoleUI.RESET}  Prêt !          ", flush=True)
    print()

    ffmpeg_exe = results["FFmpeg"]
    if not ffmpeg_exe:
        ConsoleUI.warn("FFmpeg introuvable — la fusion vidéo/audio sera désactivée.")

    cfg = _load_config()
    saved = cfg.get("dest_dir", "")

    if _is_android():
        # ── Android (Termux, Pydroid3, etc.) ─────────────────────────────────
        # Dossier par défaut : Vidéos visibles dans la galerie et les fichiers
        fallback = "/storage/emulated/0/Movies/CoTEAM/Co-tube"
    else:
        fallback = _base_dir()

    # Si un chemin personnalisé a été sauvegardé et qu'il est accessible, on l'utilise
    if saved and os.path.isdir(os.path.dirname(saved) or "."):
        initial = saved
    else:
        initial = fallback

    try:
        os.makedirs(initial, exist_ok=True)
    except OSError:
        # Fallback si le stockage interne n'est pas accessible (permissions manquantes)
        initial = os.path.join(os.path.expanduser("~"), "co-tube")
        os.makedirs(initial, exist_ok=True)

    dest_dir = [initial]

    while True:
        cookie_info = _cookie_summary(cfg)
        choice = ConsoleUI.navigate(
            ["🎬  Télécharger une vidéo", "⚙️   Paramètres", "❌  Quitter"],
            "MENU PRINCIPAL",
            f"v{VERSION}  —  {dest_dir[0]}  |  {cookie_info}",
        )
        if choice == 0:      menu_download(dest_dir, ffmpeg_exe, cfg)
        elif choice == 1:    menu_settings(dest_dir, cfg, ffmpeg_exe)
        elif choice in (2, -1):
            ConsoleUI.result_screen([
                f"  {ConsoleUI.CYAN}👋  Merci d'avoir utilisé CO-TUBE !{ConsoleUI.RESET}",
                "  🎬  À bientôt !",
            ], pause=False)
            time.sleep(1)
            sys.exit(0)


def _goodbye():
    try:
        ConsoleUI.clear()
        print(ConsoleUI.CYAN + "\n  " + "═"*58 + ConsoleUI.RESET)
        print(f"  {ConsoleUI.CYAN}👋  Merci d'avoir utilisé CO-TUBE !{ConsoleUI.RESET}")
        print("  🎬  À bientôt !")
        print(ConsoleUI.CYAN + "  " + "═"*58 + ConsoleUI.RESET + "\n")
        time.sleep(1)
    except Exception:
        pass
    sys.exit(0)


def _signal_handler(_sig, _frame):
    _goodbye()


if __name__ == "__main__":
    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _signal_handler)
    try:
        main()
    except KeyboardInterrupt:
        _goodbye()
    except Exception as _e:
        ConsoleUI.clear()
        print(ConsoleUI.RED + "\n\n  💥  ERREUR CRITIQUE\n" + ConsoleUI.RESET)
        print(f"  {_e}\n")
        traceback.print_exc()
        try:
            input("\n  Appuyez sur Entrée pour quitter...")
        except (EOFError, OSError):
            pass
        _goodbye()
