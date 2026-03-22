# pylint: disable=line-too-long,too-many-lines
"""YT-DL — Téléchargeur de vidéos YouTube avec interface style CO-FLIX."""

import os
import sys
import shutil
import signal
import subprocess
import tempfile
import time
import json as _json
import traceback

try:
    import ctypes
except ImportError:
    ctypes = None  # pylint: disable=invalid-name

try:
    import msvcrt
except ImportError:
    msvcrt = None  # pylint: disable=invalid-name

try:
    import tty
    import termios
    import select
except ImportError:
    tty = termios = select = None  # pylint: disable=invalid-name

VERSION = "1.0"

# ─────────────────────────────────────────────────────────────────────────────
# Détection environnement
# ─────────────────────────────────────────────────────────────────────────────
def _is_termux():
    """Retourne True si on tourne dans Termux (Android)."""
    return (os.name != "nt" and (
        "ANDROID_STORAGE" in os.environ
        or "com.termux" in os.environ.get("PREFIX", "")
    ))


def _base_dir():
    """Retourne le dossier de base du script (ou de l'exécutable)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _config_path():
    """Retourne le chemin du fichier de config JSON."""
    return os.path.join(_base_dir(), "ytdl_config.json")


def _load_config():
    """Charge la config. Retourne un dict (vide si absent/corrompu)."""
    try:
        with open(_config_path(), encoding="utf-8") as _f:
            return _json.load(_f)
    except Exception:  # pylint: disable=broad-except
        return {}


def _save_config(data):
    """Sauvegarde la config (merge avec l'existant)."""
    try:
        existing = _load_config()
        existing.update(data)
        with open(_config_path(), "w", encoding="utf-8") as _f:
            _json.dump(existing, _f, indent=2)
    except Exception:  # pylint: disable=broad-except
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Installation automatique des dépendances
# ─────────────────────────────────────────────────────────────────────────────
def _install_if_missing(package, pip_name=None):
    """Installe un paquet pip si non présent."""
    pip_name = pip_name or package
    try:
        __import__(package)
    except ImportError:
        print(f"  {ConsoleUI.CYAN}ℹ  {ConsoleUI.RESET}Installation de {pip_name}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"  {ConsoleUI.GREEN}✔  {ConsoleUI.RESET}{pip_name} installé.")


def setup_dependencies():
    """Installe yt-dlp et imageio-ffmpeg si nécessaire."""
    _install_if_missing("yt_dlp", "yt-dlp")
    _install_if_missing("imageio_ffmpeg", "imageio-ffmpeg")


# ─────────────────────────────────────────────────────────────────────────────
# FFmpeg — résolution du binaire
# ─────────────────────────────────────────────────────────────────────────────
def setup_ffmpeg():
    """
    Retourne le chemin complet vers un ffmpeg utilisable par yt-dlp.
    Priorité : PATH système → imageio-ffmpeg (copié sous le bon nom).
    """
    exe_name = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"

    # 1. ffmpeg dans le PATH
    found = shutil.which("ffmpeg")
    if found:
        return found

    # 2. imageio-ffmpeg — binaire embarqué (nom non standard → on le copie)
    try:
        import imageio_ffmpeg  # pylint: disable=import-outside-toplevel
        src = imageio_ffmpeg.get_ffmpeg_exe()

        tmp_dir = os.path.join(tempfile.gettempdir(), "ytdl_ffmpeg")
        os.makedirs(tmp_dir, exist_ok=True)
        dst = os.path.join(tmp_dir, exe_name)

        # Copie uniquement si nécessaire
        if not os.path.exists(dst) or os.path.getsize(dst) != os.path.getsize(src):
            shutil.copy2(src, dst)
            if os.name != "nt":
                os.chmod(dst, 0o755)

        return dst
    except Exception:  # pylint: disable=broad-except
        pass

    return None


# ─────────────────────────────────────────────────────────────────────────────
# ConsoleUI — interface identique à CO-FLIX
# ─────────────────────────────────────────────────────────────────────────────
class ConsoleUI:
    """Utilitaires d'interface console avec couleurs ANSI et navigation clavier."""

    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RED    = '\033[31m'
    GREEN  = '\033[32m'
    YELLOW = '\033[33m'
    CYAN   = '\033[36m'

    BANNER = CYAN + r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██████╗       ████████╗██╗   ██╗██████╗ ███████╗   ║
║  ██╔════╝██╔═══██╗         ██╔══╝██║   ██║██╔══██╗██╔════╝   ║
║  ██║     ██║   ██║█████╗   ██║   ██║   ██║██████╔╝█████╗     ║
║  ██║     ██║   ██║╚════╝   ██║   ██║   ██║██╔══██╗██╔══╝     ║
║  ╚██████╗╚██████╔╝         ██║   ╚██████╔╝██████╔╝███████╗   ║
║   ╚═════╝ ╚═════╝          ╚═╝    ╚═════╝ ╚═════╝ ╚══════╝   ║
║                                                              ║
║            🎬  CO-TUBE  DOWNLOADER  🎬                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝""" + RESET

    MAX_VISIBLE = 8

    @staticmethod
    def enable_ansi():
        """Active le support ANSI sur Windows."""
        if os.name == "nt":
            try:
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:  # pylint: disable=broad-except
                pass

    @staticmethod
    def clear():
        """Efface la console."""
        os.system("cls" if os.name == "nt" else "clear")

    @staticmethod
    def display_len(s):
        """Retourne la largeur visuelle réelle d'une chaîne (emojis = 2)."""
        count = 0
        for ch in s:
            cp = ord(ch)
            if cp in (0xFE0E, 0xFE0F, 0x200D, 0x20E3):
                continue
            if 0x0300 <= cp <= 0x036F:
                continue
            is_emoji = (0x1F000 <= cp <= 0x1FFFF or 0x2600 <= cp <= 0x27BF
                        or 0x2B00 <= cp <= 0x2BFF)
            is_cjk   = (0xFE30 <= cp <= 0xFE4F or 0x2E80 <= cp <= 0x2EFF
                        or 0x3000 <= cp <= 0x9FFF or 0xF900 <= cp <= 0xFAFF)
            is_hangul = 0xAC00 <= cp <= 0xD7AF
            if is_emoji or is_cjk or is_hangul:
                count += 2
            else:
                count += 1
        return count

    @staticmethod
    def show_menu(options, title="MENU", selected_index=0, subtitle=""):  # pylint: disable=too-many-locals
        """Affiche le menu interactif avec navigation clavier."""
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

        h_line      = "═" * box_w
        title_vlen  = ConsoleUI.display_len(title)
        title_pad_l = max(0, (box_w - title_vlen) // 2)
        title_pad_r = max(0, box_w - title_vlen - title_pad_l)

        print(f"  ╔{h_line}╗")
        print(f"  ║{' ' * title_pad_l}{ConsoleUI.BOLD}{ConsoleUI.CYAN}{title}{ConsoleUI.RESET}{' ' * title_pad_r}║")
        print(f"  ╠{h_line}╣")

        if top > 0:
            arrow_up = f"▲  {top} élément(s) plus haut"
            pad_r = " " * max(0, box_w - 2 - ConsoleUI.display_len(arrow_up))
            print(f"  ║  {ConsoleUI.CYAN}{arrow_up}{ConsoleUI.RESET}{pad_r}║")
        else:
            print(f"  ║{' ' * box_w}║")

        inner    = box_w - 4
        max_text = inner - 3

        for i in range(top, top + visible):
            raw = options[i]
            if ConsoleUI.display_len(raw) > max_text:
                accum, width = [], 0
                for ch in raw:
                    cw = 2 if ConsoleUI.display_len(ch) == 2 else 1
                    if width + cw > max_text - 1:
                        break
                    accum.append(ch)
                    width += cw
                raw = "".join(accum) + "…"

            prefix       = "▶  " if i == selected_index else "   "
            visible_text = prefix + raw
            pad_r        = " " * max(0, inner - ConsoleUI.display_len(visible_text))

            if i == selected_index:
                print(f"  ║  {ConsoleUI.CYAN}{ConsoleUI.BOLD}{visible_text}{ConsoleUI.RESET}{pad_r}  ║")
            else:
                print(f"  ║  {visible_text}{pad_r}  ║")

        remaining = len(options) - top - visible
        if remaining > 0:
            arrow_dn = f"▼  {remaining} élément(s) plus bas"
            pad_r = " " * max(0, box_w - 2 - ConsoleUI.display_len(arrow_dn))
            print(f"  ║  {ConsoleUI.CYAN}{arrow_dn}{ConsoleUI.RESET}{pad_r}║")
        else:
            print(f"  ║{' ' * box_w}║")

        print(f"  ╠{h_line}╣")
        nav     = "↑ ↓  Naviguer   ↵  Valider   Échap  Retour"
        nav_pad = " " * max(0, box_w - 2 - ConsoleUI.display_len(nav))
        print(f"  ║  {ConsoleUI.YELLOW}{nav}{ConsoleUI.RESET}{nav_pad}║")
        print(f"  ╚{h_line}╝")

    @staticmethod
    def show_menu_termux(options, title="MENU", subtitle=""):
        """Affiche le menu numéroté pour Termux."""
        ConsoleUI.clear()
        print(f"{ConsoleUI.CYAN}\n  {'═'*54}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.BOLD}{ConsoleUI.CYAN}🎬  CO-TUBE  —  {title}{ConsoleUI.RESET}")
        if subtitle:
            print(f"  {ConsoleUI.DIM}{subtitle}{ConsoleUI.RESET}")
        print(f"{ConsoleUI.CYAN}  {'═'*54}{ConsoleUI.RESET}\n")
        for i, opt in enumerate(options, 1):
            print(f"  {ConsoleUI.CYAN}{ConsoleUI.BOLD}[{i}]{ConsoleUI.RESET}  {opt}")
        print(f"  {ConsoleUI.CYAN}{ConsoleUI.BOLD}[0]{ConsoleUI.RESET}  {ConsoleUI.DIM}Retour{ConsoleUI.RESET}")
        print(f"\n{ConsoleUI.CYAN}  {'─'*54}{ConsoleUI.RESET}")

    @staticmethod
    def get_key():  # pylint: disable=too-many-return-statements,too-many-branches
        """Lit une touche (UP/DOWN/ENTER/ESC) sans bloquer."""
        if os.name == "nt":
            if msvcrt.kbhit():
                key = msvcrt.getch()
                if key == b'\xe0':
                    key = msvcrt.getch()
                    if key == b'H':
                        return 'UP'
                    if key == b'P':
                        return 'DOWN'
                elif key == b'\r':
                    return 'ENTER'
                elif key == b'\x1b':
                    return 'ESC'
        else:
            fd = sys.stdin.fileno()
            try:
                old_attr = termios.tcgetattr(fd)
            except Exception:  # pylint: disable=broad-except
                return None
            try:
                tty.setraw(fd)
                if select.select([sys.stdin], [], [], 0.05)[0]:
                    ch = sys.stdin.read(1)
                    if ch == '\x1b':
                        if select.select([sys.stdin], [], [], 0.05)[0]:
                            more = sys.stdin.read(2)
                            if more == '[A':
                                return 'UP'
                            if more == '[B':
                                return 'DOWN'
                        return 'ESC'
                    if ch in ('\r', '\n'):
                        return 'ENTER'
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_attr)
        return None

    @staticmethod
    def flush_keys():
        """Vide le buffer clavier."""
        if os.name == "nt":
            while msvcrt.kbhit():
                msvcrt.getch()
        else:
            try:
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
            except Exception:  # pylint: disable=broad-except
                pass

    @staticmethod
    def navigate(options, title="MENU", subtitle=""):  # pylint: disable=too-many-branches
        """Navigue dans un menu (flèches sur PC, chiffres sur Termux)."""
        if not options:
            return -1
        if _is_termux():
            while True:
                ConsoleUI.show_menu_termux(options, title, subtitle)
                try:
                    raw = input(f"  {ConsoleUI.YELLOW}▶  {ConsoleUI.RESET}Choix : ").strip()
                except (EOFError, OSError):
                    return -1
                if raw in ("0", ""):
                    return -1
                if raw.isdigit():
                    idx = int(raw) - 1
                    if 0 <= idx < len(options):
                        return idx
                ConsoleUI.warn(f"Choix invalide — entrez un nombre entre 1 et {len(options)}")
                time.sleep(0.8)
        else:
            selected = 0
            while True:
                ConsoleUI.show_menu(options, title, selected, subtitle)
                while True:
                    key = ConsoleUI.get_key()
                    if key:
                        break
                    time.sleep(0.03)
                if key == 'UP':
                    selected = (selected - 1) % len(options)
                elif key == 'DOWN':
                    selected = (selected + 1) % len(options)
                elif key == 'ENTER':
                    return selected
                elif key == 'ESC':
                    return -1

    @staticmethod
    def input_screen(title, prompt_text, subtitle=""):
        """Affiche un écran de saisie et retourne la valeur entrée."""
        ConsoleUI.clear()
        print(ConsoleUI.BANNER)
        print(f"\n  {ConsoleUI.CYAN}{ConsoleUI.BOLD}{'─'*58}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.BOLD}{title}{ConsoleUI.RESET}")
        if subtitle:
            print(f"  {ConsoleUI.DIM}{subtitle}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}\n")
        try:
            return input(f"  {ConsoleUI.YELLOW}▶  {ConsoleUI.RESET}{prompt_text} : ").strip()
        except (EOFError, OSError):
            return ""

    @staticmethod
    def result_screen(lines, pause=True):
        """Affiche un écran de résultat."""
        ConsoleUI.clear()
        print(ConsoleUI.CYAN + "\n  " + "═"*58 + ConsoleUI.RESET)
        for line in lines:
            print(line)
        print(ConsoleUI.CYAN + "\n  " + "═"*58 + ConsoleUI.RESET)
        if pause:
            try:
                input(f"\n  {ConsoleUI.DIM}Appuyez sur Entrée pour continuer...{ConsoleUI.RESET}")
            except (EOFError, OSError):
                pass

    @staticmethod
    def loading_screen(title, duration=1.5):
        """Affiche un écran de chargement animé."""
        ConsoleUI.clear()
        print(ConsoleUI.BANNER)
        print(f"\n  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.BOLD}{title}{ConsoleUI.RESET}")
        print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}\n")

        steps  = 20
        step_t = duration / steps
        bar_w  = 40
        ConsoleUI.flush_keys()
        for i in range(steps + 1):
            filled = int(bar_w * i / steps)
            pbar   = "█" * filled + "░" * (bar_w - filled)
            pct    = int(100 * i / steps)
            print(f"\r  {ConsoleUI.CYAN}[{pbar}]{ConsoleUI.RESET} {pct:3d}%",
                  end="", flush=True)
            time.sleep(step_t)
        print()
        ConsoleUI.flush_keys()

    @staticmethod
    def info(m):
        """Affiche un message informatif."""
        print(f"  {ConsoleUI.CYAN}ℹ  {ConsoleUI.RESET}{m}")

    @staticmethod
    def success(m):
        """Affiche un message de succès."""
        print(f"  {ConsoleUI.GREEN}✔  {ConsoleUI.RESET}{m}")

    @staticmethod
    def warn(m):
        """Affiche un avertissement."""
        print(f"  {ConsoleUI.YELLOW}⚠  {ConsoleUI.RESET}{m}")

    @staticmethod
    def sep():
        """Affiche un séparateur."""
        print(f"\n  {ConsoleUI.DIM}{'─'*54}{ConsoleUI.RESET}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Téléchargement
# ─────────────────────────────────────────────────────────────────────────────
def do_download(url, mode, dest_dir, ffmpeg_exe):
    """
    Télécharge une vidéo YouTube via yt-dlp.
    mode : "video" | "audio"
    """
    import yt_dlp  # pylint: disable=import-outside-toplevel

    os.makedirs(dest_dir, exist_ok=True)

    if mode == "audio":
        fmt   = "bestaudio/best"
        ext   = "mp3"
        label = "Audio MP3"
    else:
        fmt   = "bestvideo+bestaudio/best"
        ext   = "mp4"
        label = "Meilleure qualité"

    class _DownloadLogger:  # pylint: disable=too-few-public-methods
        """Logger yt-dlp : affiche uniquement les lignes [download]."""
        def debug(self, msg):
            """Affiche uniquement la progression du téléchargement."""
            if msg.startswith("[download]"):
                print(msg)
        def warning(self, msg):  # pylint: disable=unused-argument
            """Supprime les avertissements."""
        def error(self, msg):
            """Affiche les erreurs."""
            print(f"  \033[31m✖  {msg}\033[0m")

    ydl_opts = {
        "format":    fmt,
        "outtmpl":   os.path.join(dest_dir, "%(title)s.%(ext)s"),
        "noplaylist": True,
        "logger":    _DownloadLogger(),
        "quiet":     True,
        "no_warnings": True,
    }

    if ffmpeg_exe:
        ydl_opts["ffmpeg_location"] = os.path.dirname(ffmpeg_exe)
        if mode == "audio":
            ydl_opts["postprocessors"] = [{
                "key": "FFmpegExtractAudio",
                "preferredcodec": "mp3",
                "preferredquality": "192",
            }]
        else:
            ydl_opts["merge_output_format"] = "mp4"

    ConsoleUI.clear()
    print(ConsoleUI.BANNER)
    print(f"\n  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.BOLD}TÉLÉCHARGEMENT EN COURS{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.DIM}Format : {label}   —   Destination : {dest_dir}{ConsoleUI.RESET}")
    print(f"  {ConsoleUI.CYAN}{'─'*58}{ConsoleUI.RESET}\n")

    # Récupération des infos avant dl
    try:
        with yt_dlp.YoutubeDL({"quiet": True, "no_warnings": True,
                                "logger": _DownloadLogger()}) as ydl_q:
            info  = ydl_q.extract_info(url, download=False)
            titre = info.get("title", "Titre inconnu")
            duree = info.get("duration", 0)
            m, s  = divmod(int(duree), 60)

        ConsoleUI.info(f"Titre  : {titre}")
        ConsoleUI.info(f"Durée  : {m}m {s:02d}s")
        ConsoleUI.info(f"Format : {label}")
        ConsoleUI.sep()
    except Exception:  # pylint: disable=broad-except
        pass

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])

    ConsoleUI.result_screen([
        f"  {ConsoleUI.GREEN}✔  Téléchargement terminé !{ConsoleUI.RESET}",
        f"  {ConsoleUI.DIM}Format : {label}{ConsoleUI.RESET}",
        f"  {ConsoleUI.CYAN}📂  {dest_dir}{ConsoleUI.RESET}",
    ])


# ─────────────────────────────────────────────────────────────────────────────
# Menu téléchargement
# ─────────────────────────────────────────────────────────────────────────────
def menu_download(dest_dir, ffmpeg_exe):
    """Saisie de l'URL puis choix du format."""
    url = ConsoleUI.input_screen(
        "TÉLÉCHARGER UNE VIDÉO",
        "Collez le lien YouTube",
        subtitle="Exemple : https://www.youtube.com/watch?v=...",
    )

    if not url:
        return
    if not url.startswith(("http://", "https://")):
        ConsoleUI.result_screen([
            f"  {ConsoleUI.RED}✖  Lien invalide.{ConsoleUI.RESET}",
            f"  {ConsoleUI.DIM}Assurez-vous de coller une URL complète.{ConsoleUI.RESET}",
        ])
        return

    choice = ConsoleUI.navigate(
        [
            "🎬  Meilleure qualité  (vidéo + audio, MP4)",
            "🎵  Audio seulement  (MP3)",
            "🔙  Retour",
        ],
        "CHOISIR LE FORMAT",
        subtitle=f"URL : {url[:60]}{'…' if len(url) > 60 else ''}",
    )

    if choice == 2 or choice == -1:
        return

    mode = "video" if choice == 0 else "audio"

    try:
        do_download(url, mode, dest_dir[0], ffmpeg_exe)
    except KeyboardInterrupt:
        ConsoleUI.result_screen([
            f"  {ConsoleUI.YELLOW}⚠  Téléchargement annulé.{ConsoleUI.RESET}",
        ])
    except Exception as e:  # pylint: disable=broad-except
        ConsoleUI.result_screen([
            f"  {ConsoleUI.RED}✖  Erreur : {e}{ConsoleUI.RESET}",
            f"  {ConsoleUI.DIM}Vérifiez que la vidéo est publique et que l'URL est correcte.{ConsoleUI.RESET}",
        ])


# ─────────────────────────────────────────────────────────────────────────────
# Menu paramètres
# ─────────────────────────────────────────────────────────────────────────────
def menu_settings(dest_dir):
    """Menu de configuration."""
    while True:
        choice = ConsoleUI.navigate(
            [
                "📁  Changer le dossier de téléchargement",
                "📂  Ouvrir le dossier actuel",
                "🔙  Retour",
            ],
            "PARAMÈTRES",
            subtitle=f"Dossier : {dest_dir[0]}",
        )

        if choice in (-1, 2):
            return

        if choice == 0:
            new = ConsoleUI.input_screen(
                "DOSSIER DE TÉLÉCHARGEMENT",
                "Nouveau chemin complet",
                subtitle=f"Actuel : {dest_dir[0]}",
            )
            if new:
                try:
                    os.makedirs(new, exist_ok=True)
                    dest_dir[0] = os.path.abspath(new)
                    _save_config({"dest_dir": dest_dir[0]})
                    ConsoleUI.result_screen([
                        f"  {ConsoleUI.GREEN}✔  Dossier mis à jour !{ConsoleUI.RESET}",
                        f"  {ConsoleUI.CYAN}📂  {dest_dir[0]}{ConsoleUI.RESET}",
                    ])
                except Exception as e:  # pylint: disable=broad-except
                    ConsoleUI.result_screen([
                        f"  {ConsoleUI.RED}✖  Erreur : {e}{ConsoleUI.RESET}",
                    ])

        elif choice == 1:
            try:
                if os.name == "nt":
                    os.startfile(dest_dir[0])  # pylint: disable=no-member
                elif _is_termux():
                    subprocess.run(["termux-open", dest_dir[0]], check=False)
                else:
                    subprocess.run(["xdg-open", dest_dir[0]], check=False)
                time.sleep(1)
            except Exception as e:  # pylint: disable=broad-except
                ConsoleUI.result_screen([f"  {ConsoleUI.RED}✖  {e}{ConsoleUI.RESET}"])


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────────────────────────────────────
def main():  # pylint: disable=too-many-branches,too-many-statements
    """Point d'entrée principal."""
    ConsoleUI.enable_ansi()
    if os.name == "nt":
        os.system("title 🎬 CO-TUBE DOWNLOADER 🎬")

    # ── Écran de démarrage ────────────────────────────────────────────────────
    ConsoleUI.clear()
    print(ConsoleUI.BANNER)
    print(f"\n  {ConsoleUI.DIM}⏳ Chargement, veuillez patienter...{ConsoleUI.RESET}\n")

    steps    = [("yt-dlp + ffmpeg", setup_dependencies), ("FFmpeg", setup_ffmpeg)]
    results  = {}
    bar_w    = 40

    for idx, (label, fn) in enumerate(steps):
        pct    = int((idx / len(steps)) * 100)
        filled = pct * bar_w // 100
        pbar   = "█" * filled + "░" * (bar_w - filled)
        print(f"\r  {ConsoleUI.CYAN}[{pbar}]{ConsoleUI.RESET}  {label}...",
              end="", flush=True)
        results[label] = fn()

    pbar = "█" * bar_w
    print(f"\r  {ConsoleUI.CYAN}[{pbar}]{ConsoleUI.RESET}  Prêt !          ", flush=True)
    print()

    ffmpeg_exe = results["FFmpeg"]
    if not ffmpeg_exe:
        ConsoleUI.warn("FFmpeg introuvable — la fusion vidéo/audio sera désactivée.")

    # ── Dossier de téléchargement (config persistante) ────────────────────────
    cfg      = _load_config()
    saved    = cfg.get("dest_dir", "")
    fallback = _base_dir()          # dossier du script si rien dans la config
    initial  = saved if saved and os.path.isdir(os.path.dirname(saved) or ".") else fallback
    dest_dir = [initial]

    # ── Boucle principale ─────────────────────────────────────────────────────
    while True:
        choice = ConsoleUI.navigate(
            [
                "🎬  Télécharger une vidéo",
                "⚙️   Paramètres",
                "❌  Quitter",
            ],
            "MENU PRINCIPAL",
            f"v{VERSION}  —  Dossier : {dest_dir[0]}",
        )

        if choice == 0:
            menu_download(dest_dir, ffmpeg_exe)
        elif choice == 1:
            menu_settings(dest_dir)
        elif choice in (2, -1):
            ConsoleUI.result_screen([
                f"  {ConsoleUI.CYAN}👋  Merci d'avoir utilisé CO-TUBE !{ConsoleUI.RESET}",
                "  🎬  À bientôt !",
            ], pause=False)
            time.sleep(1)
            sys.exit(0)


def _goodbye():
    """Affiche le message d'au revoir et quitte proprement."""
    try:
        ConsoleUI.clear()
        print(ConsoleUI.CYAN + "\n  " + "═"*58 + ConsoleUI.RESET)
        print(f"  {ConsoleUI.CYAN}👋  Merci d'avoir utilisé CO-TUBE !{ConsoleUI.RESET}")
        print("  🎬  À bientôt !")
        print(ConsoleUI.CYAN + "  " + "═"*58 + ConsoleUI.RESET + "\n")
        time.sleep(1)
    except Exception:  # pylint: disable=broad-except
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
    except Exception as _e:  # pylint: disable=broad-except
        ConsoleUI.clear()
        print(ConsoleUI.RED + "\n\n  💥  ERREUR CRITIQUE\n" + ConsoleUI.RESET)
        print(f"  {_e}\n")
        traceback.print_exc()
        try:
            input("\n  Appuyez sur Entrée pour quitter...")
        except (EOFError, OSError):
            pass
        _goodbye()