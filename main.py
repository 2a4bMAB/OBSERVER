"""
OBSERVER — Application Entry Point
"""
import sys
import os

# Ensure the project root is in the Python path (important for PyInstaller)
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ── Logging setup ───────────────────────────────────────────────────────────
# Log file is written to %LOCALAPPDATA%\OBSERVER\observer.log
# This is readable even from the windowed .exe (no console).
import logging
from pathlib import Path

_log_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "OBSERVER"
_log_dir.mkdir(parents=True, exist_ok=True)
_log_file = _log_dir / "observer.log"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(_log_file, encoding="utf-8", mode="a"),
    ],
)
# Also log to console when launched via python main.py
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
logging.getLogger("observer").info("=" * 60)
logging.getLogger("observer").info("OBSERVER starting — log file: %s", _log_file)


# ── Fix: add Qt6 DLL directory to Windows DLL search path ──────────────────
# This resolves "DLL load failed while importing QtWidgets" on Windows
# when PyQt6-Qt6 is installed in a non-standard location.
def _add_qt6_dll_dirs():
    if not sys.platform.startswith("win"):
        return
    import site
    for sp in site.getsitepackages() + [site.getusersitepackages()]:
        qt6_bin = os.path.join(sp, "PyQt6", "Qt6", "bin")
        if os.path.isdir(qt6_bin):
            try:
                os.add_dll_directory(qt6_bin)
            except (OSError, AttributeError):
                pass

_add_qt6_dll_dirs()

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

from ui.design import theme as T
from ui.design.theme import Theme, set_theme


def main():
    # High-DPI support
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    app = QApplication(sys.argv)
    app.setApplicationName("OBSERVER")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("OBSERVER Security")

    # Set default dark theme
    set_theme(Theme.DARK)
    app.setStyleSheet(T.get_stylesheet())

    # Set window icon if available
    import pathlib
    icon_path = pathlib.Path(__file__).parent / "ui" / "design" / "assets" / "logo.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Launch main window
    from ui.app import MainWindow
    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
