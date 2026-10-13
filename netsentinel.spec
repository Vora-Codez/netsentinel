# Build: pyinstaller netsentinel.spec   ->  dist/NetSentinel.exe (one file)
from PyInstaller.utils.hooks import collect_submodules

hidden = collect_submodules("scapy") + ["waitress"]
a = Analysis(
    ["launcher.py"],
    pathex=["."],
    datas=[("netsentinel/web/templates", "netsentinel/web/templates"),
           ("netsentinel/web/static", "netsentinel/web/static")],
    hiddenimports=hidden,
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PIL"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [],
          name="NetSentinel", console=True, upx=False,
          icon="assets/icon.ico")
