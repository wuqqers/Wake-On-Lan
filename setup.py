import sys
from cx_Freeze import setup, Executable

# GUI uygulamaları için 'Win32GUI' kullanın
# Konsol uygulamaları için None kullanın
base = "Win32GUI" # main.py bir GUI uygulaması olduğu için Win32GUI kullanıyoruz

executables = [
    Executable("main.py", base=base, icon="./lan.ico", target_name="WakeonLan.exe")
]

setup(
    name = "WakeonLan",
    version = "0.1",
    description = "main.py uygulamasının çalıştırılabilir versiyonu",
    executables = executables,
    options = {"build_exe": {"include_files": ["translations.json", "lan.ico"]}}
)