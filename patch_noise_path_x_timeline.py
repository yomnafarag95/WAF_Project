import py_compile
import shutil
import sys

PATH = "src/capture/capture_addon.py"

old = '    "/ajax/bulk-route-definitions/",\n)'
new = '    "/ajax/bulk-route-definitions/",\n    "/i/api/1.1/flow/timeline.json",\n)'

with open(PATH, "r", encoding="utf-8") as f:
    content = f.read()

count = content.count(old)
if count != 1:
    print(f"ABORT: expected exactly 1 match of the NOISE_PATH_SUBSTRINGS closing anchor in {PATH}, found {count}. No changes made.")
    sys.exit(1)

backup = PATH + ".bak_xtimelinefix"
shutil.copy(PATH, backup)

new_content = content.replace(old, new, 1)
with open(PATH, "w", encoding="utf-8") as f:
    f.write(new_content)

print("Applied: add '/i/api/1.1/flow/timeline.json' to NOISE_PATH_SUBSTRINGS")

try:
    py_compile.compile(PATH, doraise=True)
except py_compile.PyCompileError as e:
    shutil.copy(backup, PATH)
    print(f"COMPILE FAILED on {PATH}, reverted: {e}")
    sys.exit(1)

print("SUCCESS: patch applied and file compiles cleanly.")
print(f"Backup saved at: {backup}")
