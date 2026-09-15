import ctypes
import json
import os
import struct
import sys
import threading
import traceback
from ctypes import wintypes

WINDOW_TITLE = "一个神秘的小东西"
BIG_TITLE = "AOEIV天赋点修改"
DESC_TEXT = "胜利！请奖励我一个月饼"
BUTTON_TEXT = "即刻打开地狱之门"
PLACEHOLDER_COLOR = "#999999"
PLACEHOLDER_TEXT = "请输入当前天赋点数"
TARGET_PROCESS = "RelicCardinal.exe"
TARGET_VALUE = 114514
STATE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False) else __file__)),
    "aoe4_perk_tool_state.json")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.VirtualProtectEx.restype = wintypes.BOOL

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PAGE_EXECUTE_READWRITE = 0x40
WRITABLE_PROTECTS = {0x04, 0x08, 0x40, 0x80}
CLEAN_MIN = -1000
CLEAN_MAX = 100_000_000
CHUNK_SIZE = 1 << 20

class MemoryInfo(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                               ctypes.POINTER(MemoryInfo), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t

class ProcessEntry(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_char * 260)]

def find_pid(process_name):
    k32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    k32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    snapshot = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snapshot == -1:
        return None
    entry = ProcessEntry()
    entry.dwSize = ctypes.sizeof(ProcessEntry)
    pid = None
    if k32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.decode("mbcs", "ignore").lower() == process_name.lower():
                pid = entry.th32ProcessID
                break
            if not k32.Process32Next(snapshot, ctypes.byref(entry)):
                break
    k32.CloseHandle(snapshot)
    return pid

def iter_writable_regions(handle):
    address = 0
    info = MemoryInfo()
    while address < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(info),
                                  ctypes.sizeof(info)):
            break
        base = info.BaseAddress or 0
        size = info.RegionSize
        if size == 0:
            break
        if (info.State == MEM_COMMIT and info.Type == MEM_PRIVATE
                and info.Protect in WRITABLE_PROTECTS
                and not (info.Protect & PAGE_GUARD)
                and not (info.Protect & PAGE_NOACCESS)):
            yield base, size
        address = base + size

def read_bytes(handle, address, length):
    buffer = ctypes.create_string_buffer(length)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, length,
                             ctypes.byref(got)) and got.value == length:
        return buffer.raw
    return None

def read_qword(handle, address):
    raw = read_bytes(handle, address, 8)
    if raw is None:
        return None
    return struct.unpack("<Q", raw)[0]

def read_signed_qword(handle, address):
    unsigned = read_qword(handle, address)
    if unsigned is None:
        return None
    return struct.unpack("<q", struct.pack("<Q", unsigned))[0]

def read_number(handle, address, kind):
    length = 8 if kind == "int64" else 4
    raw = read_bytes(handle, address, length)
    if raw is None:
        return None
    return int.from_bytes(raw, "little", signed=True)

def scan_value(handle, value, kind, log):
    needle = struct.pack("<q", value) if kind == "int64" else struct.pack("<i", value)
    hits = []
    buffer = ctypes.create_string_buffer(CHUNK_SIZE)
    got = ctypes.c_size_t(0)
    for base, size in iter_writable_regions(handle):
        offset = 0
        while offset < size:
            length = min(len(buffer), size - offset)
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base + offset), buffer, length,
                                     ctypes.byref(got)) and got.value >= len(needle):
                data = buffer.raw[:got.value]
                start = 0
                while True:
                    index = data.find(needle, start)
                    if index < 0:
                        break
                    hits.append(base + offset + index)
                    start = index + 1
            offset += length
    log("  扫描 %s = %d -> %d 个候选" % (kind, value, len(hits)))
    return hits

def slot_signature(handle, address):
    slot = address - (address % 16)
    second = read_qword(handle, slot + 8)
    return (address % 16) == 0 and second is not None and (second >> 56) >= 0x80

def is_clean_number(value):
    return value is not None and CLEAN_MIN <= value < CLEAN_MAX

def neighbours_clean(handle, address):
    slot = address - (address % 16)
    return (is_clean_number(read_signed_qword(handle, slot - 16))
            and is_clean_number(read_signed_qword(handle, slot + 16)))

def neighbour_score(handle, address):
    slot = address - (address % 16)
    return sum(1 for delta in (-48, -32, -16, 16, 32, 48)
               if is_clean_number(read_signed_qword(handle, slot + delta)))

def pick_target(handle, candidates, log):
    signed = [a for a in candidates if slot_signature(handle, a)]
    log("    0x88 槽特征: %d 个" % len(signed))
    if not signed:
        log("    没有候选带真身特征 -> 不写")
        return None
    clean = [a for a in signed if neighbours_clean(handle, a)]
    log("    紧邻槽干净: %d 个" % len(clean))
    pool = clean or signed
    if len(pool) == 1:
        return pool[0]
    ranked = sorted(pool, key=lambda a: -neighbour_score(handle, a))
    top = neighbour_score(handle, ranked[0])
    if len(ranked) == 1 or neighbour_score(handle, ranked[1]) < top:
        log("    按邻域打分选中 0x%X（分 %d，次高 %d）"
            % (ranked[0], top, neighbour_score(handle, ranked[1])))
        return ranked[0]
    log("    多个候选同分，犹豫: %s" % ", ".join("0x%X" % a for a in ranked[:6]))
    return None

def write_value(handle, address, value, kind):
    needle = struct.pack("<q", value) if kind == "int64" else struct.pack("<i", value)
    old_protect = wintypes.DWORD()
    if not k32.VirtualProtectEx(handle, ctypes.c_void_p(address), len(needle),
                                PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
        return False
    written = ctypes.c_size_t(0)
    ok = bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(address), needle, len(needle),
                                     ctypes.byref(written))) and written.value == len(needle)
    k32.VirtualProtectEx(handle, ctypes.c_void_p(address), len(needle), old_protect,
                         ctypes.byref(old_protect))
    if ok:
        echo = ctypes.create_string_buffer(len(needle))
        got = ctypes.c_size_t(0)
        ok = (bool(k32.ReadProcessMemory(handle, ctypes.c_void_p(address), echo, len(needle),
                                         ctypes.byref(got)))
              and echo.raw == needle)
    return ok

def resource_path(name):
    root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, name)

def load_state():
    import glob
    paths = [STATE_FILE]
    paths += sorted(glob.glob(os.path.join(os.path.dirname(STATE_FILE),
                                           "aoe4_perk_tool_state_*.json")), reverse=True)
    state = {}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            break
        except Exception:
            continue
    if "last_input" not in state and "shang_ci_shuru" in state:
        state["last_input"] = state["shang_ci_shuru"]
    if "last_kind" not in state and "last_index" in state:
        state["last_kind"] = state["last_index"]
    return state

def save_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
    except Exception:
        pass

def apply_change(value, log, dry_run=False, debug=False):

    def note(text):
        if debug:
            log(text)

    pid = find_pid(TARGET_PROCESS)
    if not pid:
        return False, "没找到 %s。" % TARGET_PROCESS
    handle = k32.OpenProcess(0x1F0FFF, False, pid)
    if not handle:
        return False, "打不开游戏进程。"
    note("已连接 %s (pid %d)" % (TARGET_PROCESS, pid))

    chosen = None
    total_hits = 0
    for kind in ("int64", "int32"):
        hits = scan_value(handle, value, kind, note)
        total_hits += len(hits)
        if not hits:
            continue
        note("  %s 候选 %d 个 -> 结构判别:" % (kind, len(hits)))
        address = pick_target(handle, hits, note)
        if address is not None:
            chosen = (address, kind)
            break

    if not chosen:
        state = load_state()
        stored = state.get("last_addr")
        stored_kind = state.get("last_kind", "int64")
        if stored:
            stored_address = int(stored, 16)
            if (slot_signature(handle, stored_address)
                    and read_number(handle, stored_address, stored_kind) == value):
                log("用上次记录的地址命中: 0x%X" % stored_address)
                chosen = (stored_address, stored_kind)

    if not chosen:
        if value == TARGET_VALUE and total_hits:
            return False, "内存里已经是 %d。" % value
        if not total_hits:
            return False, "内存里找不到数值 %d。" % value
        return False, "无法确定唯一地址，请让点数变化后使用新数值"

    address, kind = chosen
    note("锁定地址 0x%X (%s)" % (address, kind))
    old_value = read_number(handle, address, kind)
    if old_value != value:
        return False, "那个地址的值不是 %d（读到 %s）。" % (value, old_value)
    if dry_run:
        log("[演示模式] 没有真的写入。")
        return True, "[演示模式] 定位成功：0x%X\n正式运行会写成 %d。" % (address, TARGET_VALUE)
    if not write_value(handle, address, TARGET_VALUE, kind):
        return False, "写入失败。"
    log("已写入 %d 并回读校验通过" % TARGET_VALUE)
    log("回游戏买/退一个天赋 → 退出炼狱模式回主菜单，才会写进存档")
    state = load_state()
    state["last_value"] = TARGET_VALUE
    state["last_addr"] = "0x%X" % address
    state["last_kind"] = kind
    state["last_new"] = TARGET_VALUE
    state["last_old"] = old_value
    state["last_input"] = value
    save_state(state)
    return True, "成功了！西八里耶！！！"

def undo_last_change(log):
    state = load_state()
    address_text = state.get("last_addr")
    old_value = state.get("last_old")
    new_value = state.get("last_new")
    kind = state.get("last_kind", "int64")
    if not address_text or old_value is None:
        return False, "没有上一次修改的记录。"
    pid = find_pid(TARGET_PROCESS)
    if not pid:
        return False, "没找到 %s。" % TARGET_PROCESS
    handle = k32.OpenProcess(0x1F0FFF, False, pid)
    if not handle:
        return False, "打不开游戏进程。"
    address = int(address_text, 16)
    current = read_number(handle, address, kind)
    if current is None or (new_value is not None and current != new_value):
        return False, "0x%X 的值不是我们写的（读到 %s）。" % (address, current)
    if not write_value(handle, address, int(old_value), kind):
        return False, "撤销失败。"
    log("已把 0x%X 还原成 %d" % (address, int(old_value)))
    state["last_addr"] = None
    state["last_old"] = None
    state["last_new"] = None
    save_state(state)
    return True, "已撤销：0x%X 还原成 %d。" % (address, int(old_value))

def run_gui():
    import tkinter as tk
    from tkinter import messagebox

    state = load_state()
    root = tk.Tk()
    root.title(WINDOW_TITLE)
    try:
        root.iconbitmap(resource_path("app_icon.ico"))
    except Exception:
        pass
    root.geometry("560x420")
    root.resizable(False, False)

    tk.Label(root, text=BIG_TITLE, font=("Microsoft YaHei UI", 15, "bold")).pack(pady=(14, 2))
    tk.Label(root, text=DESC_TEXT, font=("Microsoft YaHei UI", 9), fg="#666",
             justify="left").pack(anchor="w", padx=18)

    input_row = tk.Frame(root)
    input_row.pack(fill="x", padx=18, pady=(10, 6))
    input_var = tk.StringVar(value=PLACEHOLDER_TEXT)
    entry = tk.Entry(input_row, textvariable=input_var, width=20, font=("Consolas", 11),
                     fg=PLACEHOLDER_COLOR)
    entry.pack(side="left")

    def on_focus_in(_event=None):
        if input_var.get() == PLACEHOLDER_TEXT:
            input_var.set("")
        entry.config(fg="black")

    def on_focus_out(_event=None):
        if not input_var.get().strip():
            input_var.set(PLACEHOLDER_TEXT)
        entry.config(fg=PLACEHOLDER_COLOR if input_var.get() == PLACEHOLDER_TEXT else "black")

    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<Key>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)
    tk.Label(input_row, text="要和游戏界面上的数字完全一致",
             font=("Microsoft YaHei UI", 8), fg="#999").pack(side="left", padx=8)

    button_row = tk.Frame(root)
    button_row.pack(fill="x", padx=18)
    status_label = tk.Label(root, text="", font=("Microsoft YaHei UI", 10, "bold"))
    log_box = tk.Text(root, height=13, font=("Consolas", 8), bg="#f7f7f7", relief="flat")
    log_box.pack(fill="both", expand=True, padx=18, pady=(8, 14))

    def log(text):
        log_box.insert("end", text + "\n")
        log_box.see("end")
        root.update_idletasks()

    def show_popup(message, ok):
        if ok:
            messagebox.showinfo("完成", message, parent=root)
        else:
            messagebox.showwarning("注意", message, parent=root)

    def run_apply():
        apply_button.config(state="disabled")
        status_label.config(text="处理中…")

        def work():
            try:
                value = int(float(input_var.get().strip()))
            except Exception:
                def bad_input():
                    status_label.config(text="")
                    apply_button.config(state="normal")
                    messagebox.showwarning("注意", "请填一个数字", parent=root)
                root.after(0, bad_input)
                return
            try:
                ok, message = apply_change(value, lambda m: root.after(0, lambda m=m: log(m)))
            except Exception:
                ok, message = False, "出错：\n" + traceback.format_exc(limit=3)

            def finish():
                status_label.config(text="")
                apply_button.config(state="normal")
                show_popup(message, ok)

            root.after(0, finish)

        threading.Thread(target=work, daemon=True).start()

    apply_button = tk.Button(button_row, text=BUTTON_TEXT, command=run_apply,
                             font=("Microsoft YaHei UI", 12, "bold"), height=2, bg="#2d7",
                             fg="white", activebackground="#1a5")
    apply_button.pack(side="left", fill="x", expand=True)

    status_label.pack(fill="x", padx=18, pady=(10, 4))
    pid = find_pid(TARGET_PROCESS)
    log("游戏进程: %s" % (("已找到 %s (pid %d)" % (TARGET_PROCESS, pid)) if pid
                          else "未找到"))
    log("步骤:")
    log("  1) 游戏里打开 炼狱 -> 天赋界面")
    log("  2) 填当前点数")
    log("  3) 点按钮")
    log("  4) 回游戏买一个天赋并退出炼狱界面")
    root.mainloop()

def run_cli(value, dry_run=False, debug=False):
    ok, message = apply_change(value, lambda m: print(m), dry_run=dry_run, debug=debug)
    print(("OK: " if ok else "FAIL: ") + message)
    return 0 if ok else 1

if __name__ == "__main__":
    positional = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry_run = ("--dry-run" in sys.argv) or ("--yanshi" in sys.argv)
    debug = "--debug" in sys.argv
    if ("--undo" in sys.argv) or ("--chexiao" in sys.argv):
        ok, message = undo_last_change(lambda m: print(m))
        print(("OK: " if ok else "FAIL: ") + message)
        sys.exit(0 if ok else 1)
    if positional:
        sys.exit(run_cli(int(float(positional[0])), dry_run=dry_run, debug=debug))
    run_gui()
