import ctypes
import json
import os
import re
import struct
import sys
import threading
from contextlib import contextmanager
from ctypes import wintypes

WINDOW_TITLE = "一个神秘的小东西"
BIG_TITLE = "AOEIV天赋点修改"
SUCCESS_TITLE = "成功了！西八里耶！！！"
SUCCESS_BODY = "胜利！请奖励我一个月饼"
SETTLEMENT_TEXT = "停留在结算页面"
ZERO_XP_GUIDANCE = "请回游戏完成一局（常规模式中选择尽可能高难度挂机两分钟）"
TARGET_PROCESS = "RelicCardinal.exe"
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
PAGE_READWRITE = 0x04
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SCAN_ACCESS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
PROCESS_WRITE_ACCESS = PROCESS_SCAN_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
LAST_OPEN_ERROR = [0]
ACCESS_HINTS = {2: "找不到进程", 5: "拒绝访问", 87: "参数错误"}
WRITABLE_PROTECTS = {0x04, 0x08, 0x40, 0x80}
CLEAN_MIN = -1000
CLEAN_MAX = 100_000_000
CHUNK_SIZE = 1 << 20
MAX_STRUCTURED_CANDIDATES = 100_000
SCAN_VERSION = 2
STATE_LOCK = threading.RLock()
APP_CLOSING = threading.Event()

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

def scan_value(handle, value, kind, log, max_candidates=MAX_STRUCTURED_CANDIDATES):
    needle = struct.pack("<q", value) if kind == "int64" else struct.pack("<i", value)
    hits = []
    overlap = len(needle) - 1
    buffer = ctypes.create_string_buffer(CHUNK_SIZE + 2 * overlap)
    got = ctypes.c_size_t(0)
    for base, size in iter_writable_regions(handle):
        offset = 0
        while offset < size:
            if APP_CLOSING.is_set():
                raise RuntimeError("扫描已取消。")
            core_length = min(CHUNK_SIZE, size - offset)
            read_start = max(0, offset - overlap)
            read_end = min(size, offset + core_length + overlap)
            length = read_end - read_start
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base + read_start), buffer, length,
                                     ctypes.byref(got)) and got.value >= len(needle):
                data = buffer.raw[:got.value]
                start = 0
                while True:
                    index = data.find(needle, start)
                    if index < 0:
                        break
                    address = base + read_start + index
                    if base + offset <= address < base + offset + core_length:
                        hits.append(address)
                        if len(hits) >= max_candidates:
                            raise RuntimeError(
                                "当前数值的候选达到 %d 个，扫描已安全停止。" % max_candidates)
                    start = index + 1
            offset += core_length
    log("  扫描 %s = %d -> %d 个候选" % (kind, value, len(hits)))
    return hits

def is_slot_marker(marker):
    return marker is not None and (marker >> 56) in (0x80, 0x88)

def structured_slot_hits(data, base_address, value, pattern=None):
    hits = []
    if pattern is None:
        pattern = re.compile(re.escape(struct.pack("<q", value)) + b".{7}[\x80\x88]", re.DOTALL)
    for match in pattern.finditer(data):
        offset = match.start()
        if (base_address + offset) % 16 or offset < 16 or offset + 31 >= len(data):
            continue
        previous_value, previous_marker = struct.unpack_from("<qQ", data, offset - 16)
        next_value, next_marker = struct.unpack_from("<qQ", data, offset + 16)
        if (is_slot_marker(previous_marker) and is_slot_marker(next_marker)
                and is_clean_number(previous_value) and is_clean_number(next_value)):
            hits.append(base_address + offset)
    return hits

def scan_structured_int64(handle, value, log, max_candidates=MAX_STRUCTURED_CANDIDATES):
    hits = []
    pattern = re.compile(re.escape(struct.pack("<q", value)) + b".{7}[\x80\x88]", re.DOTALL)
    buffer = ctypes.create_string_buffer(CHUNK_SIZE + 32)
    got = ctypes.c_size_t(0)
    for base, size in iter_writable_regions(handle):
        offset = 0
        while offset < size:
            if APP_CLOSING.is_set():
                raise RuntimeError("扫描已取消。")
            core_length = min(CHUNK_SIZE, size - offset)
            read_start = max(0, offset - 16)
            read_end = min(size, offset + core_length + 16)
            length = read_end - read_start
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base + read_start), buffer, length,
                                     ctypes.byref(got)) and got.value >= 16:
                data = buffer.raw[:got.value]
                chunk_hits = structured_slot_hits(data, base + read_start, value, pattern)
                core_begin = base + offset
                core_end = core_begin + core_length
                core_hits = [address for address in chunk_hits
                             if core_begin <= address < core_end]
                remaining = max_candidates - len(hits)
                if len(core_hits) >= remaining:
                    raise RuntimeError(
                        "当前数值的结构候选达到 %d 个，扫描已安全停止。" % max_candidates)
                hits.extend(core_hits)
            offset += core_length
    log("  结构化 int64 = %d -> %d 个候选" % (value, len(hits)))
    return hits

def slot_signature(handle, address):
    slot = address - (address % 16)
    second = read_qword(handle, slot + 8)
    return (address % 16) == 0 and is_slot_marker(second)

def is_clean_number(value):
    return value is not None and CLEAN_MIN <= value < CLEAN_MAX

def neighbours_clean(handle, address):
    slot = address - (address % 16)
    return (is_clean_number(read_signed_qword(handle, slot - 16))
            and is_clean_number(read_signed_qword(handle, slot + 16)))

def is_valid_structured_slot(handle, address):
    if not slot_signature(handle, address):
        return False
    slot = address - (address % 16)
    return (neighbours_clean(handle, address)
            and is_slot_marker(read_qword(handle, slot - 8))
            and is_slot_marker(read_qword(handle, slot + 24)))

def write_value(handle, address, value, kind):
    needle = struct.pack("<q", value) if kind == "int64" else struct.pack("<i", value)
    old_protect = wintypes.DWORD()
    if not k32.VirtualProtectEx(handle, ctypes.c_void_p(address), len(needle),
                                PAGE_READWRITE, ctypes.byref(old_protect)):
        return False
    written = ctypes.c_size_t(0)
    ok = bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(address), needle, len(needle),
                                     ctypes.byref(written))) and written.value == len(needle)
    restored = bool(k32.VirtualProtectEx(
        handle, ctypes.c_void_p(address), len(needle), old_protect, ctypes.byref(old_protect)))
    if not restored:
        return False
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

def apply_window_icon(window):
    try:
        window.iconbitmap(resource_path("app_icon.ico"))
    except Exception:
        pass

def result_text_segments(message):
    if SETTLEMENT_TEXT not in message:
        return [(message, False)]
    before, after = message.split(SETTLEMENT_TEXT, 1)
    return [(before, False), (SETTLEMENT_TEXT, True), (after, False)]

def discard_log(_text):
    return None

def load_state():
    state = {}
    with STATE_LOCK:
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as handle:
                state = json.load(handle)
        except (OSError, ValueError, TypeError):
            state = {}
    return state

def save_state(state):
    with STATE_LOCK:
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as handle:
                json.dump(state, handle, separators=(",", ":"))
            return True
        except (OSError, TypeError, ValueError):
            return False

def reset_search_session(mode):
    if mode not in ("perk", "civilisation"):
        raise ValueError("未知功能模式")
    state = load_state()
    sessions = state.get("sessions")
    if isinstance(sessions, dict):
        sessions.pop(mode, None)
        if not sessions:
            state.pop("sessions", None)
    return save_state(state)

def xp_for_level(level):
    level = int(level)
    if not 0 <= level <= 15:
        raise ValueError("等级必须在 0 到 15 之间")
    return 10 * level * level + 90 * level

def poll_for_game_process(find_process, schedule, on_ready):
    pid = find_process()
    if pid:
        on_ready(pid)
        return
    schedule(1000, lambda: poll_for_game_process(find_process, schedule, on_ready))

def run_wait_animation(is_waiting, update, schedule, count=1):
    if not is_waiting():
        return
    next_count = count % 3 + 1
    update("等待游戏启动" + "·" * next_count)
    schedule(400, lambda: run_wait_animation(
        is_waiting, update, schedule, next_count))

def total_civilisation_xp(level, progress):
    level = int(level)
    progress = int(progress)
    if not 0 <= level <= 15:
        raise ValueError("等级必须在 0 到 15 之间")
    if level == 15:
        if progress != 0:
            raise ValueError("满级时当前点数必须为 0")
        return xp_for_level(15)
    required = 100 + 20 * level
    if not 0 <= progress < required:
        raise ValueError("等级 %d 的当前点数必须在 0 到 %d 之间" % (level, required - 1))
    return xp_for_level(level) + progress

def _session_state(state, mode, pid):
    sessions = state.setdefault("sessions", {})
    session = sessions.get(mode)
    if (not isinstance(session, dict) or session.get("pid") != pid
            or session.get("scan_version") != SCAN_VERSION):
        session = {"pid": pid, "scan_version": SCAN_VERSION}
        sessions[mode] = session
    return session

def _reset_session(session, pid):
    session.clear()
    session.update({"pid": pid, "scan_version": SCAN_VERSION})

@contextmanager
def process_handle(pid, access):
    handle = k32.OpenProcess(access, False, pid)
    LAST_OPEN_ERROR[0] = ctypes.get_last_error() if not handle else 0
    if not handle:
        yield None
        return
    try:
        yield handle
    finally:
        k32.CloseHandle(handle)

def access_error_message():
    code = LAST_OPEN_ERROR[0]
    hint = ACCESS_HINTS.get(code, "系统错误")
    return ("打不开游戏进程（%s，错误码 %d）。\n"
            "工具没能拿到写入权限，\n"
            "请关闭工具，右键选择「以管理员身份运行」后再试。" % (hint, code))

def _save_session(state, mode, session):
    state.setdefault("sessions", {})[mode] = session
    return save_state(state)

def locate_current_value(mode, value, log, debug=False):
    if mode not in ("perk", "civilisation"):
        raise ValueError("未知功能模式")
    value = int(value)
    pid = find_pid(TARGET_PROCESS)
    if not pid:
        return "error", "没找到 %s。" % TARGET_PROCESS
    state = load_state()
    session = _session_state(state, mode, pid)
    if mode == "civilisation" and value == 0:
        return "needs_change", ZERO_XP_GUIDANCE
    with process_handle(pid, PROCESS_SCAN_ACCESS) as handle:
        if not handle:
            return "error", access_error_message()
        return _locate_with_handle(mode, value, log, debug, pid, state, session, handle)

def _locate_with_handle(mode, value, log, debug, pid, state, session, handle):
    if debug:
        log("已连接 %s (pid %d)" % (TARGET_PROCESS, pid))

    stored_hits = session.get("hits") or []
    stored_value = session.get("value")
    kind = session.get("kind", "int64")
    if stored_hits and stored_value != value:
        candidates = [int(text, 16) for text in stored_hits]
        candidates = [address for address in candidates
                      if read_number(handle, address, kind) == value]
    elif stored_hits and stored_value == value:
        candidates = [int(text, 16) for text in stored_hits]
    else:
        try:
            candidates = scan_structured_int64(
                handle, value, log if debug else discard_log)
        except RuntimeError as exc:
            return "error", str(exc)
        kind = "int64"
        if not candidates and mode == "perk":
            try:
                candidates = scan_value(handle, value, "int64",
                                        log if debug else discard_log)
            except RuntimeError as exc:
                return "error", str(exc)

    candidates = [address for address in candidates
                  if is_valid_structured_slot(handle, address)]
    if not candidates:
        _reset_session(session, pid)
        if not _save_session(state, mode, session):
            return "error", "无法保存定位状态，请把软件放到可写目录后再试。"
        return "error", "没有找到符合结构的候选地址，请确认输入与游戏界面一致，或再试一次。"

    if len(candidates) != 1:
        session.update({
            "pid": pid,
            "scan_version": SCAN_VERSION,
            "value": value,
            "kind": kind,
            "hits": ["0x%X" % address for address in candidates],
        })
        session.pop("address", None)
        session.pop("located_value", None)
        if not _save_session(state, mode, session):
            return "error", "无法保存定位状态，请把软件放到可写目录后再试。"
        action = ("买或退一个天赋" if mode == "perk" else
                  "完成一局（常规模式中选择尽可能高难度挂机两分钟），停留在结算页面")
        return "needs_change", ("还剩 %d 个候选，暂不写入。\n请回游戏%s，"
                                "再输入变化后的数值再次定位。" % (len(candidates), action))

    address = candidates[0]
    session.update({
        "pid": pid,
        "scan_version": SCAN_VERSION,
        "value": value,
        "kind": kind,
        "hits": ["0x%X" % address],
        "address": "0x%X" % address,
        "located_value": value,
    })
    if not _save_session(state, mode, session):
        return "error", "无法保存定位状态，请把软件放到可写目录后再试。"
    with process_handle(pid, PROCESS_WRITE_ACCESS) as write_handle:
        can_write = bool(write_handle)
    if not can_write:
        return "located_no_write", ("定位成功：已唯一锁定地址 0x%X。\n但%s"
                                    % (address, access_error_message()))
    return "located", "定位成功：已唯一锁定地址 0x%X。" % address

def write_located_value(mode, target_value, log):
    target_value = int(target_value)
    if mode == "civilisation" and not 0 <= target_value <= xp_for_level(15):
        return False, "文明累计经验必须在 0 到 3600 之间。"
    pid = find_pid(TARGET_PROCESS)
    if not pid:
        return False, "没找到 %s。" % TARGET_PROCESS
    state = load_state()
    session = (state.get("sessions") or {}).get(mode) or {}
    if session.get("pid") != pid:
        return False, "游戏进程已经变化，请重新定位。"
    address_text = session.get("address")
    old_value = session.get("located_value")
    kind = session.get("kind", "int64")
    if not address_text or old_value is None:
        return False, "还没有唯一定位，请先完成定位。"
    with process_handle(pid, PROCESS_WRITE_ACCESS) as handle:
        if not handle:
            return False, access_error_message()
        return _write_with_handle(mode, target_value, log, state, session,
                                  address_text, old_value, kind, handle)

def _write_with_handle(mode, target_value, log, state, session,
                       address_text, old_value, kind, handle):
    address = int(address_text, 16)
    current = read_number(handle, address, kind)
    if current != old_value:
        return False, "目标地址已变化，请重新定位。"
    if not is_valid_structured_slot(handle, address):
        return False, "目标地址结构验证失败，请重新定位。"
    if not write_value(handle, address, target_value, kind):
        return False, "写入失败（错误码 %d）。" % ctypes.get_last_error()
    if read_number(handle, address, kind) != target_value:
        return False, "写入后的读回校验失败。"
    log("已向 0x%X 写入 %d，并通过读回校验" % (address, target_value))
    session["last_old"] = old_value
    session["last_new"] = target_value
    session["located_value"] = target_value
    session["value"] = target_value
    if not _save_session(state, mode, session):
        return False, "游戏内已经写入成功，但本地状态保存失败。"
    return True, SUCCESS_BODY

def run_main_gui(root=None, start_loop=True):
    import tkinter as tk
    from tkinter import messagebox

    if root is None:
        root = tk.Tk()
        root.withdraw()
    else:
        for child in root.winfo_children():
            child.destroy()
    root.title(WINDOW_TITLE)
    apply_window_icon(root)
    root.geometry("420x250")
    root.resizable(False, False)

    def close_app():
        APP_CLOSING.set()
        root.quit()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close_app)

    def post_ui(callback):
        if APP_CLOSING.is_set():
            return
        try:
            root.after(0, callback)
        except tk.TclError:
            pass

    tk.Label(root, text=BIG_TITLE, font=("Microsoft YaHei UI", 15, "bold")).pack(pady=(16, 12))

    mode_row = tk.Frame(root)
    mode_row.pack(fill="x", padx=18)

    def open_target_dialog(mode, owner):
        dialog = tk.Toplevel(owner)
        dialog.withdraw()
        apply_window_icon(dialog)
        dialog.title("设置修改目标")
        dialog.geometry("420x220")
        dialog.resizable(False, False)
        dialog.transient(owner)
        dialog.protocol("WM_DELETE_WINDOW", close_app)
        if mode == "perk":
            tk.Label(dialog, text="输入修改后的天赋点数",
                     font=("Microsoft YaHei UI", 12, "bold")).pack(pady=(22, 10))
            target_var = tk.StringVar(value="114514")
            tk.Entry(dialog, textvariable=target_var, font=("Consolas", 12),
                     justify="center").pack(ipady=5)
        else:
            tk.Label(dialog, text="输入想要修改到的文明等级",
                     font=("Microsoft YaHei UI", 12, "bold")).pack(pady=(22, 8))
            target_var = tk.StringVar(value="15")
            tk.Spinbox(dialog, from_=0, to=15, textvariable=target_var,
                       font=("Consolas", 12), justify="center", width=10).pack(ipady=4)

        status = tk.Label(dialog, text="", font=("Microsoft YaHei UI", 9, "bold"))
        status.pack(pady=4)

        def write_target():
            try:
                raw = int(target_var.get().strip())
                target = raw if mode == "perk" else xp_for_level(raw)
                if mode == "perk" and target < 0:
                    raise ValueError("天赋点不能为负数")
            except Exception as exc:
                messagebox.showwarning("注意", str(exc) or "请输入有效数字", parent=dialog)
                return
            write_button.config(state="disabled")
            status.config(text="正在写入并校验……")

            def work():
                try:
                    ok, message = write_located_value(mode, target, discard_log)
                except Exception:
                    ok, message = False, "写入失败，请关闭本窗口后再试一次。"

                def finish():
                    status.config(text="")
                    write_button.config(state="normal")
                    if ok:
                        messagebox.showinfo(SUCCESS_TITLE, message, parent=dialog)
                        dialog.destroy()
                        owner.destroy()
                    else:
                        messagebox.showwarning("注意", message, parent=dialog)
                post_ui(finish)
            threading.Thread(target=work, daemon=True).start()

        write_button = tk.Button(dialog, text="确认修改", command=write_target,
                                 font=("Microsoft YaHei UI", 11, "bold"), bg="#2d7",
                                 fg="white", width=18)
        write_button.pack(pady=8)
        dialog.update_idletasks()
        dialog.deiconify()
        dialog.lift()
        dialog.grab_set()

    def open_locator(mode):
        dialog = tk.Toplevel(root)
        dialog.withdraw()
        apply_window_icon(dialog)
        dialog.title("定位天赋点" if mode == "perk" else "定位文明等级")
        dialog.geometry("500x290" if mode == "perk" else "500x340")
        dialog.resizable(False, False)
        dialog.transient(root)
        dialog.protocol("WM_DELETE_WINDOW", close_app)
        tk.Label(dialog, text=("输入游戏界面当前显示的天赋点数" if mode == "perk" else
                              "当前等级和当前等级内点数必须同时填写"),
                 font=("Microsoft YaHei UI", 13, "bold")).pack(pady=(18, 5))
        if mode == "civilisation":
            tk.Label(dialog, text="没玩过的民族是0级",
                     font=("Microsoft YaHei UI", 9), fg="#666").pack(pady=(2, 0))

        fields = tk.Frame(dialog)
        fields.pack(pady=16)
        if mode == "perk":
            current_var = tk.StringVar()
            tk.Label(fields, text="当前天赋点数：").grid(row=0, column=0, padx=5, pady=5)
            tk.Entry(fields, textvariable=current_var, font=("Consolas", 11),
                     width=16).grid(row=0, column=1, padx=5, pady=5)
            level_var = progress_var = None
        else:
            level_var = tk.StringVar()
            progress_var = tk.StringVar()
            current_var = None
            tk.Label(fields, text="当前等级：").grid(row=0, column=0, padx=5, pady=5)
            tk.Spinbox(fields, from_=0, to=15, textvariable=level_var,
                       font=("Consolas", 11), width=14).grid(row=0, column=1, padx=5, pady=5)
            tk.Label(fields, text="当前等级内点数：").grid(row=1, column=0, padx=5, pady=5)
            tk.Entry(fields, textvariable=progress_var, font=("Consolas", 11),
                     width=16).grid(row=1, column=1, padx=5, pady=5)

        result_box = tk.Text(dialog, height=4, width=58, wrap="word", relief="flat",
                             bg=dialog.cget("bg"), font=("Microsoft YaHei UI", 9),
                             cursor="arrow")
        result_box.pack(pady=8)

        def show_result(message, colour):
            result_box.config(state="normal")
            result_box.delete("1.0", "end")
            result_box.tag_configure("normal", foreground=colour,
                                     font=("Microsoft YaHei UI", 9))
            result_box.tag_configure("bold", foreground=colour,
                                     font=("Microsoft YaHei UI", 9, "bold"))
            for text, bold in result_text_segments(message):
                result_box.insert("end", text, "bold" if bold else "normal")
            result_box.config(state="disabled")

        def restart_search():
            if not reset_search_session(mode):
                messagebox.showwarning(
                    "注意", "无法清除搜索数据，请把软件放到可写目录后再试。", parent=dialog)
                return
            locate_button.config(text="定位 / 继续定位", state="normal")
            next_button.config(state="disabled")
            show_result("", "#777")

        button_row = tk.Frame(dialog)
        button_row.pack(pady=10)

        def locate():
            try:
                if mode == "perk":
                    value = int(current_var.get().strip())
                else:
                    value = total_civilisation_xp(level_var.get().strip(),
                                                   progress_var.get().strip())
            except Exception as exc:
                messagebox.showwarning("注意", str(exc) or "请输入有效数字", parent=dialog)
                return
            locate_button.config(state="disabled")
            restart_button.config(state="disabled")
            next_button.config(state="disabled")
            show_result("正在扫描，请稍候……", "#555")

            def work():
                try:
                    status, message = locate_current_value(
                        mode, value, discard_log)
                except Exception:
                    status, message = "error", "扫描失败，请关闭本窗口后再试一次。"

                def finish():
                    locate_button.config(state="normal")
                    restart_button.config(state="normal")
                    show_result(message, "#16803c" if status == "located" else "#a65b00")
                    if status == "located":
                        next_button.config(state="normal")
                    elif status in ("error", "located_no_write"):
                        messagebox.showwarning("注意", message, parent=dialog)
                post_ui(finish)
            threading.Thread(target=work, daemon=True).start()

        locate_button = tk.Button(button_row, text="定位 / 继续定位", command=locate,
                                  font=("Microsoft YaHei UI", 10, "bold"), width=16)
        locate_button.pack(side="left", padx=6)
        next_button = tk.Button(button_row, text="下一步", state="disabled",
                                command=lambda: open_target_dialog(mode, dialog),
                                font=("Microsoft YaHei UI", 10, "bold"), width=9,
                                bg="#2d7", fg="white")
        next_button.pack(side="left", padx=6)
        restart_button = tk.Button(button_row, text="从头搜索", command=restart_search,
                                   font=("Microsoft YaHei UI", 10), width=9)
        restart_button.pack(side="left", padx=6)
        dialog.update_idletasks()
        dialog.deiconify()
        dialog.lift()
        dialog.grab_set()
    perk_button = tk.Button(mode_row, text="修改炼狱天赋点",
                            command=lambda: open_locator("perk"),
                            font=("Microsoft YaHei UI", 12, "bold"), height=3,
                            bg="#2d7", fg="white")
    perk_button.pack(fill="x", pady=(0, 8))
    civ_button = tk.Button(mode_row, text="修改特定文明等级",
                           command=lambda: open_locator("civilisation"),
                           font=("Microsoft YaHei UI", 12, "bold"), height=3,
                           bg="#478ad1", fg="white")
    civ_button.pack(fill="x")

    root.update_idletasks()
    root.deiconify()
    root.lift()
    if start_loop:
        root.mainloop()

def run_gui():
    import tkinter as tk

    APP_CLOSING.clear()
    root = tk.Tk()
    root.withdraw()
    root.title(WINDOW_TITLE)
    apply_window_icon(root)
    root.geometry("460x180")
    root.resizable(False, False)

    def close_app():
        APP_CLOSING.set()
        root.quit()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close_app)

    tk.Label(root, text=BIG_TITLE,
             font=("Microsoft YaHei UI", 15, "bold")).pack(pady=(34, 8))
    status = tk.Label(root, text="等待游戏启动…",
                      font=("Microsoft YaHei UI", 12, "bold"), fg="#478ad1")
    status.pack(pady=10)

    waiting = {"active": True}

    def show_main(pid):
        waiting["active"] = False
        root.withdraw()
        run_main_gui(root=root, start_loop=False)

    run_wait_animation(lambda: waiting["active"],
                       lambda text: status.config(text=text), root.after)
    poll_for_game_process(lambda: find_pid(TARGET_PROCESS), root.after, show_main)
    root.update_idletasks()
    root.deiconify()
    root.lift()
    root.mainloop()

if __name__ == "__main__":
    run_gui()
