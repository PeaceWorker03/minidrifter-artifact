# -*- coding: utf-8 -*-
"""
Windows 微信 4.x 小程序面板：搜索结果点击采集器

流程：
1. 定位小程序面板。
2. 首页判定：同时出现「最近使用」和「我的常用」→ 这是首页。
   首页只搜索：点右上角放大镜，输入关键词。绝不在首页批量点图标。
3. 搜索结果（3 列卡片）：按从左到右、从上到下点击。
   不拖滚动条时最多约 11 行；点完第 11 行后把右侧拉拽条只上下拖到底
   （X 锁死，禁止左右）。若到底仍凑不满 50，立刻搜下一个词。
4. 本词结束后一次拖回顶部，确认能看到「小程序」和搜索框，再搜下一个词。
5. 每点开一个：等待窗口 → 驻留 2 秒 → 关闭 → 窗口消失后再点下一个，防止进程堆叠。
6. 被无关页覆盖（广告、「微信 Windows 版」下载页等）：识别后点击顶栏
   从左往右第二个页签「{关键词}_搜索」，直到回到搜索结果。绝不点第一个「小程序」。
7. 搜索词无限变异且不重复：每搜完一个立刻生成新词；队列将尽时从组合空间补词。

紧急停止：鼠标甩到屏幕左上角。
"""
from __future__ import annotations

import argparse
import ctypes
import itertools
import json
import multiprocessing
import os
import string
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    import pyautogui
    import pyperclip
    from pywinauto import Desktop
except ImportError:
    print("缺少依赖: pip install pyautogui pyperclip pywinauto", file=sys.stderr)
    raise SystemExit(2)

print("[open_miniprograms_ui] deps ok", flush=True)

TOOLS_DIR = Path(__file__).resolve().parent
LOG_FILE = TOOLS_DIR / "_clickonly_run.log"
DEFAULT_PROGRESS = TOOLS_DIR / "_clickonly_progress.json"
LOCK_FILE = TOOLS_DIR / "_clickonly.lock"
SCAN_TIMEOUT = 2.0          # 整树扫描上限；宁可跳屏，也不长时间卡死
RECT_TIMEOUT = 0.35         # 仅个别可疑调用才用线程超时
WRAP_TIMEOUT = 1.6          # UIA wrap 超时，避免「连接 UIA」永久卡住
WATCHDOG_SEC = 55           # 真死锁才重启；等待期间会打心跳，避免误杀
WORKER_STALL_EXIT = 75      # 看门狗退出码：父进程应重启
EMPTY_SCROLL_BURST = 2      # 空屏时一次连翻几屏，少做 UIA
HOME_SECTION_TITLES = frozenset({"最近使用", "我的常用"})
VISIBLE_RESULT_ROWS = 11    # 不拖滚动条时搜索结果大约可见行数
RESULT_COLS = 3             # 搜索结果每行 3 个（末行可能不足）

# -----------------------------------------------------------------------------
# Win32
# -----------------------------------------------------------------------------

user32 = ctypes.windll.user32
EnumWindows = user32.EnumWindows
GetWindowTextW = user32.GetWindowTextW
GetClassNameW = user32.GetClassNameW
IsWindowVisible = user32.IsWindowVisible
GetWindowRect = user32.GetWindowRect
SetForegroundWindow = user32.SetForegroundWindow
ShowWindow = user32.ShowWindow
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
PostMessageW = user32.PostMessageW
IsWindow = user32.IsWindow
SendMessageTimeoutW = user32.SendMessageTimeoutW
IsHungAppWindow = user32.IsHungAppWindow

WM_GETTEXT = 0x000D
WM_NULL = 0x0000
SMTO_ABORTIFHUNG = 0x0002

EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
WM_CLOSE = 0x0010
SW_RESTORE = 9
PANE_CLASS = "Chrome_WidgetWin_0"


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


GetCursorPos = user32.GetCursorPos
SetCursorPos = user32.SetCursorPos
mouse_event = user32.mouse_event
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
WHEEL_DELTA = 120
WM_VSCROLL = 0x0115
SB_LINEUP = 0
SB_LINEDOWN = 1
SB_PAGEUP = 2
SB_PAGEDOWN = 3
SB_TOP = 6
SB_BOTTOM = 7
OBJID_VSCROLL = -5
SM_CXVSCROLL = 2
SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
GWL_STYLE = -16
SBS_VERT = 0x0001
STATE_SYSTEM_INVISIBLE = 0x8000
SCROLLBAR_X_INSET = 6  # 估算滑条时的备用 inset；真正拖动以 Win32 滑条矩形为准


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class INPUT(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("mi", MOUSEINPUT),
    ]


class SCROLLBARINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("rcScrollBar", RECT),
        ("dxyLineButton", ctypes.c_int),
        ("xyThumbTop", ctypes.c_int),
        ("xyThumbBottom", ctypes.c_int),
        ("reserved", ctypes.c_int),
        ("rgstate", ctypes.c_uint * 6),
    ]


user32.SendInput.argtypes = (wintypes.UINT, ctypes.c_void_p, ctypes.c_int)
user32.SendInput.restype = wintypes.UINT
user32.GetScrollBarInfo.argtypes = (wintypes.HWND, ctypes.c_long, ctypes.c_void_p)
user32.GetScrollBarInfo.restype = wintypes.BOOL
EnumChildWindows = user32.EnumChildWindows
EnumChildProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)


_DESKTOP: Desktop | None = None
_LOG_FP = None
_BEAT = time.monotonic()


def heartbeat() -> None:
    global _BEAT
    _BEAT = time.monotonic()


def _join_with_heartbeat(th: threading.Thread, timeout: float) -> bool:
    """等线程结束；等待期间持续心跳，避免看门狗把正常等待当死锁。"""
    deadline = time.monotonic() + max(0.05, timeout)
    while th.is_alive() and time.monotonic() < deadline:
        heartbeat()
        th.join(0.12)
    return not th.is_alive()


def start_watchdog(seconds: float = WATCHDOG_SEC) -> None:
    """主线程若卡在 UIA/Win32 里不再打日志，到点自杀，让父进程接着进度重启。"""

    def loop() -> None:
        while True:
            time.sleep(4)
            age = time.monotonic() - _BEAT
            if age > seconds:
                try:
                    print(f"看门狗：{age:.0f}s 无进度，重启进程", flush=True)
                except Exception:
                    pass
                os._exit(WORKER_STALL_EXIT)

    threading.Thread(target=loop, daemon=True, name="click-watchdog").start()

SKIP_TITLES = {
    "小程序", "搜索小程序", "清空历史", "更多", "最近使用", "我的常用", "上次使用",
    "小游戏", "AI服务", "资讯文娱", "精选短剧", "取消", "搜索", "微信", "Weixin",
    "WeChat", "最小化", "最大化", "关闭", "重新加载", "使用过的小程序", "更多小程序",
}

# 点开后出现的假窗口/更新页（截图里的「请更新微信」/「E_搜索」）
JUNK_TITLE_MARKERS = (
    "更新微信", "版本较低", "无法使用该功能", "请更新后使用",
    "微信 Windows 版", "WeChat for Windows",
)

# 同一面板里打开的无关页（下载页、更新页等），靠文案识别
IRRELEVANT_PAGE_MARKERS = (
    "微信 Windows 版",
    "WeChat for Windows",
    "适用于 Windows",
    "多桌面端统一",
    "下载 4.",
    "请更新微信",
    "请更新后使用",
    "版本较低",
    "无法使用该功能",
)


def is_search_tab_name(name: str, keyword: str = "") -> bool:
    n = (name or "").strip()
    if not n:
        return False
    if keyword and n in {f"{keyword}_搜索", f"{keyword}_search"}:
        return True
    return n.endswith("_搜索") or n.endswith("_search")


def names_look_irrelevant(names: Iterable[str]) -> bool:
    for n in names:
        s = (n or "").strip()
        if not s:
            continue
        for m in IRRELEVANT_PAGE_MARKERS:
            if m in s:
                return True
    return False


def is_junk_window_title(title: str) -> bool:
    t = (title or "").strip()
    if not t:
        return True
    if any(m in t for m in JUNK_TITLE_MARKERS):
        return True
    # 搜索词页签，例如 E_搜索 / 北京_搜索，不是真正小程序
    if t.endswith("_搜索") or t.endswith("_search"):
        return True
    if t in {"支持", "微信团队", "WeChat Support"}:
        return True
    return False

CITIES = [
    "北京", "上海", "广州", "深圳", "杭州", "成都", "重庆", "武汉", "西安", "南京",
    "苏州", "天津", "长沙", "郑州", "青岛", "厦门", "福州", "东莞", "佛山", "合肥",
    "济南", "大连", "沈阳", "哈尔滨", "长春", "石家庄", "太原", "南昌", "昆明", "南宁",
    "海口", "贵阳", "兰州", "宁波", "无锡", "温州", "金华", "珠海", "中山", "惠州",
    "烟台", "潍坊", "洛阳", "宜昌", "绵阳", "泉州", "桂林", "保定", "唐山", "香港",
    "澳门", "台北",
]

INDUSTRY = [
    "点餐", "外卖", "快递", "医院", "挂号", "停车", "充电", "租车", "打车", "公交",
    "地铁", "银行", "保险", "证券", "理财", "支付", "会员", "商城", "购物", "酒店",
    "门票", "景区", "旅游", "校园", "教育", "政务", "缴费", "物业", "家政", "美容",
    "健身", "阅读", "小说", "短剧", "游戏", "办公", "会议", "考勤", "发票", "快递柜",
    "社区", "水费", "电费", "燃气", "医保", "社保", "公积金", "充电桩", "洗车", "加油",
    "药店", "口腔", "体检", "宠物", "奶茶", "咖啡", "火锅", "超市", "租房", "违章",
    "积分", "优惠券", "团购", "报名", "签到", "问卷", "直播", "驾考", "年检", "物流",
]

# 用于城市/行业交叉扩展，控制组合数量。
CORE_INDUSTRY = [
    "医院", "挂号", "银行", "商城", "购物", "酒店", "旅游", "景区", "教育", "校园",
    "政务", "物业", "社区", "停车", "充电", "公交", "地铁", "快递", "外卖", "点餐",
    "药店", "口腔", "体检", "超市", "咖啡", "奶茶", "租房", "加油", "洗车", "物流",
]

NAMING_WORDS = [
    "小程序", "服务", "助手", "管家", "智慧", "云", "易", "掌上", "微", "爱",
    "优", "快", "通", "达", "家", "生活", "便民", "市民", "政府", "大厅",
    "中心", "平台", "系统", "管理", "查询", "办理", "预约", "商城", "官方", "会员",
    "悦", "惠", "享", "乐", "购", "宝", "新", "好", "小", "大",
]

SEARCH_PREFIXES = [
    "附近", "网上", "在线", "官方", "智慧", "掌上", "本地", "便民", "市民", "快捷",
]

SEARCH_SUFFIXES = [
    "助手", "管家", "通", "宝", "服务", "平台", "查询", "办理", "预约", "商城",
]

PROVINCES = [
    "广东", "浙江", "江苏", "山东", "四川", "河南", "湖北", "湖南", "河北", "福建",
    "安徽", "辽宁", "陕西", "江西", "云南", "广西", "山西", "贵州", "吉林", "甘肃",
    "内蒙古", "新疆", "海南", "宁夏", "青海", "西藏",
]


# -----------------------------------------------------------------------------
# 基础工具
# -----------------------------------------------------------------------------

def log(msg: str) -> None:
    global _LOG_FP
    heartbeat()
    print(msg, flush=True)

    def _to_file() -> None:
        global _LOG_FP
        try:
            if _LOG_FP is None:
                _LOG_FP = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
            if _LOG_FP:
                _LOG_FP.write(msg if msg.endswith("\n") else msg + "\n")
        except OSError:
            _LOG_FP = False

    threading.Thread(target=_to_file, daemon=True).start()


def unique(seq: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        s = str(x).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def save_progress(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # 紧凑 JSON：进度频繁写盘时明显更快
    tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    last_err: OSError | None = None
    for i in range(8):
        try:
            tmp.replace(path)
            return
        except OSError as e:
            last_err = e
            time.sleep(0.15 * (i + 1))
    if last_err:
        raise last_err


def load_progress(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        x = json.loads(path.read_text(encoding="utf-8"))
        return x if isinstance(x, dict) else {}
    except Exception:
        return {}


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        h = user32.OpenProcess(0x1000, False, pid)
        if h:
            user32.CloseHandle(h)
            return True
    except Exception:
        pass
    return False


def acquire_single_instance() -> None:
    """避免重复启动两个实例互相卡住 UIA。"""
    if LOCK_FILE.exists():
        try:
            old = int(LOCK_FILE.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            old = 0
        if old and pid_alive(old):
            raise RuntimeError(f"已有实例在运行 (PID {old})，请勿重复启动。")
        LOCK_FILE.unlink(missing_ok=True)
    LOCK_FILE.write_text(str(os.getpid()), encoding="utf-8")


def release_single_instance() -> None:
    try:
        if LOCK_FILE.exists() and LOCK_FILE.read_text(encoding="utf-8").strip() == str(os.getpid()):
            LOCK_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def reset_uia() -> None:
    """UIA COM 失效后丢掉旧 Desktop，下次重新连接。"""
    global _DESKTOP
    _DESKTOP = None


def is_com_dead(err: BaseException) -> bool:
    if isinstance(err, TimeoutError):
        return True
    s = str(err)
    return "2147220991" in s or "事件无法调用任何订户" in s or "COMError" in type(err).__name__


def click_xy(x: int, y: int) -> None:
    pyautogui.click(int(x), int(y))


def click_elem_xy(elem: Any, timeout: float = 0.4) -> bool:
    """优先坐标点击，避免 click_input 把 UIA COM 打挂。"""
    r = timed_rectangle(elem, timeout=timeout)
    if r is None:
        try:
            r = elem.rectangle()
        except Exception:
            return False
    try:
        click_xy((int(r.left) + int(r.right)) // 2, (int(r.top) + int(r.bottom)) // 2)
        return True
    except Exception:
        return False


def hwnd_responsive(hwnd: int, timeout_ms: int = 30) -> bool:
    """无响应窗口上 GetClassNameW 会把主线程卡死，先用可超时的空消息探测。"""
    result = wintypes.DWORD()
    try:
        return bool(
            SendMessageTimeoutW(
                int(hwnd), WM_NULL, 0, 0, SMTO_ABORTIFHUNG, timeout_ms, ctypes.byref(result)
            )
        )
    except Exception:
        return False


def hwnd_title(hwnd: int, timeout_ms: int = 80) -> str:
    """读标题必须可超时：无响应窗口上的 GetWindowTextW 会把整个点击循环卡死。"""
    buf = ctypes.create_unicode_buffer(512)
    result = wintypes.DWORD()
    try:
        ok = SendMessageTimeoutW(
            hwnd, WM_GETTEXT, 512, buf, SMTO_ABORTIFHUNG, timeout_ms, ctypes.byref(result)
        )
        if not ok:
            return ""
        return (buf.value or "").strip()
    except Exception:
        return ""


def hwnd_class(hwnd: int) -> str:
    if not hwnd_responsive(hwnd, 25):
        return ""
    cbuf = ctypes.create_unicode_buffer(256)
    try:
        GetClassNameW(hwnd, cbuf, 256)
        return cbuf.value or ""
    except Exception:
        return ""


def enum_hwnds(
    title: str | None = None,
    class_name: str | None = None,
    require_responsive: bool = True,
    title_in: set[str] | None = None,
) -> list[int]:
    found: list[int] = []

    def cb(hwnd, _lparam):
        heartbeat()
        if not IsWindowVisible(hwnd):
            return True
        if require_responsive and not hwnd_responsive(int(hwnd), 20):
            return True
        cls = hwnd_class(int(hwnd))
        if class_name is not None and cls != class_name:
            return True
        t = hwnd_title(int(hwnd), timeout_ms=40)
        if title is not None and t != title:
            return True
        if title_in is not None and t not in title_in:
            return True
        found.append(int(hwnd))
        return True

    def run() -> None:
        try:
            EnumWindows(EnumWindowsProc(cb), 0)
        except Exception:
            pass

    th = threading.Thread(target=run, daemon=True)
    th.start()
    if not _join_with_heartbeat(th, 6.0):
        log("  枚举窗口超时，使用已扫到的结果")
    return found


def hwnd_rect(hwnd: int) -> tuple[int, int, int, int]:
    rc = RECT()
    GetWindowRect(hwnd, ctypes.byref(rc))
    return rc.left, rc.top, rc.right, rc.bottom


def hwnd_size(hwnd: int) -> tuple[int, int]:
    l, t, r, b = hwnd_rect(hwnd)
    return r - l, b - t


def hwnd_pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value)


def desktop() -> Desktop:
    global _DESKTOP
    if _DESKTOP is None:
        _DESKTOP = Desktop(backend="uia")
    return _DESKTOP


def wrap(hwnd: int, timeout: float = WRAP_TIMEOUT) -> Any:
    hwnd = int(hwnd)
    box: list[Any] = []
    err: list[BaseException] = []

    def worker() -> None:
        try:
            box.append(desktop().window(handle=hwnd))
        except Exception as e:
            err.append(e)

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    if not _join_with_heartbeat(th, max(0.4, timeout)):
        log("  UIA wrap 超时，丢弃旧连接")
        reset_uia()
        raise TimeoutError("UIA wrap hung")
    if err:
        e = err[0]
        if is_com_dead(e):
            reset_uia()
            box.clear()
            err.clear()
            th2 = threading.Thread(target=worker, daemon=True)
            th2.start()
            if not _join_with_heartbeat(th2, max(0.4, timeout)) or err:
                reset_uia()
                raise TimeoutError("UIA wrap COM retry failed")
            if box:
                return box[0]
        raise e
    if not box:
        raise TimeoutError("UIA wrap empty")
    return box[0]


def focus_hwnd(hwnd: int, delay: float = 0.01) -> None:
    """把面板拉到前台。用 Alt 技巧绕过前台限制，不用 AttachThreadInput（会卡死并打坏 UIA）。"""
    if not hwnd or not IsWindow(hwnd):
        return
    ShowWindow(hwnd, SW_RESTORE)
    try:
        user32.BringWindowToTop(hwnd)
    except Exception:
        pass
    try:
        # ALT down / up：允许 SetForegroundWindow
        user32.keybd_event(0x12, 0, 0, 0)
        SetForegroundWindow(hwnd)
        user32.keybd_event(0x12, 0, 2, 0)
    except Exception:
        try:
            SetForegroundWindow(hwnd)
        except Exception:
            pass
    if delay:
        time.sleep(delay)


def pane_focus_xy(hwnd: int) -> tuple[int, int] | None:
    """用 Win32 矩形算列表区点击点，滚动时完全不走 UIA。"""
    try:
        l, t, r, b = hwnd_rect(hwnd)
        if r - l < 50 or b - t < 50:
            return None
        return (l + r) // 2, min(b - 90, (t + b) // 2 + 40)
    except Exception:
        return None


def clear_overlay_windows(pane_hwnd: int) -> int:
    """关掉所有盖在面板上的小程序/更新窗，并强制面板回前台。纯 Win32，不走 UIA。"""
    wins = miniprog_hwnds(pane_hwnd)
    if wins:
        close_hwnds(wins, settle=0.03, wait_gone=0.7, protect={pane_hwnd})
        left = {h for h in wins if IsWindow(h)}
        if left:
            close_hwnds(left, settle=0.02, wait_gone=0.4, protect={pane_hwnd})
        # 不按 Esc：焦点回到面板时 Esc 会把整个小程序面板关掉。
    focus_hwnd(pane_hwnd, delay=0.02)
    return len(wins)


def pane_alive(hwnd: int, min_w: int = 400, min_h: int = 300) -> bool:
    """面板 hwnd 仍有效且尺寸正常。"""
    if not hwnd or not IsWindow(int(hwnd)):
        return False
    try:
        w, h = hwnd_size(int(hwnd))
        return w >= min_w and h >= min_h
    except Exception:
        return False


def recover_miniprogram_pane_if_needed(pane_hwnd: int) -> int:
    """面板被关掉或 hwnd 失效时，重新定位；找不到也不抛死，返回原 hwnd。"""
    if pane_alive(pane_hwnd):
        return int(pane_hwnd)
    log("  小程序面板句柄失效，重新定位…")
    try:
        pane = ensure_miniprogram_pane()
        hwnd = int(pane.handle)
        log(f"  已重新定位面板 hwnd={hex(hwnd)}")
        return hwnd
    except Exception as e:
        log(f"  重新定位面板失败（继续用旧句柄）: {e}")
        return int(pane_hwnd) if pane_hwnd else 0


def leave_home_to_search(pane_hwnd: int, keyword: str, wait: float = 0.45) -> Any:
    """卡在小程序首页（最近使用/我的常用）时：点 *_搜索 页签，或点放大镜重新搜。绝不点首页图标。"""
    log(f"  当前在小程序首页，离开首页去搜索「{keyword}」")
    pane_hwnd = recover_miniprogram_pane_if_needed(pane_hwnd)
    clear_overlay_windows(pane_hwnd)
    focus_hwnd(pane_hwnd, delay=0.05)
    try:
        pane = wrap(pane_hwnd)
        if click_second_top_tab(pane, keyword):
            time.sleep(0.45)
            _doc, cards, meta = scan_page(wrap(pane_hwnd), only_visible=True)
            if cards and not meta.get("is_home") and not meta.get("is_cover"):
                log(f"  已离开首页，搜索结果 {len(cards)} 张")
                return wrap(pane_hwnd)
            log("  点了搜索页签仍像首页，改点放大镜重搜")
    except Exception as e:
        log(f"  点搜索页签失败: {e}")
    # 首页右上角放大镜 → 输入关键词
    try:
        pane = wrap(pane_hwnd)
        edit = open_home_search(pane)
        pane = wrap(pane_hwnd)
        if edit is not None and edit_is_usable(pane, edit):
            if click_elem_xy(edit):
                pyautogui.hotkey("ctrl", "a")
                paste(keyword)
                pyautogui.press("enter")
                log(f"搜索: {keyword}")
                time.sleep(max(0.8, wait))
                focus_hwnd(pane_hwnd, delay=0.02)
                return wrap(pane_hwnd)
    except Exception as e:
        log(f"  首页放大镜搜索失败: {e}")
    return resubmit_search_in_pane(pane_hwnd, keyword, wait=wait)


def resubmit_search_in_pane(pane_hwnd: int, keyword: str, wait: float = 0.45) -> Any:
    """在当前面板内重新搜索：绝不关面板、不点「小程序」首页签、不走侧栏。"""
    pane_hwnd = recover_miniprogram_pane_if_needed(pane_hwnd)
    clear_overlay_windows(pane_hwnd)
    focus_hwnd(pane_hwnd, delay=0.02)
    drag_results_to(_HwndOnly(pane_hwnd), "top")
    pane = wrap(pane_hwnd)
    try:
        info = inspect_chrome(pane, timeout=2.5)
    except Exception:
        info = {}
    if info.get("is_cover") or info.get("edit") is None or not edit_is_usable(pane, info.get("edit")):
        click_second_top_tab(pane, keyword)
        time.sleep(0.3)
        pane = wrap(pane_hwnd)
        try:
            info = inspect_chrome(pane, timeout=2.0)
        except Exception:
            info = {}
    edit = info.get("edit") if info else None
    if edit is None or not edit_is_usable(pane, edit):
        edit = find_edit_search(pane)
    if edit is None or not edit_is_usable(pane, edit):
        if info.get("is_home"):
            edit = open_home_search(pane)
            pane = wrap(pane_hwnd)
        else:
            edit, pane = bring_search_edit_onscreen(pane, rounds=4)
    if edit is None or not edit_is_usable(pane, edit):
        click_search_by_position(pane)
        time.sleep(0.2)
        pane = wrap(pane_hwnd)
        edit = find_edit_search(pane)
    if edit is None or not edit_is_usable(pane, edit):
        raise RuntimeError("搜索框不可用（面板仍在，请检查是否被无关页挡住）")
    if not click_elem_xy(edit):
        raise RuntimeError("搜索框无法点击")
    pyautogui.hotkey("ctrl", "a")
    paste(keyword)
    pyautogui.press("enter")
    log(f"搜索: {keyword}")
    time.sleep(max(0.8, wait))
    focus_hwnd(pane_hwnd, delay=0.02)
    return wrap(pane_hwnd)


def restore_search_page(pane_hwnd: int, keyword: str, wait: float = 0.3) -> Any:
    """被小程序盖住或点飞页面后：关遮挡窗 -> 点第二页签或重新搜索，回到结果列表。"""
    log(f"  恢复搜索页: {keyword}")
    pane_hwnd = recover_miniprogram_pane_if_needed(pane_hwnd)
    for _ in range(3):
        clear_overlay_windows(pane_hwnd)
        focus_hwnd(pane_hwnd, delay=0.02)
        try:
            pane = wrap(pane_hwnd)
            click_second_top_tab(pane, keyword)
        except Exception:
            try:
                l, t, r, b = hwnd_rect(pane_hwnd)
                click_xy(l + 210, t + 22)
            except Exception:
                pass
        time.sleep(0.35)
        try:
            _doc, cards, meta = scan_page(wrap(pane_hwnd), only_visible=True)
            if cards and not meta.get("is_cover") and not meta.get("is_home"):
                log(f"  已回到搜索结果（{len(cards)} 张卡片）")
                return wrap(pane_hwnd)
        except Exception:
            pass
    return resubmit_search_in_pane(pane_hwnd, keyword, wait=wait)


def iter_descendants(win: Any, timeout: float = SCAN_TIMEOUT) -> list[Any]:
    bucket: list[Any] = []
    err: list[BaseException] = []

    def worker() -> None:
        try:
            bucket.extend(win.descendants())
        except Exception as e:
            err.append(e)

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    if not _join_with_heartbeat(th, max(0.4, timeout)):
        log(f"  UIA 扫描超时({timeout:.1f}s)，跳过本屏")
        reset_uia()
        return []
    if err and is_com_dead(err[0]):
        log("  UIA COM 失效，正在重连…")
        reset_uia()
        return []
    return bucket


def _mp_scan_cards(hwnd: int, conn: Any) -> None:
    """子进程里扫描卡片；主进程可超时杀掉，避免 UIA 卡住 GIL。"""
    try:
        d = Desktop(backend="uia")
        win = d.window(handle=int(hwnd))
        _doc, cards, _meta = scan_page(win, only_visible=True)
        conn.send(("ok", cards))
    except Exception as e:
        try:
            conn.send(("err", str(e)))
        except Exception:
            pass


def scan_cards_safe(hwnd: int, timeout: float = 5.0) -> list[tuple[str, str, str, int, int]]:
    """带硬超时的扫描。拖底后主线程 UIA 常卡死，所以放到子进程。"""
    heartbeat()
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    p = ctx.Process(target=_mp_scan_cards, args=(int(hwnd), child), daemon=True)
    start_err: list[BaseException] = []

    def _start() -> None:
        try:
            p.start()
        except BaseException as e:
            start_err.append(e)

    th = threading.Thread(target=_start, daemon=True)
    th.start()
    if not _join_with_heartbeat(th, 8.0):
        log("  底部扫描进程启动超时")
        return []
    if start_err:
        log(f"  底部扫描进程启动失败: {start_err[0]}")
        return []
    child.close()
    deadline = time.monotonic() + max(1.0, timeout)
    got = False
    while time.monotonic() < deadline:
        heartbeat()
        if parent.poll(0.2):
            got = True
            break
        if not p.is_alive() and parent.poll():
            got = True
            break
    if not got:
        log("  扫描超时，放弃本词剩余结果")
        if p.is_alive():
            p.terminate()
            p.join(1)
        parent.close()
        return []
    try:
        status, payload = parent.recv()
    except Exception:
        payload = []
        status = "err"
    parent.close()
    if p.is_alive():
        p.join(1)
    if status != "ok":
        log(f"  扫描失败: {payload}")
        return []
    return list(payload or [])


class _HwndOnly:
    def __init__(self, hwnd: int) -> None:
        self.handle = int(hwnd)


# -----------------------------------------------------------------------------
# 微信窗口 / 小程序面板
# -----------------------------------------------------------------------------

def _hwnd_class_name(hwnd: int, timeout: float = 2.5) -> str | None:
    result: list[str | None] = [None]

    def worker() -> None:
        try:
            result[0] = wrap(hwnd).class_name() or ""
        except Exception:
            pass

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    _join_with_heartbeat(th, max(0.3, timeout))
    return result[0]


def find_main_window() -> Any | None:
    """定位微信主窗口。优先用 Win32 尺寸启发式，避免 UIA class_name 卡死。"""
    cands: list[tuple[int, int]] = []
    for hwnd in enum_hwnds(class_name="Qt51514QWindowIcon"):
        w, h = hwnd_size(hwnd)
        if w >= 700 and h >= 480:
            cands.append((w * h, hwnd))
    if not cands:
        # 兼容其它 Qt 类名
        def cb(hwnd, _lparam):
            heartbeat()
            if not IsWindowVisible(hwnd):
                return True
            if not hwnd_responsive(int(hwnd), 25):
                return True
            cbuf = ctypes.create_unicode_buffer(512)
            GetClassNameW(hwnd, cbuf, 512)
            cls = cbuf.value or ""
            if "Qt" not in cls or "QWindow" not in cls:
                return True
            w, h = hwnd_size(int(hwnd))
            if w >= 700 and h >= 480:
                cands.append((w * h, int(hwnd)))
            return True

        EnumWindows(EnumWindowsProc(cb), 0)

    if not cands:
        return None
    cands.sort(reverse=True)
    hwnd = cands[0][1]
    # 若 UIA 能读到且不是 MainWindow，尝试下一个候选
    for _area, hwnd in cands[:5]:
        cls = _hwnd_class_name(hwnd, timeout=1.2)
        if cls is None or "MainWindow" in (cls or "") or cls == "":
            focus_hwnd(hwnd)
            return wrap(hwnd)
    focus_hwnd(cands[0][1])
    return wrap(cands[0][1])


def find_miniprogram_sidebar_button(main: Any) -> Any | None:
    for e in iter_descendants(main):
        try:
            info = e.element_info
            if info.control_type == "Button" and (info.name or "") == "小程序面板":
                return e
        except Exception:
            continue
    return None


def click_named_control(win: Any, names: set[str], control_types: set[str] | None = None) -> bool:
    """在面板内点击名为 names 的 Tab/按钮（用于从 E_搜索 / 更新页回到小程序）。"""
    for e in iter_descendants(win, timeout=5.0):
        try:
            info = e.element_info
            name = (info.name or "").strip()
            if name not in names:
                continue
            ct = info.control_type or ""
            if control_types and ct not in control_types:
                continue
            click_elem_xy(e)
            time.sleep(0.3)
            return True
        except Exception:
            continue
    return False


def close_junk_chrome_windows(exclude_hwnd: int) -> int:
    """关掉更新页 / xxx_搜索 等假小程序窗口。"""
    wins = list_miniprog_windows(exclude_hwnd)
    junk = {h for h, title, _pid in wins if is_junk_window_title(title)}
    if junk:
        names = [t for h, t, _ in wins if h in junk]
        log(f"  关闭异常窗口 {len(junk)} 个: {', '.join(names)[:120]}")
        close_hwnds(junk, protect={exclude_hwnd})
    return len(junk)


def recover_miniprogram_home(win: Any) -> Any:
    """从「E_搜索 / 更新微信」页签回到小程序首页，露出搜索框。"""
    hwnd = int(win.handle)
    close_junk_chrome_windows(hwnd)
    focus_hwnd(hwnd, delay=0.05)
    win = wrap(hwnd)

    # 先点面板顶栏「小程序」页签（截图里和 E_搜索 并列的那个）
    if click_named_control(win, {"小程序"}, {"TabItem", "Button", "Text", "Hyperlink", "ListItem"}):
        log("  已点击页签「小程序」")
        time.sleep(0.25)
        win = wrap(hwnd)

    # 不按 Esc，避免把小程序面板关掉；异常窗已在 close_junk_chrome_windows 里 WM_CLOSE。

    win = scroll_to_top(win)
    return wrap(hwnd)


def find_miniprogram_pane() -> Any:
    """定位小程序面板。标题通常是「微信」；忙碌时可能短暂无响应，放宽枚举。"""
    cands: list[tuple[int, int]] = []
    titles = {"微信", "Weixin", "WeChat"}
    log("  枚举微信面板窗口…")
    for hwnd in enum_hwnds(title_in=titles, class_name=PANE_CLASS, require_responsive=True):
        w, h = hwnd_size(hwnd)
        if w >= 400 and h >= 300:
            cands.append((w * h, hwnd))
    if not cands:
        # 面板忙时 GetWindow 可能短暂无响应，再扫一遍不要求响应
        for hwnd in enum_hwnds(title_in=titles, class_name=PANE_CLASS, require_responsive=False):
            w, h = hwnd_size(hwnd)
            if w >= 400 and h >= 300:
                cands.append((w * h, hwnd))
    cands.sort(reverse=True)
    if not cands:
        raise RuntimeError("未找到微信小程序面板。请先打开 PC 微信。")
    hwnd = cands[0][1]
    log(f"  候选面板 hwnd={hex(hwnd)} size={hwnd_size(hwnd)}")
    focus_hwnd(hwnd, delay=0.02)
    log("  连接 UIA…")
    try:
        return wrap(hwnd)
    except TimeoutError:
        log("  连接 UIA 超时，先用窗口句柄继续（稍后扫描时再连）")
        reset_uia()

        class _HwndPane:
            def __init__(self, h: int) -> None:
                self.handle = int(h)

        return _HwndPane(hwnd)


def click_miniprogram_sidebar(timeout: float = 12.0) -> Any:
    main = find_main_window()
    if main is None:
        raise RuntimeError("未找到微信主窗口")
    focus_hwnd(int(main.handle))
    btn = find_miniprogram_sidebar_button(main)
    if btn is None:
        raise RuntimeError("找不到侧栏「小程序面板」")
    if not click_elem_xy(btn):
        raise RuntimeError("侧栏「小程序面板」点击失败")
    time.sleep(0.35)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return find_miniprogram_pane()
        except RuntimeError:
            time.sleep(0.2)
    raise RuntimeError("点击小程序面板后窗口未出现")


def ensure_miniprogram_pane() -> Any:
    log("正在定位小程序面板…")
    try:
        pane = find_miniprogram_pane()
        log(f"已定位面板 hwnd={hex(int(pane.handle))}")
        return pane
    except RuntimeError:
        log("未找到面板，尝试点击侧栏「小程序面板」…")
        pane = click_miniprogram_sidebar()
        log(f"已打开面板 hwnd={hex(int(pane.handle))}")
        return pane


# -----------------------------------------------------------------------------
# UIA 扫描
# -----------------------------------------------------------------------------

def is_result_title(name: str) -> bool:
    n = name.strip()
    if not n or n in SKIP_TITLES:
        return False
    if len(n) < 1 or len(n) > 80:
        return False
    if "最近使用" in n:
        return False
    return True


def fast_rectangle(elem: Any) -> Any | None:
    """扫描热路径：直接读坐标，不用线程（线程超时才是滑动卡顿主因）。"""
    try:
        return elem.rectangle()
    except Exception:
        return None


def timed_rectangle(elem: Any, timeout: float = RECT_TIMEOUT) -> Any | None:
    """仅在可能卡死的路径使用（例如关窗后的旧控件）。"""
    box: list[Any | None] = [None]

    def worker() -> None:
        try:
            box[0] = elem.rectangle()
        except Exception:
            pass

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    th.join(max(0.15, timeout))
    if th.is_alive():
        return None
    return box[0]


def visible_in_rect(dr: Any, r: Any, margin: int = 2) -> bool:
    if dr is None or r is None:
        return False
    if r.right <= r.left or r.bottom <= r.top:
        return False
    cx = (r.left + r.right) // 2
    cy = (r.top + r.bottom) // 2
    return dr.left + margin <= cx <= dr.right - margin and dr.top + margin <= cy <= dr.bottom - margin


def extract_card_text(elems: list[Any], index: int) -> tuple[str, str] | None:
    """从扁平 UIA 序列中提取卡片标题和一行描述。"""
    texts: list[str] = []
    for nxt in elems[index + 1:index + 16]:
        try:
            info = nxt.element_info
            if info.control_type != "Text":
                continue
            s = (info.name or "").strip()
        except Exception:
            continue
        if not s or s in SKIP_TITLES:
            continue
        if s in texts:
            continue
        texts.append(s)
        if len(texts) >= 2:
            break
    if not texts or not is_result_title(texts[0]):
        return None
    title = texts[0]
    subtitle = texts[1] if len(texts) > 1 else ""
    return title, subtitle


def is_card_elem(cls: str, ct: str) -> bool:
    # 只认搜索结果大卡片。tab__item 等顶栏控件也含 item，一点就会回首页。
    return cls == "app_wrapper" and ct == "Group"


def scan_page(win: Any, only_visible: bool = True) -> tuple[Any | None, list[tuple[str, str, str, int, int]], dict[str, Any]]:
    """返回 (Document, [(key, title, subtitle, x, y), ...], meta)。

    meta.is_home：同时扫到「最近使用」和「我的常用」精确标题，判定为首页。
    """
    empty_meta: dict[str, Any] = {
        "is_home": False, "has_xiaochengxu": False, "names": set(), "is_cover": False,
    }
    elems = iter_descendants(win, timeout=SCAN_TIMEOUT)
    if not elems:
        return None, [], empty_meta

    doc = None
    home_hits: set[str] = set()
    has_xiaochengxu = False
    names: set[str] = set()
    for e in elems:
        try:
            info = e.element_info
            n = (info.name or "").strip()
            if n:
                names.add(n)
                if n in HOME_SECTION_TITLES:
                    home_hits.add(n)
                if n == "小程序":
                    has_xiaochengxu = True
            if info.control_type == "Document" and doc is None:
                doc = e
        except Exception:
            pass

    meta: dict[str, Any] = {
        "is_home": HOME_SECTION_TITLES <= home_hits,
        "has_xiaochengxu": has_xiaochengxu,
        "names": names,
    }

    try:
        pl, pt, pr, pb = hwnd_rect(int(win.handle))

        class _R:
            left, top, right, bottom = pl, pt, pr, pb

        pane_rect = _R()
    except Exception:
        pane_rect = fast_rectangle(doc) if doc is not None else None

    out: list[tuple[str, str, str, int, int]] = []
    local_seen: set[str] = set()
    for i, e in enumerate(elems):
        try:
            info = e.element_info
            cls = info.class_name or ""
            ct = info.control_type or ""
        except Exception:
            continue

        if not is_card_elem(cls, ct):
            continue

        r = fast_rectangle(e)
        if r is None:
            continue
        if only_visible and not visible_in_rect(pane_rect, r):
            continue

        text = extract_card_text(elems, i)
        if text is None:
            continue
        title, subtitle = text
        key = title + "\x1f" + subtitle
        if key in local_seen:
            continue

        if int(r.right) - int(r.left) < 160 or int(r.bottom) - int(r.top) < 60:
            continue

        x = (int(r.left) + int(r.right)) // 2
        y = (int(r.top) + int(r.bottom)) // 2
        if x <= 0 or y <= 0:
            continue

        local_seen.add(key)
        out.append((key, title, subtitle, x, y))

    out.sort(key=lambda item: (item[4], item[3]))
    meta["is_cover"] = (not out) and names_look_irrelevant(names)
    return doc, out, meta


def page_signature(cards: list[tuple[str, str, str, int, int]]) -> tuple:
    return tuple((key, y // 8, x // 8) for key, _t, _s, x, y in cards)


def find_edit_search(win: Any) -> Any | None:
    for e in iter_descendants(win, timeout=3.0):
        try:
            info = e.element_info
            if info.control_type == "Edit" and (info.name or "") == "搜索小程序":
                return e
        except Exception:
            pass
    return None


def edit_is_usable(win: Any, edit: Any) -> bool:
    try:
        pl, pt, pr, pb = hwnd_rect(int(win.handle))
        er = timed_rectangle(edit, timeout=0.4)
        if er is None:
            return False
        if er.right <= er.left or er.bottom <= er.top:
            return False
        cx = (er.left + er.right) // 2
        cy = (er.top + er.bottom) // 2
        return pl <= cx <= pr and pt <= cy <= pb
    except Exception:
        return False


def find_search_icon(win: Any) -> Any | None:
    for e in iter_descendants(win, timeout=3.0):
        try:
            if (e.element_info.class_name or "") == "search_small":
                return e
        except Exception:
            pass
    return None


def _focus_list_area(win: Any, doc: Any | None = None) -> None:
    """列表聚焦只用 Win32，保证滚动丝滑。"""
    try:
        xy = pane_focus_xy(int(win.handle))
        if xy is None:
            return
        pyautogui.moveTo(xy[0], xy[1], duration=0)
        pyautogui.click()
        time.sleep(0.02)
    except Exception:
        pass


def scroll_to_top(win: Any, doc: Any | None = None, wait: float = 0.05) -> Any:
    hwnd = int(win.handle)
    focus_hwnd(hwnd, delay=0.01)
    _focus_list_area(win, doc)
    try:
        pyautogui.press("home")
        time.sleep(wait)
        for _ in range(8):
            pyautogui.press("pageup")
            time.sleep(0.03)
        for _ in range(10):
            pyautogui.scroll(20)
            time.sleep(0.02)
    except Exception:
        pass
    time.sleep(0.08)
    try:
        return wrap(hwnd)
    except TimeoutError:
        return _HwndOnly(hwnd)


def bring_search_edit_onscreen(win: Any, rounds: int = 6) -> tuple[Any | None, Any]:
    """搜索框常被滚到视口外（坐标 Y 为负）。先拖滑条回顶，再确认输入框。"""
    hwnd = int(win.handle)
    drag_results_to(_HwndOnly(hwnd), "top")
    for i in range(max(1, rounds)):
        try:
            win = wrap(hwnd)
            edit = find_edit_search(win)
            if edit is not None and edit_is_usable(win, edit):
                if i:
                    log(f"  搜索框已滚回可视区域 (round {i})")
                return edit, win
        except TimeoutError:
            log("  顶部 UIA 仍超时，再拖一次拉拽条")
        except Exception as e:
            log(f"  确认搜索框失败: {e}")
        drag_results_to(_HwndOnly(hwnd), "top")
    try:
        win = wrap(hwnd)
        return find_edit_search(win), win
    except Exception:
        return None, _HwndOnly(hwnd)


def scroll_one_screen(win: Any, doc: Any | None = None, wait: float = 0.08, wheels: int = -8) -> bool:
    """丝滑翻页：Win32 聚焦 + PageDown + 大滚轮。"""
    try:
        _focus_list_area(win, doc)
        pyautogui.press("pagedown")
        time.sleep(wait)
        pyautogui.scroll(wheels)
        time.sleep(wait * 0.7)
        return True
    except Exception:
        return False


def scroll_burst(win: Any, rounds: int = 2, wait: float = 0.06) -> None:
    for _ in range(max(1, rounds)):
        scroll_one_screen(win, None, wait=wait, wheels=-10)


def click_search_by_position(win: Any) -> bool:
    """面板内没有可点的 UIA 搜索框时，点顶部放大镜大致位置。"""
    try:
        hwnd = int(win.handle)
        l, t, r, b = hwnd_rect(hwnd)
        # 页签栏约 40px，其下才是「小程序」标题行 + 右上角放大镜/搜索框
        points = [
            (r - 48, t + 88),
            (r - 72, t + 88),
            (r - 40, t + 72),
            (r - 56, t + 104),
            (r - 100, t + 88),
            (r - 48, t + 52),
            ((l + r) // 2, t + 88),
        ]
        for x, y in points:
            pyautogui.click(x, y)
            time.sleep(0.2)
            edit = find_edit_search(wrap(hwnd))
            if edit is not None and edit_is_usable(wrap(hwnd), edit):
                return True
        return False
    except Exception:
        return False


def inspect_chrome(win: Any, timeout: float = 2.2) -> dict[str, Any]:
    """一次扫描：首页特征、搜索框、放大镜、顶栏页签。"""
    names: set[str] = set()
    edit = None
    icon = None
    tabs: list[tuple[int, int, str, Any]] = []
    try:
        _pl, pt, _pr, _pb = hwnd_rect(int(win.handle))
    except Exception:
        pt = 0
    for e in iter_descendants(win, timeout=timeout):
        try:
            info = e.element_info
            n = (info.name or "").strip()
            ct = info.control_type or ""
            cls = info.class_name or ""
        except Exception:
            continue
        if n:
            names.add(n)
        if ct == "Edit" and n == "搜索小程序" and edit is None:
            edit = e
        if cls == "search_small" and icon is None:
            icon = e
        if not n:
            continue
        r = fast_rectangle(e)
        if r is None:
            continue
        top = int(r.top)
        h = int(r.bottom) - int(r.top)
        w = int(r.right) - int(r.left)
        if h > 56 or w < 24 or h < 10:
            continue
        if not (pt - 10 <= top <= pt + 58):
            continue
        if ct == "TabItem" or n == "小程序" or is_search_tab_name(n) or names_look_irrelevant([n]):
            tabs.append((int(r.left), top, n, e))
    tabs.sort(key=lambda x: (x[1], x[0]))
    dedup: list[tuple[int, int, str, Any]] = []
    seen_tab: set[tuple[str, int]] = set()
    for item in tabs:
        key = (item[2], item[0] // 8)
        if key in seen_tab:
            continue
        seen_tab.add(key)
        dedup.append(item)
    return {
        "names": names,
        "is_home": HOME_SECTION_TITLES <= names,
        "has_xiaochengxu": "小程序" in names,
        "is_cover": names_look_irrelevant(names),
        "edit": edit,
        "icon": icon,
        "tabs": dedup,
    }


def is_home_page(win: Any, info: dict[str, Any] | None = None) -> bool:
    """首页：同时出现「最近使用」和「我的常用」。"""
    if info is None:
        info = inspect_chrome(win)
    return bool(info.get("is_home"))


def search_header_ready(win: Any, info: dict[str, Any] | None = None) -> bool:
    """能同时看到「小程序」和搜索输入框。"""
    if info is None:
        info = inspect_chrome(win)
    edit = info.get("edit")
    if not info.get("has_xiaochengxu") or edit is None:
        return False
    return edit_is_usable(win, edit)


def wait_search_header_ready(pane_hwnd: int, timeout: float = 4.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pane = wrap(pane_hwnd)
        if search_header_ready(pane):
            return True
        time.sleep(0.2)
    return False


def click_tab_label(elem: Any, name: str) -> bool:
    """点页签左侧文字，躲开右侧关闭按钮。"""
    r = timed_rectangle(elem, timeout=0.35)
    if r is None:
        r = fast_rectangle(elem)
    if r is None:
        return False
    w = max(1, int(r.right) - int(r.left))
    cx = int(r.left) + max(12, int(w * 0.28))
    cy = (int(r.top) + int(r.bottom)) // 2
    try:
        click_xy(cx, cy)
        log(f"  已点击顶栏页签「{name}」")
        time.sleep(0.35)
        return True
    except Exception:
        return False


def click_second_top_tab(win: Any, keyword: str = "") -> bool:
    """无关页覆盖时，点从左往右第二个页签（{关键词}_搜索），不要点「小程序」。"""
    info = inspect_chrome(win, timeout=3.0)
    tabs = list(info.get("tabs") or [])
    want_names: list[str] = []
    if keyword:
        want_names = [f"{keyword}_搜索", f"{keyword}_search"]

    search_tabs = [t for t in tabs if is_search_tab_name(t[2], keyword)]
    preferred = [t for t in search_tabs if t[2] in want_names] if want_names else []
    for _left, _top, name, elem in preferred or search_tabs:
        if click_tab_label(elem, name):
            return True

    # 顶栏从左到右：第 1 个是「小程序」，第 2 个就是 X_搜索
    bar = [t for t in tabs if t[2] == "小程序" or is_search_tab_name(t[2], keyword)]
    bar.sort(key=lambda x: x[0])
    if len(bar) >= 2:
        _l, _t, name, elem = bar[1]
        if name != "小程序" and click_tab_label(elem, name):
            return True

    for left, top, name, elem in tabs:
        if name != "小程序":
            continue
        r = timed_rectangle(elem, timeout=0.35) or fast_rectangle(elem)
        if r is None:
            continue
        w = max(40, int(r.right) - int(r.left))
        cx = int(r.right) + max(16, w // 3)
        cy = (int(r.top) + int(r.bottom)) // 2
        click_xy(cx, cy)
        log(f"  已点击「小程序」右侧第二个位置（{keyword}_搜索）")
        time.sleep(0.35)
        return True
    return False


def _set_cursor_xy(x: int, y: int) -> None:
    _send_mouse(0, int(x), int(y))


def _abs_xy(x: int, y: int) -> tuple[int, int]:
    vx = int(user32.GetSystemMetrics(SM_XVIRTUALSCREEN))
    vy = int(user32.GetSystemMetrics(SM_YVIRTUALSCREEN))
    vw = max(1, int(user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)) - 1)
    vh = max(1, int(user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)) - 1)
    ax = int(round((int(x) - vx) * 65535 / vw))
    ay = int(round((int(y) - vy) * 65535 / vh))
    return ax, ay


def _send_mouse(flags: int, x: int | None = None, y: int | None = None, data: int = 0) -> None:
    """SendInput 注入鼠标事件。微信收不到 SetCursorPos 的移动，拖滑条必须走这条。"""
    inp = INPUT()
    inp.type = 0
    inp.mi.mouseData = int(data)
    inp.mi.dwFlags = int(flags)
    if x is not None and y is not None:
        ax, ay = _abs_xy(x, y)
        inp.mi.dx = ax
        inp.mi.dy = ay
        inp.mi.dwFlags |= MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
    user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))


def drag_vertical_locked(x: int, y0: int, y1: int, steps: int = 40, linger: float = 0.16) -> None:
    """按下左键后只改 Y，X 全程锁死。用 SendInput，不用 SetCursorPos。"""
    x = int(x)
    y0 = int(y0)
    y1 = int(y1)
    _send_mouse(0, x, y0)
    time.sleep(max(0.05, linger))
    _send_mouse(MOUSEEVENTF_LEFTDOWN, x, y0)
    time.sleep(0.04)
    nudge = 4 if y1 > y0 else -4
    _send_mouse(0, x, y0 + nudge)
    time.sleep(0.02)
    n = max(16, int(steps))
    for i in range(1, n + 1):
        y = y0 + (y1 - y0) * i // n
        _send_mouse(0, x, y)
        time.sleep(0.008)
        if i % 10 == 0:
            heartbeat()
    _send_mouse(0, x, y1)
    time.sleep(0.02)
    _send_mouse(MOUSEEVENTF_LEFTUP, x, y1)


def _vscroll_geom(hwnd: int) -> tuple[int, int, int, int | None, int | None] | None:
    """返回 (x, track_top, track_bot, thumb_top, thumb_bot)。优先 Win32 真滑条。"""
    hwnd = int(hwnd)
    sbi = SCROLLBARINFO()
    sbi.cbSize = ctypes.sizeof(SCROLLBARINFO)
    if user32.GetScrollBarInfo(hwnd, OBJID_VSCROLL, ctypes.byref(sbi)):
        rc = sbi.rcScrollBar
        if (rc.right - rc.left) >= 6 and (rc.bottom - rc.top) >= 40:
            if not (int(sbi.rgstate[0]) & STATE_SYSTEM_INVISIBLE):
                arrow = max(0, int(sbi.dxyLineButton))
                x = (int(rc.left) + int(rc.right)) // 2
                track_top = int(rc.top) + arrow + 2
                track_bot = int(rc.bottom) - arrow - 2
                thumb_top = int(rc.top) + int(sbi.xyThumbTop)
                thumb_bot = int(rc.top) + int(sbi.xyThumbBottom)
                if thumb_bot > thumb_top + 4:
                    return x, track_top, track_bot, thumb_top, thumb_bot
                return x, track_top, track_bot, None, None

    found: list[tuple[int, int, int, int]] = []

    def cb(ch, _lp):
        heartbeat()
        if not IsWindowVisible(ch):
            return True
        buf = ctypes.create_unicode_buffer(256)
        GetClassNameW(ch, buf, 256)
        if (buf.value or "") != "ScrollBar":
            return True
        try:
            style = int(user32.GetWindowLongW(ch, GWL_STYLE))
        except Exception:
            return True
        if not (style & SBS_VERT):
            return True
        l, t, r, b = hwnd_rect(int(ch))
        if r - l >= 6 and b - t >= 40:
            found.append((l, t, r, b))
        return True

    try:
        EnumChildWindows(hwnd, EnumChildProc(cb), 0)
    except Exception:
        pass
    if found:
        found.sort(key=lambda box: (box[0], -(box[3] - box[1])))
        l, t, r, b = found[-1]
        x = (l + r) // 2
        arrow = max(12, min(24, r - l + 2))
        return x, t + arrow, b - arrow, None, None

    try:
        _l, t, r, b = hwnd_rect(hwnd)
    except Exception:
        return None
    if r - _l < 80 or b - t < 160:
        return None
    bar_w = max(12, int(user32.GetSystemMetrics(SM_CXVSCROLL)))
    x = r - max(SCROLLBAR_X_INSET, bar_w // 2)
    arrow = bar_w
    return x, t + 140, b - arrow - 4, None, None


def _wheel_list(hwnd: int, notches: int, times: int) -> None:
    xy = pane_focus_xy(int(hwnd))
    if xy is None:
        return
    x, y = xy
    _send_mouse(0, x, y)
    time.sleep(0.04)
    delta = WHEEL_DELTA if notches > 0 else -WHEEL_DELTA
    for _ in range(max(0, times)):
        heartbeat()
        _send_mouse(MOUSEEVENTF_WHEEL, data=delta)
        time.sleep(0.02)


def drag_results_to(win: Any, end: str = "bottom") -> Any:
    """拖动搜索结果右侧拉拽条：抓住滑块只上下拖，完全不左右。"""
    hwnd = int(win.handle)
    focus_hwnd(hwnd, delay=0.02)
    geom = _vscroll_geom(hwnd)
    try:
        if geom is None:
            raise RuntimeError("no track")
        x, track_top, track_bot, thumb_top, thumb_bot = geom
        if thumb_top is not None and thumb_bot is not None and thumb_bot > thumb_top + 4:
            y0 = (int(thumb_top) + int(thumb_bot)) // 2
        elif end == "bottom":
            y0 = track_top + 18
        else:
            y0 = track_bot - 18
        y1 = track_bot - 6 if end == "bottom" else track_top + 6
        y0 = min(max(y0, track_top + 4), track_bot - 4)
        y1 = min(max(y1, track_top + 2), track_bot - 2)
        log(f"  拖滑条 {'↓' if end == 'bottom' else '↑'} x={x} {y0}->{y1}")
        drag_vertical_locked(x, y0, y1, steps=52, linger=0.18)
        try:
            PostMessageW(hwnd, WM_VSCROLL, SB_BOTTOM if end == "bottom" else SB_TOP, 0)
        except Exception:
            pass
        _wheel_list(hwnd, -8 if end == "bottom" else 8, 10)
        time.sleep(0.12)
        log("  已拖动拉拽条到" + ("底部" if end == "bottom" else "顶部"))
    except Exception as e:
        log(f"  拖动拉拽条失败: {e}")
        try:
            pyautogui.press("end" if end == "bottom" else "home")
        except Exception:
            pass
    heartbeat()
    return win


def _card_col(x: int, pane_hwnd: int | None) -> int:
    """按面板宽度把卡片分到左/中/右 3 列（右侧留给滑条）。"""
    if pane_hwnd:
        l, _t, r, _b = hwnd_rect(pane_hwnd)
        inner_l = l + 12
        inner_r = r - 20
    else:
        inner_l, inner_r = 0, 1
    span = max(1, inner_r - inner_l)
    return min(RESULT_COLS - 1, max(0, int((x - inner_l) * RESULT_COLS / span)))


def group_into_rows(
    cards: list[tuple[str, str, str, int, int]],
    y_tol: int = 48,
    pane_hwnd: int | None = None,
) -> list[list[tuple[str, str, str, int, int]]]:
    """先按行聚，行内再按 3 列从左到右，得到阅读顺序。"""
    if not cards:
        return []
    ordered = sorted(cards, key=lambda c: (c[4], c[3]))
    rows: list[list[tuple[str, str, str, int, int]]] = []
    for card in ordered:
        if rows:
            row_y = sum(c[4] for c in rows[-1]) / len(rows[-1])
            if abs(card[4] - row_y) <= y_tol:
                rows[-1].append(card)
                continue
        rows.append([card])
    for row in rows:
        row.sort(key=lambda c: (_card_col(c[3], pane_hwnd), c[3]))
    return rows


def screen_looks_full(
    cards: list[tuple[str, str, str, int, int]],
    rows: list[list[tuple[str, str, str, int, int]]],
    pane_hwnd: int,
    visible_rows: int = VISIBLE_RESULT_ROWS,
) -> bool:
    if len(rows) >= visible_rows:
        return True
    if not cards:
        return False
    last_y = cards[-1][4]
    _l, _t, _r, b = hwnd_rect(pane_hwnd)
    return last_y >= b - 150


def open_home_search(win: Any) -> Any | None:
    """首页只点右上角放大镜，露出「搜索小程序」输入框。"""
    hwnd = int(win.handle)
    icon = find_search_icon(win)
    if icon is not None:
        click_elem_xy(icon)
        time.sleep(0.25)
    edit = find_edit_search(wrap(hwnd))
    if edit is not None and edit_is_usable(wrap(hwnd), edit):
        return edit
    if click_search_by_position(wrap(hwnd)):
        return find_edit_search(wrap(hwnd))
    return find_edit_search(wrap(hwnd))


def reveal_search_box(win: Any) -> tuple[Any, Any]:
    hwnd = int(win.handle)
    close_junk_chrome_windows(hwnd)
    extras = miniprog_hwnds(hwnd)
    if extras:
        close_hwnds(extras, protect={hwnd})

    info = inspect_chrome(win)
    edit = info.get("edit")
    if edit is not None and edit_is_usable(win, edit):
        return edit, win

    if info.get("is_home"):
        log("  识别到首页（最近使用 + 我的常用），点击右上角放大镜…")
        edit = open_home_search(win)
        win = wrap(hwnd)
        if edit is not None and edit_is_usable(win, edit):
            return edit, win

    log("  搜索框不可见，滚回顶部直到输入框出现…")
    edit, win = bring_search_edit_onscreen(win, rounds=6)
    if edit is not None and edit_is_usable(win, edit):
        return edit, win

    icon = find_search_icon(win)
    if icon is not None:
        click_elem_xy(icon)
        time.sleep(0.2)
        win = wrap(hwnd)
        edit = find_edit_search(win)
        if edit is not None and edit_is_usable(win, edit):
            return edit, win

    log("  尝试坐标点击搜索入口…")
    if click_search_by_position(win):
        win = wrap(hwnd)
        edit = find_edit_search(win)
        if edit is not None and edit_is_usable(win, edit):
            return edit, win

    log("  仍无搜索框，请保持小程序面板打开")
    raise RuntimeError("找不到小程序搜索框（请保持小程序面板打开）")


def paste(text: str) -> None:
    pyperclip.copy(text)
    time.sleep(0.01)
    pyautogui.hotkey("ctrl", "v")


def search_keyword(win: Any, keyword: str, wait: float = 0.45) -> Any:
    hwnd = int(win.handle)
    focus_hwnd(hwnd, delay=0.02)
    # 触底后 UIA 树极大，必须先把拉拽条拖回顶部再 wrap
    drag_results_to(_HwndOnly(hwnd), "top")
    try:
        win = wrap(hwnd)
    except TimeoutError:
        drag_results_to(_HwndOnly(hwnd), "top")
        win = wrap(hwnd)
    try:
        info = inspect_chrome(win)
    except Exception as e:
        if not is_com_dead(e):
            raise
        log(f"  搜索前 UIA 失效，重连: {e}")
        reset_uia()
        win = wrap(hwnd)
        info = inspect_chrome(win)
    if info.get("is_cover"):
        log("  当前是覆盖页，点第二页签回到搜索")
        return recover_search_after_ad(hwnd, keyword, wait=wait)
    if info.get("is_home"):
        log("  当前是小程序首页，只执行搜索（不点击首页图标）")
        edit = info.get("edit")
        if edit is None or not edit_is_usable(win, edit):
            edit = open_home_search(win)
            win = wrap(hwnd)
        if edit is None or not edit_is_usable(win, edit):
            edit, win = bring_search_edit_onscreen(win, rounds=4)
    else:
        edit = info.get("edit")
        if edit is None or not edit_is_usable(win, edit):
            click_second_top_tab(win, keyword)
            time.sleep(0.25)
            win = wrap(hwnd)
            edit = find_edit_search(win)
        if edit is None or not edit_is_usable(win, edit):
            edit, win = bring_search_edit_onscreen(win, rounds=4)

    if not click_elem_xy(edit):
        raise RuntimeError("搜索框无法点击")
    pyautogui.hotkey("ctrl", "a")
    paste(keyword)
    pyautogui.press("enter")
    log(f"搜索: {keyword}")
    time.sleep(max(0.8, wait))
    return wrap(int(win.handle))


def recover_search_after_ad(pane_hwnd: int, keyword: str, wait: float = 0.3) -> Any:
    """无关页覆盖搜索结果：点第二页签或重新搜索，直到回到卡片列表。"""
    log(f"  无关页面，点击顶栏第二个页签「{keyword}_搜索」回到搜索结果")
    pane_hwnd = recover_miniprogram_pane_if_needed(pane_hwnd)
    clear_overlay_windows(pane_hwnd)
    focus_hwnd(pane_hwnd, delay=0.05)

    def _back_on_results() -> bool:
        heartbeat()
        try:
            _doc, cards, meta = scan_page(wrap(pane_hwnd), only_visible=True)
        except Exception:
            return False
        if cards and not meta.get("is_cover") and not meta.get("is_home"):
            log(f"  已回到搜索结果（{len(cards)} 张卡片）")
            return True
        return False

    try:
        for round_i in range(5):
            if _back_on_results():
                return wrap(pane_hwnd)
            pane = wrap(pane_hwnd)
            clicked = click_second_top_tab(pane, keyword)
            if not clicked:
                l, t, r, b = hwnd_rect(pane_hwnd)
                click_xy(l + 210, t + 22)
                log("  已按坐标点击顶栏第二个页签位置")
                time.sleep(0.35)
            else:
                time.sleep(0.25)
            if _back_on_results():
                return wrap(pane_hwnd)
    except Exception as e:
        if is_com_dead(e):
            log(f"  UIA 失效，重连后改坐标点「{keyword}_搜索」: {e}")
            reset_uia()
            try:
                l, t, r, b = hwnd_rect(pane_hwnd)
                click_xy(l + 210, t + 22)
                time.sleep(0.4)
                if _back_on_results():
                    return wrap(pane_hwnd)
            except Exception:
                reset_uia()
        else:
            log(f"  页签恢复异常: {e}")
    log("  页签恢复失败，在当前面板重新搜索该词")
    pane = resubmit_search_in_pane(pane_hwnd, keyword, wait=wait)
    wait_for_result_cards(int(pane.handle), keyword, timeout=6.0)
    return pane


def wait_for_result_cards(pane_hwnd: int, keyword: str = "", timeout: float = 6.0) -> tuple[list, dict[str, Any]]:
    """搜索后等到结果卡片出现，避免把加载中的空屏误判成广告。"""
    deadline = time.monotonic() + timeout
    last_meta: dict[str, Any] = {"is_home": False, "has_xiaochengxu": False, "names": set()}
    while time.monotonic() < deadline:
        pane = wrap(pane_hwnd)
        _doc, cards, meta = scan_page(pane, only_visible=True)
        last_meta = meta
        if meta.get("is_cover"):
            click_second_top_tab(pane, keyword)
            time.sleep(0.3)
            continue
        if meta.get("is_home"):
            # 首页图标不能当搜索结果；点第二页签或放大镜离开
            try:
                leave_home_to_search(pane_hwnd, keyword or "", wait=0.5)
            except Exception:
                click_second_top_tab(pane, keyword)
            time.sleep(0.35)
            continue
        if cards and not meta.get("is_home"):
            log(f"  搜索结果已刷出 {len(cards)} 张卡片")
            return cards, meta
        time.sleep(0.35)
    return [], last_meta


# -----------------------------------------------------------------------------
# 小程序独立窗口：出现 -> 关闭
# -----------------------------------------------------------------------------

def list_miniprog_windows(exclude_hwnd: int) -> list[tuple[int, str, int]]:
    out: list[tuple[int, str, int]] = []

    def cb(hwnd, _lparam):
        heartbeat()
        if not IsWindowVisible(hwnd) or int(hwnd) == exclude_hwnd:
            return True
        if hwnd_class(int(hwnd)) != PANE_CLASS:
            return True
        title = hwnd_title(int(hwnd), timeout_ms=50)
        if not title or title in {"微信", "Weixin", "WeChat"}:
            return True
        w, h = hwnd_size(int(hwnd))
        if w < 200 or h < 200:
            return True
        out.append((int(hwnd), title, hwnd_pid(int(hwnd))))
        return True

    def run() -> None:
        try:
            EnumWindows(EnumWindowsProc(cb), 0)
        except Exception:
            pass

    th = threading.Thread(target=run, daemon=True)
    th.start()
    if not _join_with_heartbeat(th, 4.0):
        log("  枚举小程序窗口超时")
    return out


def miniprog_hwnds(pane_hwnd: int) -> set[int]:
    return {h for h, _t, _pid in list_miniprog_windows(pane_hwnd)}


def wait_new_window(pane_hwnd: int, before: set[int], timeout: float, poll: float = 0.12) -> set[int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        heartbeat()
        now = miniprog_hwnds(pane_hwnd)
        new = now - before
        if new:
            return new
        time.sleep(poll)
    return set()


def wait_windows_gone(hwnds: set[int], timeout: float = 1.2, poll: float = 0.03) -> bool:
    """等到目标 hwnd 全部销毁；关完再点下一个，避免窗口叠着抢焦点。"""
    if not hwnds:
        return True
    deadline = time.monotonic() + timeout
    pending = set(hwnds)
    while pending and time.monotonic() < deadline:
        heartbeat()
        pending = {h for h in pending if IsWindow(h)}
        if not pending:
            return True
        time.sleep(poll)
    return not pending


def close_hwnds(
    hwnds: set[int],
    settle: float = 0.04,
    wait_gone: float = 1.0,
    protect: set[int] | None = None,
) -> None:
    if not hwnds:
        return
    if protect:
        hwnds = {h for h in hwnds if int(h) not in protect}
    if not hwnds:
        return
    for hwnd in hwnds:
        try:
            PostMessageW(hwnd, WM_CLOSE, 0, 0)
        except Exception:
            pass
    if settle:
        time.sleep(settle)
    if not wait_windows_gone(hwnds, timeout=wait_gone):
        # 再补发一次关闭；仍不消失也不死等，继续点下一个。
        for hwnd in list(hwnds):
            if IsWindow(hwnd):
                try:
                    PostMessageW(hwnd, WM_CLOSE, 0, 0)
                except Exception:
                    pass
        wait_windows_gone(hwnds, timeout=0.4)


def close_all_new_windows(pane_hwnd: int, baseline: set[int]) -> None:
    new = miniprog_hwnds(pane_hwnd) - baseline
    close_hwnds(new, protect={pane_hwnd})


# -----------------------------------------------------------------------------
# 关键词策略：无限变异、永不重复
# -----------------------------------------------------------------------------

def build_seed_keywords(letter_start: str = "E") -> list[str]:
    start = (letter_start or "A").upper()[0]
    if start not in string.ascii_uppercase:
        start = "A"
    letters = list(string.ascii_uppercase[string.ascii_uppercase.index(start):])
    digits = [str(i) for i in range(10)]
    return unique(letters + digits + NAMING_WORDS + CITIES + INDUSTRY + SEARCH_PREFIXES + PROVINCES)


def latin_children(keyword: str, max_prefix_len: int) -> list[str]:
    k = (keyword or "").strip().upper()
    if not k or not k.isalpha() or len(k) >= max_prefix_len:
        return []
    return [k + c for c in string.ascii_uppercase]


def semantic_children(keyword: str) -> list[str]:
    if keyword in CITIES or keyword in PROVINCES:
        return [keyword + x for x in CORE_INDUSTRY]
    if keyword in CORE_INDUSTRY or keyword in INDUSTRY:
        return [city + keyword for city in CITIES]
    return []


def parent_mutations(parent: str, max_prefix_len: int) -> list[str]:
    """由当前词派生出一批候选，供去重后使用。"""
    p = (parent or "").strip()
    if not p:
        return []
    out: list[str] = []
    out += latin_children(p, max_prefix_len)
    out += semantic_children(p)
    if not p.startswith("附近"):
        out.append("附近" + p)
    for pre in SEARCH_PREFIXES:
        if p != pre and not p.startswith(pre):
            out.append(pre + p)
    for sfx in SEARCH_SUFFIXES:
        if p != sfx and not p.endswith(sfx):
            out.append(p + sfx)
    return unique(out)


def build_mutation_stream(letter_start: str = "A") -> Iterator[str]:
    """确定性组合空间：字母/数字/词库/前缀后缀/城市行业，体量足够跑到目标。"""
    start = (letter_start or "A").upper()[0]
    if start not in string.ascii_uppercase:
        start = "A"
    letters = list(string.ascii_uppercase[string.ascii_uppercase.index(start):])
    all_letters = list(string.ascii_uppercase)
    digits = list(string.digits)

    yield from letters
    yield from digits
    yield from NAMING_WORDS
    yield from CITIES
    yield from PROVINCES
    yield from INDUSTRY
    yield from SEARCH_PREFIXES
    yield from SEARCH_SUFFIXES

    for a, b in itertools.product(letters, all_letters):
        yield a + b
    for a, d in itertools.product(letters, digits):
        yield a + d
        yield d + a
    for pre, ind in itertools.product(SEARCH_PREFIXES, INDUSTRY):
        yield pre + ind
    for city, ind in itertools.product(CITIES + PROVINCES, CORE_INDUSTRY):
        yield city + ind
    for city, sfx in itertools.product(CITIES, SEARCH_SUFFIXES):
        yield city + sfx
    for ind, sfx in itertools.product(INDUSTRY, SEARCH_SUFFIXES):
        yield ind + sfx
    for pre, city in itertools.product(SEARCH_PREFIXES, CITIES):
        yield pre + city
    for a, b in itertools.product(digits, digits):
        yield a + b
    for a, b, c in itertools.product(letters, all_letters, all_letters):
        yield a + b + c
    for pre, city, ind in itertools.product(SEARCH_PREFIXES[:5], CITIES, CORE_INDUSTRY):
        yield pre + city + ind
    for a, b, c, d in itertools.product(letters, all_letters, all_letters, all_letters):
        yield a + b + c + d


class UniqueMutator:
    """保证吐出的每一个搜索词都没搜过。"""

    def __init__(self, used: set[str], letter_start: str = "A") -> None:
        self.used = used
        self._stream = build_mutation_stream(letter_start)

    def take(self, n: int) -> list[str]:
        out: list[str] = []
        if n <= 0:
            return out
        for k in self._stream:
            s = str(k).strip()
            if not s or s in self.used:
                continue
            self.used.add(s)
            out.append(s)
            if len(out) >= n:
                break
        return out

    def from_parent(
        self,
        parent: str,
        limit: int = 6,
        max_prefix_len: int = 4,
        semantic: bool = True,
    ) -> list[str]:
        p = (parent or "").strip()
        families: list[list[str]] = []
        if p:
            families.append(latin_children(p, max_prefix_len))
            if semantic:
                families.append(semantic_children(p))
            pref = []
            if not p.startswith("附近"):
                pref.append("附近" + p)
            for pre in SEARCH_PREFIXES:
                if p != pre and not p.startswith(pre):
                    pref.append(pre + p)
            families.append(pref)
            families.append([
                p + sfx for sfx in SEARCH_SUFFIXES
                if p != sfx and not p.endswith(sfx)
            ])
        # 各家族轮询，避免连续全是 AA/AB/AC
        mixed: list[str] = []
        seen_local: set[str] = set()
        for _ in range(64):
            progressed = False
            for fam in families:
                while fam:
                    k = fam.pop(0)
                    if k in seen_local or k in self.used or k == parent:
                        continue
                    seen_local.add(k)
                    mixed.append(k)
                    progressed = True
                    break
            if not progressed:
                break
        out: list[str] = []
        for k in mixed:
            self.used.add(k)
            out.append(k)
            if len(out) >= limit:
                break
        if len(out) < max(2, limit // 2):
            out += self.take(limit - len(out))
        return out


# -----------------------------------------------------------------------------
# 单关键词快速点击
# -----------------------------------------------------------------------------

def crawl_keyword(
    pane_hwnd: int,
    keyword: str,
    *,
    max_count: int,
    launch_timeout: float,
    dwell: float,
    scroll_wait: float,
    stagnant_rounds: int,
    max_scroll_rounds: int,
    global_seen: set[str],
    keyword_state: dict[str, Any],
    progress: dict[str, Any],
    progress_path: Path,
    global_dedup: bool,
    visible_rows: int = VISIBLE_RESULT_ROWS,
) -> tuple[int, int, int, bool]:
    """搜索结果页按 3 列顺序点击；第 11 行后拖到底继续，点满 max_count（默认 50）。"""
    attempted = set(str(x) for x in keyword_state.get("attempted", []))
    opened_keys = set(str(x) for x in keyword_state.get("opened_keys", []))
    failed_keys = set(str(x) for x in keyword_state.get("failed_keys", []))

    opened = int(keyword_state.get("opened", 0) or 0)
    failed = int(keyword_state.get("failed", 0) or 0)
    seen_keys: set[str] = set()
    scroll_round = int(keyword_state.get("scroll_round", 0) or 0)
    stagnant = 0
    prev_sig: tuple | None = None
    completed = False
    jumped_bottom = bool(keyword_state.get("jumped_bottom"))
    last_clicked_key = str(keyword_state.get("last_clicked_key") or "")

    baseline = miniprog_hwnds(pane_hwnd)

    def persist(status: str) -> None:
        progress["keywords"][keyword] = {
            "status": status,
            "completed": completed,
            "opened": opened,
            "failed": failed,
            "seen": max(len(seen_keys), int(keyword_state.get("seen", 0) or 0)),
            "attempted": list(attempted),
            "opened_keys": list(opened_keys),
            "failed_keys": list(failed_keys),
            "scroll_round": scroll_round,
            "jumped_bottom": jumped_bottom,
            "last_clicked_key": last_clicked_key,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        progress["opened_total"] = int(progress.get("opened_total", 0) or 0)
        progress["global_seen"] = list(global_seen)
        try:
            save_progress(progress_path, progress)
        except OSError as e:
            log(f"  进度写入失败，继续点击: {e}")

    empty_streak = 0
    fail_streak = 0
    cover_streak = 0

    def recover_ad() -> None:
        nonlocal pane_hwnd, cover_streak
        pane_hwnd = recover_miniprogram_pane_if_needed(pane_hwnd)
        cover_streak += 1
        try:
            if cover_streak >= 3:
                log("  覆盖页恢复多次未回到列表，在当前面板重新搜索")
                cover_streak = 0
                pane = resubmit_search_in_pane(pane_hwnd, keyword, wait=max(0.2, scroll_wait * 2))
                pane_hwnd = int(pane.handle)
                wait_for_result_cards(pane_hwnd, keyword, timeout=6.0)
                return
            pane = recover_search_after_ad(pane_hwnd, keyword, wait=max(0.2, scroll_wait * 2))
            pane_hwnd = int(pane.handle)
            _doc, cards, meta = scan_page(wrap(pane_hwnd), only_visible=True)
            if cards and not meta.get("is_cover") and not meta.get("is_home"):
                cover_streak = 0
        except Exception as e:
            log(f"  广告恢复失败: {e}")
            if is_com_dead(e):
                reset_uia()
                try:
                    pane_hwnd = int(find_miniprogram_pane().handle)
                except Exception:
                    pass
            if cover_streak >= 2:
                try:
                    log("  尝试在当前面板重新搜索以脱离覆盖页")
                    cover_streak = 0
                    pane = resubmit_search_in_pane(pane_hwnd, keyword, wait=max(0.2, scroll_wait * 2))
                    pane_hwnd = int(pane.handle)
                    wait_for_result_cards(pane_hwnd, keyword, timeout=6.0)
                except Exception as e2:
                    log(f"  重新搜索仍失败: {e2}")

    def click_one(key: str, title: str, x: int, y: int) -> str:
        """点开 → 驻留 dwell 秒 → 关闭 → 等消失。返回 ok/fail/ad。"""
        nonlocal opened, failed, last_clicked_key
        clear_overlay_windows(pane_hwnd)
        before = miniprog_hwnds(pane_hwnd)
        attempted.add(key)
        try:
            click_xy(x, y)
        except Exception as e:
            log(f"    点击失败: {title}: {e}")
            failed_keys.add(key)
            failed += 1
            return "fail"

        new_hwnds = wait_new_window(pane_hwnd, before, timeout=launch_timeout)
        if not new_hwnds:
            focus_hwnd(pane_hwnd, delay=0.01)
            try:
                pyautogui.click(x, y)
            except Exception:
                pass
            new_hwnds = wait_new_window(pane_hwnd, before, timeout=max(0.4, launch_timeout * 0.7))

        if not new_hwnds:
            try:
                _doc, cover_cards, cover_meta = scan_page(wrap(pane_hwnd), only_visible=True)
            except Exception:
                cover_cards, cover_meta = [], {}
            if (not cover_cards) and (
                cover_meta.get("is_cover") or cover_meta.get("is_home") or names_look_irrelevant(cover_meta.get("names") or [])
            ):
                failed_keys.add(key)
                log(f"    COVER  {title} → 点「{keyword}_搜索」")
                return "ad"
            failed += 1
            failed_keys.add(key)
            log(f"    FAIL  {title}")
            clear_overlay_windows(pane_hwnd)
            return "fail"

        title_by_hwnd = {h: t for h, t, _ in list_miniprog_windows(pane_hwnd)}
        real_hwnds = {h for h in new_hwnds if not is_junk_window_title(title_by_hwnd.get(h, ""))}
        junk_hwnds = set(new_hwnds) - real_hwnds

        if junk_hwnds and not real_hwnds:
            close_hwnds(junk_hwnds, protect={pane_hwnd})
            clear_overlay_windows(pane_hwnd)
            failed += 1
            failed_keys.add(key)
            log(f"    SKIP  {title} (更新页/广告窗)")
            return "ad"

        if junk_hwnds:
            close_hwnds(junk_hwnds, protect={pane_hwnd})

        if dwell > 0:
            until = time.monotonic() + dwell
            while time.monotonic() < until:
                heartbeat()
                time.sleep(min(0.4, max(0.05, until - time.monotonic())))
        close_hwnds(real_hwnds, protect={pane_hwnd})
        wait_windows_gone(real_hwnds, timeout=1.4)
        clear_overlay_windows(pane_hwnd)
        focus_hwnd(pane_hwnd, delay=0.02)

        opened += 1
        last_clicked_key = key
        opened_keys.add(key)
        global_seen.add(key)
        progress["opened_total"] = int(progress.get("opened_total", 0) or 0) + 1
        log(f"    OK  {title}  ({progress['opened_total']})  本词 {opened}/{max_count or '∞'}")
        if opened % 5 == 0:
            persist("running")
        return "ok"

    do_crawl = not (jumped_bottom and opened > 0)
    if not do_crawl:
        log(f"  本词上次已拖到底（已点 {opened}），直接下一词")
        completed = True
    else:
        log("  等待搜索结果刷出…")
        wait_for_result_cards(pane_hwnd, keyword, timeout=6.5)

    while do_crawl:
        if max_count > 0 and opened >= max_count:
            completed = True
            break
        if scroll_round >= max_scroll_rounds:
            log(f"  达到最大滚动轮数 {max_scroll_rounds}，结束 {keyword}")
            completed = True
            break

        pane_hwnd = recover_miniprogram_pane_if_needed(pane_hwnd)
        clear_overlay_windows(pane_hwnd)
        focus_hwnd(pane_hwnd, delay=0.01)
        try:
            pane = wrap(pane_hwnd)
            t0 = time.monotonic()
            _doc, cards, meta = scan_page(pane, only_visible=True)
        except TimeoutError:
            log("  扫描连接超时，重连后继续")
            reset_uia()
            empty_streak += 1
            if empty_streak >= 8:
                log("  连续超时过多，结束本关键词")
                completed = True
                break
            continue
        scan_ms = int((time.monotonic() - t0) * 1000)
        if scan_ms > 1500:
            log(f"  扫描偏慢 {scan_ms}ms")

        if meta.get("is_cover"):
            log("  识别到无关页面（如下载页/更新页），点第二页签回到搜索")
            recover_ad()
            empty_streak = 0
            prev_sig = None
            if cover_streak >= 5:
                log("  覆盖页反复出现，在当前面板重新搜索")
                cover_streak = 0
                try:
                    pane = resubmit_search_in_pane(pane_hwnd, keyword, wait=max(0.2, scroll_wait * 2))
                    pane_hwnd = int(pane.handle)
                    wait_for_result_cards(pane_hwnd, keyword, timeout=6.0)
                except Exception as e:
                    log(f"  强制重新搜索失败: {e}")
            continue

        if meta.get("is_home"):
            log("  扫到首页特征（最近使用 + 我的常用），不点击图标，离开首页去搜索")
            try:
                pane = leave_home_to_search(pane_hwnd, keyword, wait=max(0.2, scroll_wait * 2))
                pane_hwnd = int(pane.handle)
                cover_streak = 0
            except Exception as e:
                log(f"  离开首页失败: {e}")
                recover_ad()
            empty_streak = 0
            prev_sig = None
            continue

        sig = page_signature(cards)
        if sig and prev_sig is not None and sig == prev_sig:
            stagnant += 1
        elif cards and prev_sig is not None:
            stagnant = 0
        prev_sig = sig if cards else prev_sig

        # 首页残留卡片不当作可点搜索结果
        if not cards:
            empty_streak += 1
            log(f"  空屏 #{empty_streak}，先等待结果加载")
            time.sleep(0.7)
            if empty_streak <= 3:
                continue
            if empty_streak in (4, 6):
                log("  仍无卡片，按广告遮挡恢复")
                recover_ad()
                wait_for_result_cards(pane_hwnd, keyword, timeout=4.0)
            if empty_streak >= 8:
                log("  连续空屏过多，结束本关键词")
                completed = True
                break
            continue

        empty_streak = 0
        rows = group_into_rows(cards, pane_hwnd=pane_hwnd)
        full_screen = screen_looks_full(cards, rows, pane_hwnd, visible_rows=visible_rows)
        stop_after_visible = (not jumped_bottom and full_screen)
        rows_to_use = rows[:visible_rows] if stop_after_visible else rows
        queue_cards: list[tuple[int, int, tuple[str, str, str, int, int]]] = []
        for ri, row in enumerate(rows_to_use):
            for ci, card in enumerate(row):
                queue_cards.append((ri, ci, card))

        next_cards: list[tuple[int, int, str, str, int, int]] = []
        for ri, ci, (key, title, _subtitle, x, y) in queue_cards:
            seen_keys.add(key)
            if key in attempted:
                continue
            if global_dedup and key in global_seen:
                attempted.add(key)
                continue
            next_cards.append((ri, ci, key, title, x, y))

        if not next_cards or (next_cards[0][0] == 0 and next_cards[0][1] == 0):
            log(
                f"  可见 {len(cards)} 个 / {len(rows)} 行"
                f"{'（满屏约 %d 行，点完后拖到底）' % visible_rows if stop_after_visible else ''}"
            )

        clicked_this_screen = 0
        abort_screen = False
        for ri, ci, key, title, x, y in next_cards:
            if max_count > 0 and opened >= max_count:
                completed = True
                break
            log(f"  顺序 行{ri + 1}列{ci + 1}")
            result = click_one(key, title, x, y)
            if result == "ok":
                fail_streak = 0
                clicked_this_screen += 1
                continue
            if result == "ad":
                fail_streak += 1
                recover_ad()
                abort_screen = True
                prev_sig = None
                break
            fail_streak += 1
            if fail_streak >= 2:
                recover_ad()
                fail_streak = 0
                abort_screen = True
                prev_sig = None
                break

        if completed:
            break
        if abort_screen:
            continue

        if max_count > 0 and opened >= max_count:
            completed = True
            break

        # 本屏点完：拖到底，点底部新出现的未点卡片，再换词。
        if not jumped_bottom:
            log(f"  本屏已点完（本词 {opened}/{max_count or '∞'}），拖到底继续点")
            drag_results_to(_HwndOnly(pane_hwnd), "bottom")
            time.sleep(0.4)
            extra = scan_cards_safe(pane_hwnd, timeout=6.0)
            if not extra:
                time.sleep(0.5)
                extra = scan_cards_safe(pane_hwnd, timeout=5.0)
            clicked_extra = 0
            if extra:
                rows_extra = group_into_rows(extra, pane_hwnd=pane_hwnd)
                extra_queue = [
                    (ri, ci, card)
                    for ri, row in enumerate(rows_extra)
                    for ci, card in enumerate(row)
                ]
                pending = [
                    item
                    for item in extra_queue
                    if item[2][0] not in attempted
                    and not (global_dedup and item[2][0] in global_seen)
                ]
                log(f"  底部可见 {len(extra)} 个 / {len(rows_extra)} 行，未点 {len(pending)}")
                for ri, ci, (key, title, _subtitle, x, y) in extra_queue:
                    seen_keys.add(key)
                    if key in attempted:
                        continue
                    if global_dedup and key in global_seen:
                        attempted.add(key)
                        continue
                    if max_count > 0 and opened >= max_count:
                        break
                    log(f"  顺序 底部 行{ri + 1}列{ci + 1}")
                    result = click_one(key, title, x, y)
                    if result == "ok":
                        clicked_extra += 1
                        fail_streak = 0
                        continue
                    if result == "ad":
                        recover_ad()
                        break
                    fail_streak += 1
                    if fail_streak >= 2:
                        recover_ad()
                        break
            else:
                log("  底部没有扫到卡片")
            jumped_bottom = True
            persist("running")
            log(f"  已到底（本词 {opened}/{max_count or '∞'}，底部新点 {clicked_extra}），换下一词")
            completed = True
            break

        log(f"  已到底（本词 {opened}/{max_count or '∞'}），换下一词")
        completed = True
        break

    close_all_new_windows(pane_hwnd, baseline)
    try:
        log("  一次拖回顶部，确认「小程序」和搜索框")
        drag_results_to(_HwndOnly(pane_hwnd), "top")
        log("  已拖回顶部，准备搜下一词")
    except Exception as e:
        log(f"  拖回顶部失败: {e}")
    persist("done" if completed else "partial")
    return opened, failed, max(len(seen_keys), int(keyword_state.get("seen", 0) or 0)), completed


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def run_supervisor() -> int:
    """卡死时看门狗会让子进程退出；这里接着进度自动拉起，鼠标左上角仍会停。"""
    env = os.environ.copy()
    env["_CLICK_WORKER"] = "1"
    script = str(Path(__file__).resolve())
    cmd = [sys.executable, "-X", "utf8", "-u", script, *sys.argv[1:]]
    cwd = str(Path(__file__).resolve().parent.parent)
    n = 0
    while True:
        n += 1
        print(f"[supervisor] 启动点击进程 #{n}", flush=True)
        p = subprocess.Popen(cmd, env=env, cwd=cwd)
        try:
            rc = int(p.wait() or 0)
        except KeyboardInterrupt:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()
            return 130
        if rc in (0, 130):
            if rc == 130:
                print("[supervisor] 用户停止，不再重启", flush=True)
            return rc
        print(f"[supervisor] 进程退出码 {rc}，3 秒后接着进度重启", flush=True)
        time.sleep(3)


def main() -> int:
    parser = argparse.ArgumentParser(description="Windows 微信小程序快速点击/关闭采集器")
    parser.add_argument("--name", action="append", default=[])
    parser.add_argument("--from-list")
    parser.add_argument("--fuzz", action="store_true", help="使用内置关键词库")
    parser.add_argument("--loop", action="store_true", help="同 --fuzz（兼容旧参数）")
    parser.add_argument("--letter-start", default="E", help="字母关键词起点，默认 E；A-D 已跑过时保持 E")
    parser.add_argument("--target", type=int, default=0, help="全局成功打开目标数，0=跑完关键词")
    parser.add_argument("--max-per-keyword", type=int, default=50, help="单次搜索最多点击数量，默认 50；0=不限制")
    parser.add_argument("--visible-rows", type=int, default=VISIBLE_RESULT_ROWS,
                        help="不拖滚动条时可见行数，点完该行后拖到底，默认 11")
    parser.add_argument("--close-every", type=int, default=0, help=argparse.SUPPRESS)

    parser.add_argument("--launch-timeout", type=float, default=2.2, help="等待小程序窗口出现的秒数")
    parser.add_argument("--dwell", type=float, default=2.0, help="点开后驻留秒数再关闭，默认 2；关完才点下一个")
    parser.add_argument("--search-wait", type=float, default=1.2, help="输入关键词后等待结果刷出的秒数")
    parser.add_argument("--scroll-wait", type=float, default=0.07)
    parser.add_argument("--stagnant-rounds", type=int, default=3, help="页面连续几次完全不动才结束")
    parser.add_argument("--max-scroll-rounds", type=int, default=20)

    parser.add_argument("--refine-threshold", type=int, default=40,
                        help="结果较多时，优先从当前词多派生几个子词")
    parser.add_argument("--max-prefix-len", type=int, default=4,
                        help="英文字母前缀最大细分长度")
    parser.add_argument("--mutate-per-keyword", type=int, default=6,
                        help="每搜完一个词，最多新派生几个从未搜过的词")
    parser.add_argument("--no-mutate", action="store_true",
                        help="关闭无限变异，只用初始关键词列表")
    parser.add_argument("--no-semantic-expand", action="store_true",
                        help="关闭 城市<->行业 的自适应组合扩展")
    parser.add_argument("--no-global-dedup", action="store_true",
                        help="关闭跨关键词去重；覆盖率更激进，但会大量重复点击")

    parser.add_argument("--progress", default=str(DEFAULT_PROGRESS))
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.max_per_keyword < 0:
        parser.error("--max-per-keyword 必须 >= 0")
    if args.stagnant_rounds <= 0:
        parser.error("--stagnant-rounds 必须 > 0")
    if args.visible_rows <= 0:
        parser.error("--visible-rows 必须 > 0")
    if args.dwell < 0:
        parser.error("--dwell 必须 >= 0")

    if args.mutate_per_keyword < 0:
        parser.error("--mutate-per-keyword 必须 >= 0")

    pyautogui.FAILSAFE = True
    pyautogui.PAUSE = 0

    seeds: list[str] = list(args.name)
    if args.from_list:
        with open(args.from_list, "r", encoding="utf-8-sig") as f:
            seeds += [x.strip().split("#")[0].strip() for x in f if x.strip()]
    if args.fuzz or args.loop or not seeds:
        seeds += build_seed_keywords(args.letter_start)
    seeds = unique(seeds)
    do_mutate = not args.no_mutate

    if args.dry_run:
        used: set[str] = set()
        mut = UniqueMutator(used, letter_start=args.letter_start)
        preview = []
        for s in seeds:
            if s not in used:
                used.add(s)
                preview.append(s)
        preview += mut.take(80)
        for i, k in enumerate(preview, 1):
            print(i, k)
        print(f"# unique={len(set(preview))} total={len(preview)} mutate={do_mutate}")
        return 0

    if os.environ.get("_CLICK_WORKER") != "1":
        return run_supervisor()

    start_watchdog()

    pane = ensure_miniprogram_pane()
    pane_hwnd = int(pane.handle)
    progress_path = Path(args.progress)
    prev = {} if args.no_resume else load_progress(progress_path)

    progress: dict[str, Any] = {
        "version": "clickonly-v3",
        "started_at": prev.get("started_at") or datetime.now().isoformat(timespec="seconds"),
        "keywords": dict(prev.get("keywords") or {}),
        "queue": list(prev.get("queue") or seeds),
        "opened_total": int(prev.get("opened_total", 0) or 0),
        "global_seen": list(prev.get("global_seen") or []),
        "used_searches": list(prev.get("used_searches") or []),
    }

    queue = unique(progress["queue"] + seeds)
    queued = set(queue)
    used_searches = set(str(x) for x in progress.get("used_searches") or [])
    used_searches |= set(progress["keywords"].keys())
    used_searches |= queued
    mutator = UniqueMutator(used_searches, letter_start=args.letter_start)
    global_seen = set(str(x) for x in progress.get("global_seen", []))
    global_dedup = not args.no_global_dedup

    def persist_queue() -> None:
        progress["queue"] = queue
        progress["used_searches"] = list(used_searches)
        progress["global_seen"] = list(global_seen)
        try:
            save_progress(progress_path, progress)
        except OSError as e:
            log(f"  队列进度写入失败，继续: {e}")

    def enqueue(words: list[str]) -> int:
        added = 0
        for w in words:
            if not w or w in queued:
                continue
            queued.add(w)
            used_searches.add(w)
            queue.append(w)
            added += 1
        return added

    log(f"关键词初始 {len(queue)} 个 | 当前累计打开 {progress['opened_total']}")
    log("流程：首页只搜索 → 结果 3 列顺序点 → 拖到底 → 不满 50 立刻下一词")
    log(f"点开后驻留 {args.dwell:.1f}s 再关闭；无关页覆盖时点顶栏第二个「关键词_搜索」")
    log(f"单次搜索上限: {'无限' if args.max_per_keyword == 0 else args.max_per_keyword}")
    log(f"搜索变异: {'无限且不重复' if do_mutate else '关闭'}")
    log(f"跨关键词去重: {'开启(标题+描述)' if global_dedup else '关闭，允许重复点击'}")

    i = 0
    try:
        while True:
            if args.target > 0 and int(progress.get("opened_total", 0)) >= args.target:
                log(f"达到目标 {args.target}")
                break

            if i >= len(queue):
                if not do_mutate:
                    break
                extra = mutator.take(16)
                if not extra:
                    log("变异空间已用尽，结束")
                    break
                n = enqueue(extra)
                log(f"  队列补词 +{n}: {', '.join(extra[:8])}{'…' if n > 8 else ''}")
                persist_queue()
                continue

            keyword = queue[i]
            i += 1
            item = progress["keywords"].get(keyword)
            if isinstance(item, dict) and item.get("completed") is True and not args.no_resume:
                continue

            log(f"\n====== [{i}/{len(queue)}] {keyword} | total={progress['opened_total']} ======")
            pane_hwnd = recover_miniprogram_pane_if_needed(pane_hwnd)
            pane = wrap(pane_hwnd)
            focus_hwnd(pane_hwnd)
            try:
                pane = search_keyword(pane, keyword, wait=args.search_wait)
                pane_hwnd = int(pane.handle)
            except Exception as e:
                log(f"搜索失败 {keyword}: {e}")
                if is_com_dead(e):
                    log("  UIA 失效，重连后重试同一关键词（不跳过）")
                    reset_uia()
                    time.sleep(0.6)
                    try:
                        pane_hwnd = int(find_miniprogram_pane().handle)
                    except Exception:
                        pass
                    i -= 1
                    continue
                progress["keywords"][keyword] = {
                    "status": "search_fail", "completed": True, "error": str(e)
                }
                used_searches.add(keyword)
                if do_mutate:
                    extra = mutator.from_parent(
                        keyword,
                        limit=max(2, args.mutate_per_keyword),
                        max_prefix_len=args.max_prefix_len,
                        semantic=not args.no_semantic_expand,
                    )
                    n = enqueue(extra)
                    if n:
                        log(f"  失败后变异 +{n}: {', '.join(extra)}")
                persist_queue()
                continue

            old = progress["keywords"].get(keyword)
            if not isinstance(old, dict):
                old = {}

            opened, failed, seen_count, completed = crawl_keyword(
                pane_hwnd,
                keyword,
                max_count=args.max_per_keyword,
                launch_timeout=args.launch_timeout,
                dwell=args.dwell,
                scroll_wait=args.scroll_wait,
                stagnant_rounds=args.stagnant_rounds,
                max_scroll_rounds=args.max_scroll_rounds,
                global_seen=global_seen,
                keyword_state=old,
                progress=progress,
                progress_path=progress_path,
                global_dedup=global_dedup,
                visible_rows=args.visible_rows,
            )

            progress["keywords"][keyword]["completed"] = completed
            progress["keywords"][keyword]["finished_at"] = datetime.now().isoformat(timespec="seconds")
            used_searches.add(keyword)
            log(f"关键词 {keyword}: seen={seen_count}, opened={opened}, failed={failed}")

            if do_mutate:
                limit = args.mutate_per_keyword
                if seen_count >= args.refine_threshold:
                    limit = max(limit, args.mutate_per_keyword + 4)
                extra = mutator.from_parent(
                    keyword,
                    limit=limit,
                    max_prefix_len=args.max_prefix_len,
                    semantic=not args.no_semantic_expand,
                )
                n = enqueue(extra)
                if n:
                    log(f"  变异 +{n}（不重复）: {', '.join(extra)}")
                pending = len(queue) - i
                if pending < 4:
                    refill = mutator.take(12)
                    n2 = enqueue(refill)
                    if n2:
                        log(f"  预补队列 +{n2}: {', '.join(refill[:8])}")

            persist_queue()

    except pyautogui.FailSafeException:
        log("FailSafe：鼠标到左上角，停止")
        close_all_new_windows(pane_hwnd, set())
        persist_queue()
        return 130
    except KeyboardInterrupt:
        log("用户中断")
        close_all_new_windows(pane_hwnd, set())
        persist_queue()
        return 130

    progress["finished_at"] = datetime.now().isoformat(timespec="seconds")
    persist_queue()
    log(f"完成：累计成功打开 {progress.get('opened_total', 0)}")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
