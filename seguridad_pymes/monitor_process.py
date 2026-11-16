"""Owned capture process trees; Windows job ownership precedes first instruction."""
import ctypes
from ctypes import wintypes as wt
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


class ProcessTree:
    def __init__(self, command, *, env, memory_mib=256):
        self.process = None
        self.job = None
        self._lock = threading.Lock()
        self.forced = False
        self.signal_diagnostic = None
        options = {}
        if os.name == 'nt':
            self._create_job(memory_mib)
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = 0
            options = {'creationflags': subprocess.CREATE_NEW_CONSOLE | 0x00000004,
                       'startupinfo': startup}  # CREATE_SUSPENDED
        else:
            options['start_new_session'] = True
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL, text=True, encoding='utf-8', errors='replace',
                bufsize=1, env=env, **options)
            if os.name == 'nt':
                if not self.kernel.AssignProcessToJobObject(self.job, int(self.process._handle)):
                    raise ctypes.WinError(ctypes.get_last_error())
                self._resume()
        except BaseException:
            if self.process is not None:
                self.process.kill()
                self.process.wait()
                self.process.stdout.close()
                self.process.stderr.close()
            self._close_job()
            raise

    def _create_job(self, memory_mib):
        size_t = ctypes.c_size_t

        class Basic(ctypes.Structure):
            _fields_ = [('ProcessTime', ctypes.c_longlong), ('JobTime', ctypes.c_longlong),
                        ('Flags', wt.DWORD), ('MinWS', size_t), ('MaxWS', size_t),
                        ('Active', wt.DWORD), ('Affinity', size_t), ('Priority', wt.DWORD), ('Scheduling', wt.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ['ReadOps', 'WriteOps', 'OtherOps', 'ReadBytes', 'WriteBytes', 'OtherBytes']]

        class Extended(ctypes.Structure):
            _fields_ = [('Basic', Basic), ('IO', IO), ('ProcessMemory', size_t), ('JobMemory', size_t),
                        ('PeakProcessMemory', size_t), ('PeakJobMemory', size_t)]

        k = self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        k.CreateJobObjectW.argtypes, k.CreateJobObjectW.restype = [ctypes.c_void_p, wt.LPCWSTR], wt.HANDLE
        k.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
        k.SetInformationJobObject.restype = wt.BOOL
        k.AssignProcessToJobObject.argtypes, k.AssignProcessToJobObject.restype = [wt.HANDLE, wt.HANDLE], wt.BOOL
        k.CloseHandle.argtypes, k.CloseHandle.restype = [wt.HANDLE], wt.BOOL
        self.job = k.CreateJobObjectW(None, None)
        if not self.job:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.Basic.Flags = 0x2000 | 0x200  # KILL_ON_JOB_CLOSE | JOB_MEMORY
        limits.JobMemory = memory_mib * 1024**2
        if not k.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self._close_job()
            raise ctypes.WinError(ctypes.get_last_error())

    def _resume(self):
        class ThreadEntry(ctypes.Structure):
            _fields_ = [('size', wt.DWORD), ('usage', wt.DWORD), ('tid', wt.DWORD),
                        ('pid', wt.DWORD), ('base', wt.LONG), ('delta', wt.LONG), ('flags', wt.DWORD)]
        k = self.kernel
        k.CreateToolhelp32Snapshot.argtypes, k.CreateToolhelp32Snapshot.restype = [wt.DWORD, wt.DWORD], wt.HANDLE
        k.Thread32First.argtypes = k.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(ThreadEntry)]
        k.OpenThread.argtypes, k.OpenThread.restype = [wt.DWORD, wt.BOOL, wt.DWORD], wt.HANDLE
        k.ResumeThread.argtypes, k.ResumeThread.restype = [wt.HANDLE], wt.DWORD
        snapshot = k.CreateToolhelp32Snapshot(4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        entry = ThreadEntry()
        entry.size = ctypes.sizeof(entry)
        resumed = False
        try:
            found = k.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.pid == self.process.pid:
                    handle = k.OpenThread(2, False, entry.tid)
                    if not handle:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if k.ResumeThread(handle) == 0xffffffff:
                            raise ctypes.WinError(ctypes.get_last_error())
                        resumed = True
                    finally:
                        k.CloseHandle(handle)
                    break
                found = k.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            k.CloseHandle(snapshot)
        if not resumed:
            raise OSError('No se pudo reanudar el proceso de captura bajo su Job Object.')

    def rss(self):
        import psutil
        try:
            parent = psutil.Process(self.process.pid)
            total = 0
            for member in [parent, *parent.children(recursive=True)]:
                try:
                    total += member.memory_info().rss
                except psutil.NoSuchProcess:
                    pass
            return total
        except psutil.NoSuchProcess:
            return 0

    def _close_job(self):
        if self.job:
            self.kernel.CloseHandle(self.job)
            self.job = None

    def close(self):
        import psutil
        with self._lock:
            if self.process is None:
                return
            process = self.process
            try:
                members = psutil.Process(process.pid).children(recursive=True)
            except psutil.NoSuchProcess:
                members = []
            if process.poll() is None:
                try:
                    if os.name == 'nt':
                        base = Path(sys.base_prefix) / 'python.exe'
                        signal_result = subprocess.run([str(base), '-I', '-B', str(Path(__file__).resolve()), '--break', str(process.pid)],
                            timeout=2, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                        self.signal_diagnostic = {'returncode': signal_result.returncode,
                            'stderr': signal_result.stderr.decode('utf-8', errors='replace')[-1500:]}
                    else:
                        os.killpg(process.pid, signal.SIGINT)
                    process.wait(timeout=4)
                except (OSError, subprocess.SubprocessError):
                    self.forced = True
                    if os.name == 'nt':
                        self._close_job()
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=4)
            self._close_job()  # also removes surviving descendants after root exit
            psutil.wait_procs(members, timeout=3)

    def close_pipes(self):
        self.process.stdout.close()
        self.process.stderr.close()


def console_break(pid):
    """Helper has its own lifetime; never attaches the Streamlit process console."""
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.FreeConsole()  # some Windows Python launchers attach a console despite CREATE_NO_WINDOW
    if not k.AttachConsole(pid):
        print(f'AttachConsole failed: {ctypes.get_last_error()}', file=sys.stderr)
        return 2
    callback_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.DWORD)
    handler = callback_type(lambda code: True)
    k.SetConsoleCtrlHandler.argtypes = [callback_type, wt.BOOL]
    k.SetConsoleCtrlHandler(handler, True)
    success = k.GenerateConsoleCtrlEvent(1, 0)
    if not success:
        print(f'GenerateConsoleCtrlEvent failed: {ctypes.get_last_error()}', file=sys.stderr)
    time.sleep(0.05)
    k.FreeConsole()
    return 0 if success else 2


if __name__ == '__main__':
    if os.name != 'nt' or len(sys.argv) != 3 or sys.argv[1] != '--break':
        raise SystemExit(2)
    raise SystemExit(console_break(int(sys.argv[2])))
