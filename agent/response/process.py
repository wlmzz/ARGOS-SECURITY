import logging

import psutil

log = logging.getLogger("argos.process")

# PIDs that must never be suspended or terminated: init, kernel threads, Windows System
PROTECTED_PIDS = {0, 1, 2, 4}


class ProcessController:
    """Suspend, resume, and terminate processes by PID."""

    def suspend(self, pid: int) -> bool:
        """Suspend (SIGSTOP) a process. Returns True on success."""
        if pid in PROTECTED_PIDS:
            log.warning(f"[Process] Refusing to suspend protected PID {pid}")
            return False
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            log.warning(f"[Process] Suspended PID {pid} ({proc.name()})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            log.error(f"[Process] Cannot suspend PID {pid}: {e}")
            return False

    def resume(self, pid: int) -> bool:
        """Resume (SIGCONT) a suspended process. Returns True on success."""
        try:
            proc = psutil.Process(pid)
            proc.resume()
            log.info(f"[Process] Resumed PID {pid}")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            log.error(f"[Process] Cannot resume PID {pid}: {e}")
            return False

    def terminate(self, pid: int) -> bool:
        """Send SIGTERM to a process. Returns True on success."""
        if pid in PROTECTED_PIDS:
            log.warning(f"[Process] Refusing to terminate protected PID {pid}")
            return False
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            log.warning(f"[Process] Terminated PID {pid} ({proc.name()})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            log.error(f"[Process] Cannot terminate PID {pid}: {e}")
            return False
