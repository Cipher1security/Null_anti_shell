from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from queue import Queue
from threading import Thread
import os
import time
from .logger import write_log
from core.scanner import scan_file, quarantine_file

HOME_DIRS = None
MONITOR_RECURSIVE = None
EVENT_COOLDOWN = None
NUM_WORKERS = None
TASK_QUEUE_SIZE = None
SCAN_CACHE_TIMEOUT = None

task_queue = Queue(maxsize=TASK_QUEUE_SIZE)
last_event = {}
scan_cache = {}

def wait_for_stable_file(path, check_delay=0.3, timeout=5):
    start = time.time()
    last_size = -1

    try:
        while time.time() - start < timeout:
            if not os.path.exists(path):
                return False

            if os.path.isdir(path):
                return False

            new_size = os.path.getsize(path)
            if new_size == last_size:
                return True

            last_size = new_size
            time.sleep(check_delay)

        return False

    except Exception:
        return False

def worker():
    while True:
        path = task_queue.get()
        skip = False
        file_hash = None
        risk = 0
        alerts = []

        try:
            if not os.path.exists(path) or os.path.isdir(path):
                skip = True

            if not skip:
                stable = wait_for_stable_file(path)
                if not stable:
                    write_log(f"[INFO] File still being written (skipping for now): {path}")
                    skip = True

            if not skip:
                risk, alerts, file_hash = scan_file(path)

                now = time.time()
                if file_hash:
                    last_scan = scan_cache.get(file_hash)
                    if last_scan and (now - last_scan) < SCAN_CACHE_TIMEOUT:
                        write_log(f"[DEBUG] Recently scanned (cache) {path} | hash={file_hash}")
                        skip = True
                    else:
                        scan_cache[file_hash] = now

            if not skip:
                if risk > 0:
                    write_log(f"[ALERT] Suspicious file: {path} | Risk={risk} | Alerts={alerts}")

                if 60 <= risk < 90:
                    try:
                        new_path = quarantine_file(path)
                        write_log(f"[QUARANTINE] {path} -> {new_path} | hash={file_hash}")
                    except Exception as e:
                        write_log(f"[ERROR] Quarantine failed {path}: {e}")

                elif risk >= 90:
                    try:
                        os.remove(path)
                        write_log(f"[DELETE] High-risk: {path} | hash={file_hash}")
                    except Exception as e:
                        write_log(f"[ERROR] Delete failed {path}: {e}")

        except Exception as e:
            write_log(f"[ERROR] Worker crashed while processing {path}: {e}")

        finally:
            try:
                task_queue.task_done()
            except Exception as e:
                write_log(f"[ERROR] task_done() exception: {e}")

def watchdog(threads):
    while True:
        for i, t in enumerate(threads):
            if not t.is_alive():
                write_log("[CRITICAL] Worker thread died! Restarting...")
                new_t = Thread(target=worker, daemon=True)
                new_t.start()
                threads[i] = new_t
        time.sleep(1)

class MonitorHandler(FileSystemEventHandler):

    def push_event(self, path):
        now = time.time()
        prev = last_event.get(path, 0)

        if now - prev < EVENT_COOLDOWN:
            return

        last_event[path] = now

        if task_queue.full():
            write_log("[WARN] Task queue full, skipping event for: " + path)
            return

        try:
            task_queue.put_nowait(path)
        except Exception:
            write_log("[WARN] Failed to enqueue: " + path)

    def on_created(self, event):
        write_log(f"[CREATE] {event.src_path}")
        self.push_event(event.src_path)

    def on_modified(self, event):
        write_log(f"[MODIFY] {event.src_path}")
        self.push_event(event.src_path)

def cleanup_last_event(max_age=60):
    now = time.time()
    to_remove = [p for p, t in last_event.items() if now - t > max_age]
    for p in to_remove:
        try:
            del last_event[p]
        except KeyError:
            pass
def cleanup_scan_cache(max_age=None):
    global SCAN_CACHE_TIMEOUT
    if max_age is None:
        max_age = (SCAN_CACHE_TIMEOUT or 10) * 4

    now = time.time()
    to_remove = [h for h, t in scan_cache.items() if now - t > max_age]
    for h in to_remove:
        try:
            del scan_cache[h]
        except KeyError:
            pass

def cleaner_thread():
    while True:
        try:
            cleanup_last_event()
            cleanup_scan_cache()
        except Exception as e:
            write_log(f"[ERROR] Cleaner thread exception: {e}")
        time.sleep(30)

def start_monitoring(
    home_dirs,
    recursive=True,
    event_cooldown=1.2,
    num_workers=None,
    task_queue_size=5000,
    scan_cache_timeout=10
):
    global EVENT_COOLDOWN, NUM_WORKERS, TASK_QUEUE_SIZE, SCAN_CACHE_TIMEOUT, task_queue

    EVENT_COOLDOWN = event_cooldown
    NUM_WORKERS = num_workers or max(2, (os.cpu_count() or 2) * 2)
    TASK_QUEUE_SIZE = task_queue_size
    SCAN_CACHE_TIMEOUT = scan_cache_timeout

    task_queue = Queue(maxsize=TASK_QUEUE_SIZE)

    threads = []
    for _ in range(NUM_WORKERS):
        t = Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    Thread(target=watchdog, args=(threads,), daemon=True).start()

    Thread(target=cleaner_thread, daemon=True).start()

    observers = []
    handler = MonitorHandler()

    for home in home_dirs:
        if not os.path.exists(home):
            continue

        observer = Observer()
        observer.schedule(handler, home, recursive=recursive)
        observer.start()
        observers.append(observer)

        write_log(f"[INFO] Monitoring started on: {home}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for obs in observers:
            obs.stop()

    for obs in observers:
        obs.join()
