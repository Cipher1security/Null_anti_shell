import os
from datetime import datetime

LOG_DIR = None
LOG_FILE_NAME = None
MAX_LOG_SIZE = None
MAX_LOG_FILES = None


def init_logger(settings):
    global LOG_DIR, LOG_FILE_NAME, MAX_LOG_SIZE, MAX_LOG_FILES
    LOG_DIR = settings["log_dir"]
    LOG_FILE_NAME = settings["log_file_name"]
    MAX_LOG_SIZE = settings["max_log_size_mb"] * 1024 * 1024
    MAX_LOG_FILES = settings["max_log_files"]

    os.makedirs(LOG_DIR, exist_ok=True)
    main_log = get_log_path()
    if not os.path.exists(main_log):
        open(main_log, "w", encoding="utf-8").close()


def get_log_path(i=None):
    if i is None:
        return os.path.join(LOG_DIR, LOG_FILE_NAME)
    else:
        return os.path.join(LOG_DIR, f"{LOG_FILE_NAME}.{i}")


def rotate_logs():
    main_file = get_log_path()
    if not os.path.exists(main_file):
        open(main_file, "w", encoding="utf-8").close()

    if os.path.getsize(main_file) >= MAX_LOG_SIZE:
        last_log = get_log_path(MAX_LOG_FILES - 1)
        if os.path.exists(last_log):
            os.remove(last_log)

        for i in range(MAX_LOG_FILES - 1, 0, -1):
            prev = get_log_path(i - 1)
            curr = get_log_path(i)
            if os.path.exists(prev):
                os.rename(prev, curr)

        os.rename(main_file, get_log_path(0))
        open(main_file, "w", encoding="utf-8").close()


def write_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    rotate_logs()
    with open(get_log_path(), "a", encoding="utf-8") as f:
        f.write(full_message + "\n")
