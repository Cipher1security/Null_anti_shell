import json
from core import logger, monitor, scanner

with open("config/settings.json", "r") as f:
    settings = json.load(f)

logger.init_logger(settings)
scanner.init_quarantine_dir(settings)

if __name__ == "__main__":
    print("Null anti-shell [1.0.0] Started...")
    monitor.start_monitoring(settings["home_dirs"], settings["monitor_recursive"])
