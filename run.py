#!/usr/bin/env python3
"""
RansomwareGuard — Full System Launcher
Starts all components: file monitor, process monitor, ML engine,
backup system, honeypot, and web dashboard together.
"""

import sys
import os
import time
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from utils.config import Config
from utils.logger import setup_logger
from utils.alert_manager import AlertManager
from core.entropy_analyzer import EntropyAnalyzer
from core.process_monitor import ProcessMonitor
from core.threat_engine import ThreatEngine
from core.response_engine import ResponseEngine
from core.file_monitor import FileSystemMonitor
from backup.snapshot_manager import SnapshotManager
from backup.backup_vault import BackupVault
from honeypot.canary_manager import CanaryManager
from ml.anomaly_detector import AnomalyDetector
from ui.dashboard_server import run_dashboard


def launch(watch_dir: str = "./test_directory",
           backup_dir: str = "./backups",
           port: int = 5000,
           demo: bool = False):

    logger = setup_logger("RansomwareGuard", "logs/ransomguard.log")

    watch_dir  = Path(watch_dir);  watch_dir.mkdir(parents=True, exist_ok=True)
    backup_dir = Path(backup_dir); backup_dir.mkdir(parents=True, exist_ok=True)

    print("\n  🛡️  Initializing RansomwareGuard components...\n")

    # ── Init all components ──────────────────────────────────────
    config           = Config()
    alert_manager    = AlertManager(config)
    entropy_analyzer = EntropyAnalyzer()
    anomaly_detector = AnomalyDetector()
    snapshot_manager = SnapshotManager(str(watch_dir), str(backup_dir))
    backup_vault     = BackupVault(str(backup_dir))
    canary_manager   = CanaryManager(str(watch_dir))
    response_engine  = ResponseEngine(snapshot_manager, backup_vault, alert_manager)
    threat_engine    = ThreatEngine(entropy_analyzer, anomaly_detector, response_engine)
    process_monitor  = ProcessMonitor(threat_engine)
    file_monitor     = FileSystemMonitor(str(watch_dir), threat_engine, canary_manager)

    # ── Plant canaries ───────────────────────────────────────────
    n = canary_manager.plant_canaries()
    print(f"  🍯 Planted {n} honeypot canary files")

    # ── Initial snapshot ─────────────────────────────────────────
    snap_id = snapshot_manager.create_snapshot("initial")
    print(f"  💾 Initial snapshot: {snap_id}")

    # ── Start monitors ───────────────────────────────────────────
    file_monitor.start()
    process_monitor.start()
    print(f"  👁  File system monitor active: {watch_dir.absolute()}")
    print(f"  🔬 Process monitor active")

    # ── Start dashboard ──────────────────────────────────────────
    run_dashboard(threat_engine, snapshot_manager, backup_vault,
                  canary_manager, response_engine, port=port)

    # ── Demo mode ────────────────────────────────────────────────
    if demo:
        from utils.demo_simulator import DemoSimulator
        sim = DemoSimulator(str(watch_dir), threat_engine)
        threading.Thread(target=sim.run_demo, daemon=True).start()
        print(f"  🎬 Demo simulation started")

    print(f"\n  ✅ RansomwareGuard ACTIVE")
    print(f"  📊 Dashboard : http://localhost:{port}")
    print(f"  📁 Watching  : {watch_dir.absolute()}")
    print(f"  💾 Backups   : {backup_dir.absolute()}")
    print(f"  Press Ctrl+C to stop\n")
    print("  " + "─"*50)

    # Auto-open browser
    time.sleep(1)
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

    try:
        while True:
            stats = threat_engine.get_stats()
            print(f"\r  [LIVE] Events: {stats['events']:5d} | "
                  f"Threats: {stats['threats']:3d} | "
                  f"Blocked: {stats['blocked']:3d}", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Shutting down...")
        file_monitor.stop()
        process_monitor.stop()
        threat_engine.print_summary()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--watch",  default="./test_directory")
    p.add_argument("--backup", default="./backups")
    p.add_argument("--port",   default=5000, type=int)
    p.add_argument("--demo",   action="store_true")
    args = p.parse_args()
    launch(args.watch, args.backup, args.port, args.demo)
