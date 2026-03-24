"""
RansomwareGuard - Advanced Ransomware Detection & File Recovery System
Entry Point
"""

import os
import sys
import time
import threading
import argparse
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.file_monitor import FileSystemMonitor
from core.entropy_analyzer import EntropyAnalyzer
from core.process_monitor import ProcessMonitor
from core.threat_engine import ThreatEngine
from core.response_engine import ResponseEngine
from honeypot.canary_manager import CanaryManager
from backup.snapshot_manager import SnapshotManager
from backup.backup_vault import BackupVault
from ml.anomaly_detector import AnomalyDetector
from utils.logger import setup_logger
from utils.config import Config
from utils.alert_manager import AlertManager

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗  ║
║    ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║  ║
║    ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║  ║
║    ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║  ║
║    ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║  ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ║
║                   G U A R D  v1.0.0                          ║
║         Advanced Ransomware Detection & Recovery             ║
╚══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(description="RansomwareGuard - Protection System")
    parser.add_argument("--watch", "-w", default="./test_directory",
                        help="Directory to monitor (default: ./test_directory)")
    parser.add_argument("--backup", "-b", default="./backups",
                        help="Backup vault directory (default: ./backups)")
    parser.add_argument("--config", "-c", default="./config.json",
                        help="Config file path")
    parser.add_argument("--demo", action="store_true",
                        help="Run demo simulation")
    parser.add_argument("--train", action="store_true",
                        help="Train ML model on current directory")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch web dashboard only")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    # Setup logging
    logger = setup_logger("RansomwareGuard", "logs/ransomguard.log")
    logger.info("RansomwareGuard starting up...")

    # Load config
    config = Config(args.config)

    # Create watch directory if not exists
    watch_dir = Path(args.watch)
    watch_dir.mkdir(parents=True, exist_ok=True)

    backup_dir = Path(args.backup)
    backup_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] Monitoring directory : {watch_dir.absolute()}")
    print(f"[*] Backup vault         : {backup_dir.absolute()}")
    print(f"[*] Log file             : logs/ransomguard.log\n")

    # Initialize components
    alert_manager   = AlertManager(config)
    entropy_analyzer = EntropyAnalyzer()
    anomaly_detector = AnomalyDetector()
    snapshot_manager = SnapshotManager(str(watch_dir), str(backup_dir))
    backup_vault     = BackupVault(str(backup_dir))
    canary_manager   = CanaryManager(str(watch_dir))
    response_engine  = ResponseEngine(snapshot_manager, backup_vault, alert_manager)
    threat_engine    = ThreatEngine(entropy_analyzer, anomaly_detector, response_engine)
    process_monitor  = ProcessMonitor(threat_engine)
    file_monitor     = FileSystemMonitor(str(watch_dir), threat_engine, canary_manager)

    # Train ML model
    if args.train:
        print("[*] Training anomaly detection model...")
        anomaly_detector.train(str(watch_dir))
        print("[+] Training complete!")
        return

    # Plant canary files
    print("[*] Planting honeypot canary files...")
    canary_manager.plant_canaries()
    print(f"[+] {len(canary_manager.canary_files)} canary files planted\n")

    # Initial snapshot
    print("[*] Creating initial file snapshot...")
    snapshot_manager.create_snapshot("initial")
    print("[+] Initial snapshot created\n")

    # Run demo if requested
    if args.demo:
        from utils.demo_simulator import DemoSimulator
        simulator = DemoSimulator(str(watch_dir), threat_engine)
        t = threading.Thread(target=simulator.run_demo, daemon=True)
        t.start()

    # Start monitoring
    print("[*] Starting file system monitor...")
    print("[*] Starting process monitor...")
    print("[+] RansomwareGuard is ACTIVE — Press Ctrl+C to stop\n")
    print("=" * 65)

    try:
        file_monitor.start()
        process_monitor.start()

        while True:
            time.sleep(1)
            stats = threat_engine.get_stats()
            print(f"\r[LIVE] Events: {stats['events']:5d} | "
                  f"Threats: {stats['threats']:3d} | "
                  f"Blocked: {stats['blocked']:3d} | "
                  f"Files Protected: {stats['files_protected']:5d}", end="", flush=True)

    except KeyboardInterrupt:
        print("\n\n[*] Shutting down RansomwareGuard...")
        file_monitor.stop()
        process_monitor.stop()
        threat_engine.print_summary()
        print("[+] Goodbye. Stay safe!")


if __name__ == "__main__":
    main()
