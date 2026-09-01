"""
Celery Beat Periodic Scheduler Runner Script — Windows & Linux Safe.

Usage:
  python run_celery_beat.py
"""
import sys
import subprocess
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')

def cleanup_stale_locks():
    for f in ["celerybeat-schedule", "celerybeat-schedule.db", "celerybeat.pid"]:
        p = Path(f)
        if p.exists():
            try:
                p.unlink()
                print(f"🧹 Removed stale beat lock file: {f}")
            except Exception:
                pass

if __name__ == "__main__":
    cleanup_stale_locks()
    
    cmd = [
        sys.executable,
        "-m", "celery",
        "-A", "app.core.celery_app.celery_app",
        "beat",
        "--loglevel=info"
    ]
    
    print("⏰ Starting Celery Beat Periodic Scheduler...")
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n🛑 Celery Beat stopped cleanly.")
