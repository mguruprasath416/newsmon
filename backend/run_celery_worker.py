"""
Celery Worker Runner Script — Windows & Linux Safe.

Usage:
  python run_celery_worker.py
"""
import sys
import platform
import subprocess
sys.stdout.reconfigure(encoding='utf-8')

if __name__ == "__main__":
    is_windows = sys.platform.startswith("win")
    pool_arg = "--pool=solo" if is_windows else "--pool=prefork"
    
    cmd = [
        sys.executable,
        "-m", "celery",
        "-A", "app.core.celery_app.celery_app",
        "worker",
        pool_arg,
        "-Q", "default,collection,digest,lens",
        "--loglevel=info"
    ]
    
    print(f"🚀 Starting Celery Worker ({pool_arg})...")
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n🛑 Celery Worker stopped cleanly.")
