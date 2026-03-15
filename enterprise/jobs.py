import json
import os
import threading
from typing import Any, Dict

from .db_enterprise import claim_next_job, update_job, write_audit_log


_WORKER_LOCK = threading.Lock()
_WORKER_THREAD: threading.Thread | None = None
_WORKER_STOP = threading.Event()


def _parse_input(raw: str | None) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _process_job(job: Dict[str, Any]) -> None:
    job_id = str(job["id"])
    tenant_id = int(job["tenant_id"])
    user_id = job.get("user_id")
    payload = _parse_input(job.get("input_json"))
    job_type = str(job.get("type") or "")

    try:
        if job_type == "export_report":
            from report_generator import generate_report

            out_path = payload.get("out_path")
            path = generate_report(tenant_id=tenant_id, out_path=out_path)
        elif job_type == "compliance_report":
            from compliance_report import generate_compliance_report

            path = generate_compliance_report(tenant_id=tenant_id)
        else:
            raise ValueError(f"Unsupported job type: {job_type}")

        update_job(job_id=job_id, status="done", output_path=path, error=None)
        try:
            write_audit_log(
                tenant_id=tenant_id,
                user_id=user_id,
                action=f"{job_type}.completed",
                target_type="job",
                target_id=job_id,
                metadata={"output_path": path},
            )
        except Exception:
            pass
    except Exception as exc:
        error_msg = str(exc)[:2000]
        update_job(job_id=job_id, status="failed", output_path=None, error=error_msg)
        try:
            write_audit_log(
                tenant_id=tenant_id,
                user_id=user_id,
                action=f"{job_type}.failed",
                target_type="job",
                target_id=job_id,
                metadata={"error": error_msg},
            )
        except Exception:
            pass


def _worker_loop(poll_interval_seconds: float) -> None:
    while not _WORKER_STOP.is_set():
        job = None
        try:
            job = claim_next_job(job_type=None)
        except Exception:
            job = None

        if not job:
            _WORKER_STOP.wait(poll_interval_seconds)
            continue
        _process_job(job)


def start_job_worker() -> None:
    if os.getenv("ENABLE_JOB_WORKER", "true").lower() != "true":
        return
    global _WORKER_THREAD
    with _WORKER_LOCK:
        if _WORKER_THREAD and _WORKER_THREAD.is_alive():
            return
        _WORKER_STOP.clear()
        interval = float(os.getenv("JOB_WORKER_POLL_SECONDS", "1.0"))
        _WORKER_THREAD = threading.Thread(
            target=_worker_loop,
            args=(interval,),
            name="enterprise-job-worker",
            daemon=True,
        )
        _WORKER_THREAD.start()


def stop_job_worker() -> None:
    _WORKER_STOP.set()
