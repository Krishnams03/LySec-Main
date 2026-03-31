"""
LySec - eBPF process event adapter

Optional adapter for process exec visibility using BCC tracepoints.
Designed to fail open: if BCC/kernel support is unavailable, the caller
can safely degrade to proc connector or polling.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

logger = logging.getLogger("lysec.monitor.process.ebpf")


class EbpfExecAdapter:
    """Collects process exec events from kernel tracepoints via BCC."""

    _BPF_TEXT = r"""
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>

    struct data_t {
        u32 pid;
        u32 uid;
        char comm[TASK_COMM_LEN];
        char filename[256];
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(sched, sched_process_exec) {
        struct data_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    """

    def __init__(self):
        self._bpf = None
        self._queue: deque[dict[str, Any]] = deque()

    def start(self) -> bool:
        try:
            from bcc import BPF  # type: ignore
        except Exception as exc:
            logger.warning("BCC import failed: %s", exc)
            return False

        try:
            bpf = BPF(text=self._BPF_TEXT)
            bpf["events"].open_perf_buffer(self._on_event)
            self._bpf = bpf
            logger.info("eBPF exec adapter started")
            return True
        except Exception as exc:
            logger.warning("eBPF adapter setup failed: %s", exc)
            self._bpf = None
            return False

    def stop(self):
        # BCC resources are released when object is dropped.
        self._bpf = None
        self._queue.clear()

    def poll_events(self) -> list[dict[str, Any]]:
        if not self._bpf:
            return []
        try:
            self._bpf.perf_buffer_poll(timeout=0)
        except Exception as exc:
            logger.debug("eBPF perf poll failed: %s", exc)
        events = list(self._queue)
        self._queue.clear()
        return events

    def _on_event(self, cpu: int, data: Any, size: int):
        del cpu, size
        if not self._bpf:
            return
        try:
            evt = self._bpf["events"].event(data)
            self._queue.append(
                {
                    "what": "exec",
                    "pid": int(getattr(evt, "pid", 0) or 0),
                    "uid": int(getattr(evt, "uid", 0) or 0),
                    "comm": bytes(getattr(evt, "comm", b"")).split(b"\x00", 1)[0].decode(
                        "utf-8", errors="replace"
                    ),
                    "filename": bytes(getattr(evt, "filename", b""))
                    .split(b"\x00", 1)[0]
                    .decode("utf-8", errors="replace"),
                }
            )
        except Exception as exc:
            logger.debug("eBPF event decode failure: %s", exc)
