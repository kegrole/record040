"""Load Kubernetes workload manifests and normalize them for auditing."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import yamlmini

WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Pod")


@dataclass
class Workload:
    name: str
    kind: str
    namespace: str
    pod_spec: dict
    source: str
    labels: dict = field(default_factory=dict)

    @property
    def containers(self) -> list[dict]:
        return list(self.pod_spec.get("containers") or [])

    @property
    def init_containers(self) -> list[dict]:
        return list(self.pod_spec.get("initContainers") or [])

    @property
    def volumes(self) -> list[dict]:
        return list(self.pod_spec.get("volumes") or [])


def _pod_spec(document: dict) -> dict | None:
    kind = document.get("kind")
    if kind == "Pod":
        return document.get("spec")
    template = (
        document.get("spec", {}).get("template", {}).get("spec")
    )
    return template


def _workload_from_document(document: Any, source: str) -> Workload | None:
    if not isinstance(document, dict):
        return None
    kind = document.get("kind")
    if kind not in WORKLOAD_KINDS:
        return None
    metadata = document.get("metadata") or {}
    name = metadata.get("name") or "<unnamed>"
    namespace = metadata.get("namespace") or "default"
    labels = metadata.get("labels") or {}
    pod_spec = _pod_spec(document) or {}
    if not isinstance(pod_spec, dict):
        pod_spec = {}
    return Workload(
        name=name,
        kind=kind,
        namespace=namespace,
        pod_spec=pod_spec,
        source=source,
        labels=labels,
    )


def iter_manifest_documents(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    for document in yamlmini.load_all(text):
        if isinstance(document, dict):
            yield document


def load_workloads(manifests_dir: str) -> list[Workload]:
    """Load every supported workload found under *manifests_dir*."""
    paths: list[str] = []
    if os.path.isfile(manifests_dir):
        paths = [manifests_dir]
    else:
        for root, _dirs, files in os.walk(manifests_dir):
            for filename in sorted(files):
                if filename.endswith((".yaml", ".yml")):
                    paths.append(os.path.join(root, filename))

    workloads: list[Workload] = []
    for path in sorted(paths):
        for document in iter_manifest_documents(path):
            workload = _workload_from_document(document, path)
            if workload is not None:
                workloads.append(workload)
    return workloads
