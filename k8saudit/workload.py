"""Expand a :class:`Workload` into rule-engine target dictionaries."""

from __future__ import annotations

from typing import Any

from .manifest import Workload

CONTAINER_SCOPES = ("container", "any_container")


def _get_path(obj: Any, dotted_path: str) -> Any:
    current = obj
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def effective_security_context(container: dict, pod_spec: dict) -> dict:
    """Merge pod-level and container-level securityContext.

    Container-level keys win; pod-level values fill gaps so rules can use a
    single path such as ``securityContext.runAsNonRoot``.
    """
    merged = {}
    pod_security = pod_spec.get("securityContext")
    if isinstance(pod_security, dict):
        merged.update(pod_security)
    container_security = container.get("securityContext")
    if isinstance(container_security, dict):
        merged.update(container_security)
    return merged


def _container_target(workload: Workload, container: dict, init: bool) -> dict:
    target = dict(container)
    target["securityContext"] = effective_security_context(
        container, workload.pod_spec
    )
    target["_context"] = {
        "scope": "init_container" if init else "container",
        "workload": workload.name,
        "kind": workload.kind,
        "namespace": workload.namespace,
        "container": container.get("name", "<unnamed>"),
        "init": init,
    }
    return target


def _capability_targets(workload: Workload) -> list[dict]:
    targets: list[dict] = []
    for init, containers in (
        (True, workload.init_containers),
        (False, workload.containers),
    ):
        for container in containers:
            capabilities = _get_path(container, "securityContext.capabilities")
            added = (capabilities or {}).get("add") if isinstance(
                capabilities, dict
            ) else None
            for capability in added or []:
                targets.append(
                    {
                        "capability": capability,
                        "container": container.get("name", "<unnamed>"),
                        "_context": {
                            "scope": "capability",
                            "workload": workload.name,
                            "kind": workload.kind,
                            "namespace": workload.namespace,
                            "container": container.get("name", "<unnamed>"),
                            "init": init,
                        },
                    }
                )
    return targets


def _volume_targets(workload: Workload) -> list[dict]:
    targets: list[dict] = []
    for volume in workload.volumes:
        host_path = volume.get("hostPath")
        if isinstance(host_path, dict):
            targets.append(
                {
                    "volume": volume.get("name", "<unnamed>"),
                    "hostPath": host_path.get("path"),
                    "type": host_path.get("type"),
                    "_context": {
                        "scope": "volume",
                        "workload": workload.name,
                        "kind": workload.kind,
                        "namespace": workload.namespace,
                        "volume": volume.get("name", "<unnamed>"),
                    },
                }
            )
    return targets


def build_targets(workload: Workload) -> list[dict]:
    """Return all audit targets belonging to *workload*.

    Target kinds: pod, container, init_container, capability and volume.
    Every target carries a ``_context`` block used for evidence formatting.
    """
    pod_target = dict(workload.pod_spec)
    pod_target["_context"] = {
        "scope": "pod",
        "workload": workload.name,
        "kind": workload.kind,
        "namespace": workload.namespace,
    }
    targets = [pod_target]
    for container in workload.init_containers:
        targets.append(_container_target(workload, container, init=True))
    for container in workload.containers:
        targets.append(_container_target(workload, container, init=False))
    targets.extend(_capability_targets(workload))
    targets.extend(_volume_targets(workload))
    return targets
