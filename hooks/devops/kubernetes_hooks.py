#!/usr/bin/env python3
"""DevOps: Kubernetes hooks for Codex. 20 PreToolUse/PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("block_kubectl_delete_namespace")
def block_kubectl_delete_namespace(data):
    cmd = get_command(data)
    protected = r"\b(default|kube-system|kube-public|kube-node-lease|production|monitoring)\b"
    if re.search(r"kubectl\s+delete\s+namespace", cmd) and re.search(protected, cmd):
        return deny("K8s: Cannot delete protected namespace. This destroys all resources within it.")
    return allow()

@registry.hook("block_kubectl_delete_all")
def block_kubectl_delete_all(data):
    cmd = get_command(data)
    if re.search(r"kubectl\s+delete\s+.*--all\s+--all-namespaces|kubectl\s+delete\s+all\s+--all", cmd):
        return deny("K8s: Deleting all resources cluster-wide is extremely destructive.")
    return allow()

@registry.hook("block_kubectl_apply_production")
def block_kubectl_apply_production(data):
    cmd = get_command(data)
    if re.search(r"kubectl\s+apply\s+", cmd) and re.search(r"-n\s+production|--namespace\s*=?\s*production", cmd):
        return deny("K8s: Direct apply to production namespace. Use CI/CD pipeline instead.")
    return allow()

@registry.hook("warn_kubectl_run_privileged")
def warn_kubectl_run_privileged(data):
    cmd = get_command(data)
    if re.search(r"kubectl\s+run\s+.*--privileged", cmd) or re.search(r"securityContext.*privileged.*true", cmd):
        return deny("K8s: Privileged pod grants host access. Use specific securityContext capabilities.")
    return allow()

@registry.hook("detect_pod_crash_loop")
def detect_pod_crash_loop(data):
    output = get_command_output(data)
    if not output: return allow()
    crashes = re.findall(r"CrashLoopBackOff", output)
    if crashes:
        return post_tool_context(f"K8s: {len(crashes)} pods in CrashLoopBackOff. Check logs: kubectl logs <pod> --previous")
    return allow()

@registry.hook("detect_image_pull_errors")
def detect_image_pull_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ImagePullBackOff|ErrImagePull|ImagePullErr", output):
        return post_tool_context("K8s: Image pull failed. Check image name, tag, and registry credentials.")
    return allow()

@registry.hook("check_resource_limits")
def check_resource_limits(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"resources:\s*\{\}|no resource limits|resources.*not set", output, re.IGNORECASE):
        return post_tool_context("K8s: No resource limits set. Add CPU/memory limits to prevent resource starvation.")
    return allow()

@registry.hook("detect_pending_pods")
def detect_pending_pods(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"kubectl\s+get\s+pods", cmd) or not output: return allow()
    pending = re.findall(r"(\S+)\s+\d+/\d+\s+Pending", output)
    if pending:
        return post_tool_context(f"K8s: {len(pending)} pending pods. Check: kubectl describe pod {pending[0]}")
    return allow()

@registry.hook("detect_evicted_pods")
def detect_evicted_pods(data):
    output = get_command_output(data)
    if not output: return allow()
    evicted = re.findall(r"Evicted", output)
    if len(evicted) > 3:
        return post_tool_context(f"K8s: {len(evicted)} evicted pods. Node may be under resource pressure.")
    return allow()

@registry.hook("check_service_endpoints")
def check_service_endpoints(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"<none>.*<none>|Endpoints:\s*<none>|no endpoints", output, re.IGNORECASE):
        return post_tool_context("K8s: Service has no endpoints. Check selector labels match pod labels.")
    return allow()

@registry.hook("detect_oom_killed")
def detect_oom_killed(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"OOMKilled|Last State.*OOMKilled|memory.*exceeded", output):
        return post_tool_context("K8s: Pod OOMKilled. Increase memory limits or optimize application memory usage.")
    return allow()

@registry.hook("check_hpa_status")
def check_hpa_status(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"kubectl\s+get\s+hpa", cmd) or not output: return allow()
    if re.search(r"<unknown>|unable to fetch metrics|FailedGetResourceMetric", output):
        return post_tool_context("K8s: HPA cannot fetch metrics. Check metrics-server deployment.")
    return allow()

@registry.hook("detect_failed_deployments")
def detect_failed_deployments(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"deployment.*failed|ProgressDeadlineExceeded|rollout.*failed", output, re.IGNORECASE):
        return post_tool_context("K8s: Deployment failed. Check: kubectl rollout status / kubectl rollout undo")
    return allow()

@registry.hook("block_kubectl_edit_production")
def block_kubectl_edit_production(data):
    cmd = get_command(data)
    if re.search(r"kubectl\s+edit\s+", cmd) and re.search(r"-n\s+production|--namespace\s*=?\s*production", cmd):
        return deny("K8s: Direct editing in production. Apply changes through version-controlled manifests.")
    return allow()

@registry.hook("check_node_conditions")
def check_node_conditions(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"MemoryPressure.*True", output): issues.append("MemoryPressure")
    if re.search(r"DiskPressure.*True", output): issues.append("DiskPressure")
    if re.search(r"PIDPressure.*True", output): issues.append("PIDPressure")
    if re.search(r"NetworkUnavailable.*True", output): issues.append("NetworkUnavailable")
    if re.search(r"NotReady", output): issues.append("NotReady")
    if issues:
        return post_tool_context(f"K8s: Node issues: {', '.join(issues)}")
    return allow()

@registry.hook("detect_pvc_issues")
def detect_pvc_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Pending.*pvc|persistentvolumeclaim.*Pending|no persistent volumes available", output, re.IGNORECASE):
        return post_tool_context("K8s: PVC pending. Check StorageClass and available PersistentVolumes.")
    return allow()

@registry.hook("check_rbac_issues")
def check_rbac_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"forbidden|RBAC.*denied|cannot.*resource|User.*cannot", output, re.IGNORECASE):
        return post_tool_context("K8s: RBAC permission denied. Check ClusterRole/RoleBinding configuration.")
    return allow()

@registry.hook("detect_secret_not_found")
def detect_secret_not_found(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r'secret.*not found|couldn\'t find key|MountVolume.*secret', output, re.IGNORECASE):
        return post_tool_context("K8s: Secret not found. Create the secret before deploying: kubectl create secret")
    return allow()

@registry.hook("check_ingress_config")
def check_ingress_config(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ingress.*error|backend.*not found|default backend.*404|no matching backend", output, re.IGNORECASE):
        return post_tool_context("K8s: Ingress configuration issue. Check backend service name and port.")
    return allow()

@registry.hook("detect_pod_security_issues")
def detect_pod_security_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"PodSecurity.*violation|pod-security.*warn|restricted.*policy", output, re.IGNORECASE):
        return post_tool_context("K8s: Pod security policy violation. Review securityContext and pod spec.")
    return allow()

if __name__ == "__main__":
    registry.main()
