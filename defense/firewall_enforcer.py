import ipaddress
import os
import subprocess


class FirewallEnforcer:
    """
    Minimal nftables enforcer for the AI IDS.

    The actual nftables table/set lives on Apollo
    inside the ai-ids-firewall hostNetwork pod.

    Only private Kubernetes pod addresses are allowed
    to be blocked by this controller.
    """

    def __init__(
        self,
        namespace="ai-ids",
        firewall_pod="ai-ids-firewall",
        timeout_seconds=300,
    ):
        self.namespace = namespace
        self.firewall_pod = firewall_pod
        self.timeout_seconds = timeout_seconds


    def _validate_ip(
        self,
        src_ip,
    ):
        ip = ipaddress.ip_address(
            str(src_ip)
        )

        if ip.version != 4:
            raise ValueError(
                "Only IPv4 sources are supported."
            )

        # Fail closed until the operator specifies the authorized
        # lab CIDR; never make a broad network block by default.
        lab_cidr = os.environ.get("AI_IDS_ALLOWED_CIDR")
        if not lab_cidr:
            raise RuntimeError(
                "Set AI_IDS_ALLOWED_CIDR to the authorized "
                "Kubernetes pod network before enabling enforcement."
            )
        allowed_network = ipaddress.ip_network(lab_cidr)

        if ip not in allowed_network:
            raise ValueError(
                f"Refusing to block non-lab address: {ip}"
            )

        if (
            ip.is_loopback
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError(
                f"Unsafe block address: {ip}"
            )

        return str(ip)


    def block(
        self,
        src_ip,
        timeout_seconds=None,
    ):
        src_ip = self._validate_ip(
            src_ip
        )

        timeout = (
            self.timeout_seconds
            if timeout_seconds is None
            else int(timeout_seconds)
        )

        if timeout <= 0:
            raise ValueError(
                "Block timeout must be positive."
            )

        nft_command = (
            "nft add element "
            "inet ai_ids_defense "
            "blocked_ipv4 "
            f"'{{ {src_ip} timeout {timeout}s }}'"
        )

        command = [
            "kubectl",
            "exec",
            "-n",
            self.namespace,
            self.firewall_pod,
            "--",
            "/bin/sh",
            "-lc",
            nft_command,
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Firewall block failed:\n"
                + result.stderr.strip()
            )

        return {
            "src_ip": src_ip,
            "timeout_seconds": timeout,
            "enforced": True,
        }


    def list_blocked(
        self,
    ):
        command = [
            "kubectl",
            "exec",
            "-n",
            self.namespace,
            self.firewall_pod,
            "--",
            "nft",
            "list",
            "set",
            "inet",
            "ai_ids_defense",
            "blocked_ipv4",
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
            )

        return result.stdout
