#!/usr/bin/env python3
"""
Security: Secret Detection hooks for Codex.
40 PreToolUse hooks that detect secrets and credentials in commands.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command

registry = HookRegistry()


def _check(cmd, patterns, msg):
    for p in patterns:
        if re.search(p, cmd):
            return deny(msg)
    return allow()


@registry.hook("detect_aws_access_key")
def detect_aws_access_key(data):
    """Detect AWS Access Key IDs in commands."""
    return _check(get_command(data), [r"AKIA[0-9A-Z]{16}"], "Blocked: AWS Access Key ID detected")


@registry.hook("detect_aws_secret_key")
def detect_aws_secret_key(data):
    """Detect AWS Secret Access Keys."""
    return _check(get_command(data), [
        r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        r"(?i)AWS_SECRET_ACCESS_KEY\s*=\s*\S{20,}",
    ], "Blocked: AWS Secret Access Key detected")


@registry.hook("detect_aws_session_token")
def detect_aws_session_token(data):
    """Detect AWS Session Tokens."""
    return _check(get_command(data), [
        r"(?i)aws_session_token\s*[=:]\s*\S{20,}",
        r"(?i)AWS_SESSION_TOKEN\s*=\s*\S{20,}",
    ], "Blocked: AWS Session Token detected")


@registry.hook("detect_gcp_api_key")
def detect_gcp_api_key(data):
    """Detect Google Cloud API keys."""
    return _check(get_command(data), [r"AIza[0-9A-Za-z_-]{35}"], "Blocked: GCP API key detected")


@registry.hook("detect_gcp_service_account")
def detect_gcp_service_account(data):
    """Detect GCP service account private keys."""
    return _check(get_command(data), [
        r'"type"\s*:\s*"service_account"',
        r"(?i)GOOGLE_APPLICATION_CREDENTIALS\s*=",
    ], "Blocked: GCP service account key detected")


@registry.hook("detect_gcp_oauth_token")
def detect_gcp_oauth_token(data):
    """Detect GCP OAuth tokens."""
    return _check(get_command(data), [r"ya29\.[A-Za-z0-9_-]{20,}"], "Blocked: GCP OAuth token detected")


@registry.hook("detect_azure_client_secret")
def detect_azure_client_secret(data):
    """Detect Azure client secrets."""
    return _check(get_command(data), [
        r"(?i)AZURE_CLIENT_SECRET\s*[=:]\s*\S{10,}",
        r"(?i)azure[_-]?client[_-]?secret\s*[=:]\s*\S{10,}",
    ], "Blocked: Azure client secret detected")


@registry.hook("detect_azure_storage_key")
def detect_azure_storage_key(data):
    """Detect Azure Storage Account keys."""
    return _check(get_command(data), [
        r"(?i)azure[_-]?(storage|account)[_-]?key\s*[=:]\s*[A-Za-z0-9/+=]{44,}",
        r"AccountKey=[A-Za-z0-9/+=]{44,}",
    ], "Blocked: Azure Storage key detected")


@registry.hook("detect_azure_connection_string")
def detect_azure_connection_string(data):
    """Detect Azure connection strings."""
    return _check(get_command(data), [
        r"DefaultEndpointsProtocol=https;AccountName=\w+;AccountKey=",
    ], "Blocked: Azure connection string with key detected")


@registry.hook("detect_github_pat_classic")
def detect_github_pat_classic(data):
    """Detect GitHub Personal Access Tokens (classic)."""
    return _check(get_command(data), [r"ghp_[A-Za-z0-9]{36}"], "Blocked: GitHub PAT (classic) detected")


@registry.hook("detect_github_pat_fine")
def detect_github_pat_fine(data):
    """Detect GitHub fine-grained PATs."""
    return _check(get_command(data), [r"github_pat_[A-Za-z0-9_]{22,}"], "Blocked: GitHub fine-grained PAT detected")


@registry.hook("detect_github_oauth")
def detect_github_oauth(data):
    """Detect GitHub OAuth tokens."""
    return _check(get_command(data), [
        r"gho_[A-Za-z0-9]{36}",
        r"ghs_[A-Za-z0-9]{36}",
        r"ghr_[A-Za-z0-9]{36}",
    ], "Blocked: GitHub OAuth/server/refresh token detected")


@registry.hook("detect_gitlab_pat")
def detect_gitlab_pat(data):
    """Detect GitLab Personal Access Tokens."""
    return _check(get_command(data), [r"glpat-[A-Za-z0-9_-]{20,}"], "Blocked: GitLab PAT detected")


@registry.hook("detect_gitlab_runner")
def detect_gitlab_runner(data):
    """Detect GitLab Runner tokens."""
    return _check(get_command(data), [
        r"GR1348941[A-Za-z0-9_-]{20,}",
        r"gldt-[A-Za-z0-9_-]{20,}",
    ], "Blocked: GitLab runner/deploy token detected")


@registry.hook("detect_openai_key")
def detect_openai_key(data):
    """Detect OpenAI API keys."""
    return _check(get_command(data), [
        r"sk-[A-Za-z0-9]{20,}",
        r"sk-proj-[A-Za-z0-9_-]{20,}",
    ], "Blocked: OpenAI API key detected")


@registry.hook("detect_anthropic_key")
def detect_anthropic_key(data):
    """Detect Anthropic API keys."""
    return _check(get_command(data), [r"sk-ant-[A-Za-z0-9_-]{20,}"], "Blocked: Anthropic API key detected")


@registry.hook("detect_slack_token")
def detect_slack_token(data):
    """Detect Slack tokens."""
    return _check(get_command(data), [
        r"xox[bpsa]-[0-9]{10,}-[A-Za-z0-9-]+",
        r"xapp-[0-9]-[A-Za-z0-9-]+",
    ], "Blocked: Slack token detected")


@registry.hook("detect_slack_webhook")
def detect_slack_webhook(data):
    """Detect Slack webhook URLs."""
    return _check(get_command(data), [
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    ], "Blocked: Slack webhook URL detected")


@registry.hook("detect_stripe_secret")
def detect_stripe_secret(data):
    """Detect Stripe secret keys."""
    return _check(get_command(data), [
        r"sk_live_[A-Za-z0-9]{24,}",
        r"sk_test_[A-Za-z0-9]{24,}",
        r"rk_live_[A-Za-z0-9]{24,}",
    ], "Blocked: Stripe secret key detected")


@registry.hook("detect_stripe_webhook_secret")
def detect_stripe_webhook_secret(data):
    """Detect Stripe webhook secrets."""
    return _check(get_command(data), [r"whsec_[A-Za-z0-9]{24,}"], "Blocked: Stripe webhook secret detected")


@registry.hook("detect_twilio_auth")
def detect_twilio_auth(data):
    """Detect Twilio auth tokens and Account SIDs."""
    return _check(get_command(data), [
        r"(?i)TWILIO_AUTH_TOKEN\s*[=:]\s*[a-f0-9]{32}",
        r"AC[a-f0-9]{32}",
    ], "Blocked: Twilio credentials detected")


@registry.hook("detect_sendgrid_key")
def detect_sendgrid_key(data):
    """Detect SendGrid API keys."""
    return _check(get_command(data), [
        r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}",
    ], "Blocked: SendGrid API key detected")


@registry.hook("detect_discord_token")
def detect_discord_token(data):
    """Detect Discord bot tokens."""
    return _check(get_command(data), [
        r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",
        r"(?i)DISCORD_TOKEN\s*[=:]\s*\S{20,}",
    ], "Blocked: Discord bot token detected")


@registry.hook("detect_discord_webhook")
def detect_discord_webhook(data):
    """Detect Discord webhook URLs."""
    return _check(get_command(data), [
        r"https://discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    ], "Blocked: Discord webhook URL detected")


@registry.hook("detect_npm_token")
def detect_npm_token(data):
    """Detect npm tokens."""
    return _check(get_command(data), [
        r"npm_[A-Za-z0-9]{36}",
        r"(?i)NPM_TOKEN\s*[=:]\s*\S{10,}",
    ], "Blocked: npm token detected")


@registry.hook("detect_pypi_token")
def detect_pypi_token(data):
    """Detect PyPI tokens."""
    return _check(get_command(data), [r"pypi-[A-Za-z0-9_-]{16,}"], "Blocked: PyPI token detected")


@registry.hook("detect_rubygems_key")
def detect_rubygems_key(data):
    """Detect RubyGems API keys."""
    return _check(get_command(data), [
        r"(?i)RUBYGEMS_API_KEY\s*[=:]\s*[a-f0-9]{32,}",
        r"(?i)GEM_HOST_API_KEY\s*[=:]\s*\S{10,}",
    ], "Blocked: RubyGems API key detected")


@registry.hook("detect_nuget_key")
def detect_nuget_key(data):
    """Detect NuGet API keys."""
    return _check(get_command(data), [
        r"(?i)NUGET_API_KEY\s*[=:]\s*\S{20,}",
        r"oy2[a-z0-9]{43}",
    ], "Blocked: NuGet API key detected")


@registry.hook("detect_docker_password")
def detect_docker_password(data):
    """Detect Docker registry credentials."""
    return _check(get_command(data), [
        r"(?i)DOCKER_PASSWORD\s*[=:]\s*\S+",
        r"(?i)docker\s+login\s+.*-p\s+\S+",
        r"(?i)DOCKER_AUTH_CONFIG\s*=",
    ], "Blocked: Docker registry credentials detected")


@registry.hook("detect_ssh_private_key")
def detect_ssh_private_key(data):
    """Detect SSH private key content."""
    return _check(get_command(data), [
        r"-----BEGIN (RSA |OPENSSH |EC |DSA |ED25519 )?PRIVATE KEY-----",
    ], "Blocked: SSH private key content detected")


@registry.hook("detect_pgp_private_key")
def detect_pgp_private_key(data):
    """Detect PGP private key content."""
    return _check(get_command(data), [
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ], "Blocked: PGP private key content detected")


@registry.hook("detect_jwt_token")
def detect_jwt_token(data):
    """Detect JWT tokens in commands."""
    return _check(get_command(data), [
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
    ], "Blocked: JWT token detected in command")


@registry.hook("detect_database_url")
def detect_database_url(data):
    """Detect database connection strings with passwords."""
    return _check(get_command(data), [
        r"(?i)(postgres|postgresql|mysql|mongodb|redis|mssql)://\S+:\S+@\S+",
        r"(?i)DATABASE_URL\s*[=:]\s*\S+://\S+:\S+@",
    ], "Blocked: database connection string with credentials detected")


@registry.hook("detect_redis_password")
def detect_redis_password(data):
    """Detect Redis passwords."""
    return _check(get_command(data), [
        r"(?i)REDIS_PASSWORD\s*[=:]\s*\S+",
        r"(?i)redis-cli\s+.*-a\s+\S+",
        r"(?i)AUTH\s+\S{8,}",
    ], "Blocked: Redis password detected")


@registry.hook("detect_elasticsearch_creds")
def detect_elasticsearch_creds(data):
    """Detect Elasticsearch credentials."""
    return _check(get_command(data), [
        r"(?i)ELASTIC_PASSWORD\s*[=:]\s*\S+",
        r"(?i)https?://elastic:\S+@",
        r"(?i)ELASTICSEARCH_URL\s*[=:]\s*\S+:\S+@",
    ], "Blocked: Elasticsearch credentials detected")


@registry.hook("detect_smtp_password")
def detect_smtp_password(data):
    """Detect SMTP/email passwords."""
    return _check(get_command(data), [
        r"(?i)(SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_HOST_PASSWORD)\s*[=:]\s*\S+",
        r"(?i)SENDMAIL_PASSWORD\s*[=:]\s*\S+",
    ], "Blocked: SMTP/email password detected")


@registry.hook("detect_firebase_key")
def detect_firebase_key(data):
    """Detect Firebase API keys and config."""
    return _check(get_command(data), [
        r"(?i)FIREBASE_API_KEY\s*[=:]\s*AIza[0-9A-Za-z_-]{35}",
        r"(?i)firebase[_-]?token\s*[=:]\s*\S{20,}",
    ], "Blocked: Firebase API key detected")


@registry.hook("detect_heroku_api_key")
def detect_heroku_api_key(data):
    """Detect Heroku API keys."""
    return _check(get_command(data), [
        r"(?i)HEROKU_API_KEY\s*[=:]\s*[a-f0-9-]{36}",
        r"(?i)heroku\s+auth:token",
    ], "Blocked: Heroku API key detected")


@registry.hook("detect_datadog_key")
def detect_datadog_key(data):
    """Detect Datadog API and app keys."""
    return _check(get_command(data), [
        r"(?i)DD_API_KEY\s*[=:]\s*[a-f0-9]{32}",
        r"(?i)DD_APP_KEY\s*[=:]\s*[a-f0-9]{40}",
        r"(?i)DATADOG_API_KEY\s*[=:]\s*[a-f0-9]{32}",
    ], "Blocked: Datadog API key detected")


@registry.hook("detect_generic_bearer_token")
def detect_generic_bearer_token(data):
    """Detect Bearer tokens and Authorization headers."""
    return _check(get_command(data), [
        r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        r"(?i)-H\s+['\"]Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    ], "Blocked: Bearer token in Authorization header detected")


if __name__ == "__main__":
    registry.main()
