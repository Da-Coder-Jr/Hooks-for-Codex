"""
Comprehensive pattern libraries used across multiple hooks.

Centralizes regex patterns for secrets, dangerous commands, file types,
and other common detection needs.
"""

# ── Secret / Credential Patterns ──

AWS_KEY_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                                   # AWS Access Key ID
    r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    r"(?i)aws_session_token\s*[=:]\s*\S{20,}",
    r"(?i)aws_access_key_id\s*[=:]\s*AKIA[0-9A-Z]{16}",
]

GCP_KEY_PATTERNS = [
    r"AIza[0-9A-Za-z_-]{35}",                              # GCP API key
    r'"type"\s*:\s*"service_account"',                      # GCP service account JSON
    r"(?i)gcloud.*--service-account-key",
    r"(?i)GOOGLE_APPLICATION_CREDENTIALS\s*=",
]

AZURE_KEY_PATTERNS = [
    r"(?i)azure[_-]?(storage|account)[_-]?key\s*[=:]\s*\S{20,}",
    r"(?i)AZURE_CLIENT_SECRET\s*[=:]\s*\S{10,}",
    r"(?i)AZURE_TENANT_ID\s*[=:]\s*[0-9a-f-]{36}",
    r"DefaultEndpointsProtocol=https;AccountName=\w+;AccountKey=",
]

GITHUB_TOKEN_PATTERNS = [
    r"ghp_[A-Za-z0-9]{36}",                                # GitHub PAT (classic)
    r"github_pat_[A-Za-z0-9_]{22,}",                       # GitHub PAT (fine-grained)
    r"gho_[A-Za-z0-9]{36}",                                # GitHub OAuth token
    r"ghs_[A-Za-z0-9]{36}",                                # GitHub server token
    r"ghr_[A-Za-z0-9]{36}",                                # GitHub refresh token
]

GITLAB_TOKEN_PATTERNS = [
    r"glpat-[A-Za-z0-9_-]{20,}",                           # GitLab PAT
    r"gldt-[A-Za-z0-9_-]{20,}",                            # GitLab deploy token
    r"GR1348941[A-Za-z0-9_-]{20,}",                        # GitLab runner token
]

OPENAI_KEY_PATTERNS = [
    r"sk-[A-Za-z0-9]{20,}",                                # OpenAI API key
    r"sk-proj-[A-Za-z0-9_-]{20,}",                         # OpenAI project key
]

SLACK_TOKEN_PATTERNS = [
    r"xox[bpsa]-[0-9]{10,}-[A-Za-z0-9-]+",                # Slack tokens
    r"xapp-[0-9]-[A-Za-z0-9-]+",                           # Slack app token
    r"(?i)slack[_-]?webhook[_-]?url\s*[=:]\s*https://hooks\.slack\.com/\S+",
]

STRIPE_KEY_PATTERNS = [
    r"sk_live_[A-Za-z0-9]{24,}",                           # Stripe secret key
    r"sk_test_[A-Za-z0-9]{24,}",                           # Stripe test key
    r"rk_live_[A-Za-z0-9]{24,}",                           # Stripe restricted key
    r"pk_live_[A-Za-z0-9]{24,}",                           # Stripe publishable key
    r"whsec_[A-Za-z0-9]{24,}",                             # Stripe webhook secret
]

DATABASE_URL_PATTERNS = [
    r"(?i)(postgres|postgresql|mysql|mongodb|redis|mssql)://\S+:\S+@\S+",
    r"(?i)DATABASE_URL\s*[=:]\s*\S+://\S+:\S+@",
    r"(?i)REDIS_URL\s*[=:]\s*redis://\S+",
    r"(?i)MONGO_URI\s*[=:]\s*mongodb(\+srv)?://\S+",
]

JWT_PATTERNS = [
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",  # JWT token
]

PRIVATE_KEY_PATTERNS = [
    r"-----BEGIN (RSA |OPENSSH |EC |DSA |ED25519 )?PRIVATE KEY-----",
    r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    r"(?i)PRIVATE[_-]?KEY\s*[=:]\s*\S{20,}",
]

CRYPTO_PATTERNS = [
    r"(?i)(npm|pypi|rubygems|nuget)[_-]?token\s*[=:]\s*\S{10,}",
    r"(?i)DOCKER_AUTH_CONFIG\s*=",
    r"(?i)DOCKER_PASSWORD\s*[=:]\s*\S+",
    r"(?i)REGISTRY_PASSWORD\s*[=:]\s*\S+",
]

TWILIO_PATTERNS = [
    r"(?i)TWILIO_AUTH_TOKEN\s*[=:]\s*[a-f0-9]{32}",
    r"AC[a-f0-9]{32}",                                      # Twilio Account SID
]

SENDGRID_PATTERNS = [
    r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}",        # SendGrid API key
]

DISCORD_PATTERNS = [
    r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",         # Discord bot token
    r"(?i)DISCORD_TOKEN\s*[=:]\s*\S{20,}",
]

FIREBASE_PATTERNS = [
    r"(?i)FIREBASE_API_KEY\s*[=:]\s*AIza[0-9A-Za-z_-]{35}",
    r"(?i)firebase[_-]?token\s*[=:]\s*\S{20,}",
]

SMTP_PATTERNS = [
    r"(?i)SMTP_PASSWORD\s*[=:]\s*\S+",
    r"(?i)MAIL_PASSWORD\s*[=:]\s*\S+",
    r"(?i)EMAIL_HOST_PASSWORD\s*[=:]\s*\S+",
]

GENERIC_SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=_-]{16,}",
    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?\S{8,}",
    r"(?i)token\s*[=:]\s*['\"]?[A-Za-z0-9_-]{16,}",
    r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    r"(?i)Basic\s+[A-Za-z0-9+/]+=+",
    r"(?i)Authorization:\s*(Bearer|Basic|Token)\s+\S+",
]

ALL_SECRET_PATTERNS = (
    AWS_KEY_PATTERNS + GCP_KEY_PATTERNS + AZURE_KEY_PATTERNS +
    GITHUB_TOKEN_PATTERNS + GITLAB_TOKEN_PATTERNS + OPENAI_KEY_PATTERNS +
    SLACK_TOKEN_PATTERNS + STRIPE_KEY_PATTERNS + DATABASE_URL_PATTERNS +
    JWT_PATTERNS + PRIVATE_KEY_PATTERNS + CRYPTO_PATTERNS +
    TWILIO_PATTERNS + SENDGRID_PATTERNS + DISCORD_PATTERNS +
    FIREBASE_PATTERNS + SMTP_PATTERNS + GENERIC_SECRET_PATTERNS
)


# ── Dangerous Command Patterns ──

DESTRUCTIVE_FS_PATTERNS = [
    r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(/|~|\$HOME)\b",
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/\b",
    r"\brm\s+.*\b/(usr|etc|var|boot|lib|sbin|bin|proc|sys|dev)\b",
    r"\brm\s+.*\b/(System|Library|Applications)\b",
    r"\bmkfs\b",
    r"\bdd\s+.*\bif=.*\bof=/dev/",
    r"\bshred\b.*(/dev/|/etc/|/var/)",
    r"\bwipefs\b",
]

FORK_BOMB_PATTERNS = [
    r":\(\)\{\s*:\|:\s*&\s*\}\s*;",
    r"\bfork\s*\(\s*\)\s*while",
    r"while\s+true.*do.*&.*done",
    r"\byes\s*\|",
]

PRIVILEGE_ESCALATION_PATTERNS = [
    r"\bsudo\s+(su|bash|sh|zsh)\b",
    r"\bsudo\s+-i\b",
    r"\bsu\s+-\s*$",
    r"\bchmod\s+.*\+s\b",
    r"\bchmod\s+[0-7]*[4-7][0-7]{2}\s+/(usr|bin|sbin)/",
    r"\bchown\s+root\b",
    r"\bsetcap\b",
]

SYSTEM_MODIFICATION_PATTERNS = [
    r"\bsystemctl\s+(halt|poweroff|disable|mask)\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\binit\s+[06]\b",
    r"\bsysctl\s+-w\b",
    r"\bmodprobe\b",
    r"\binsmod\b",
    r"\brmmod\b",
]

NETWORK_DANGER_PATTERNS = [
    r"\biptables\s+-F\b",                                   # flush all rules
    r"\biptables\s+.*-j\s+DROP\b.*-p\s+all",              # drop all traffic
    r"\bufw\s+disable\b",
    r"\bfirewall-cmd\s+.*--remove",
    r"\bwget\b.*\|\s*(ba)?sh",
    r"\bcurl\b.*\|\s*(ba)?sh",
    r"\bnc\s+-[a-zA-Z]*l[a-zA-Z]*\s+-[a-zA-Z]*e\s+(ba)?sh",  # reverse shell
    r"\bbash\s+-i\s+>&\s*/dev/tcp/",                        # bash reverse shell
]


# ── Sensitive File Patterns ──

SENSITIVE_FILES = [
    r"\.env\b",
    r"\.env\.\w+",
    r"credentials\.json",
    r"service[-_]?account\.json",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"\.jks$",
    r"\.keystore$",
    r"id_rsa\b",
    r"id_ed25519\b",
    r"id_ecdsa\b",
    r"\.ssh/config",
    r"\.aws/credentials",
    r"\.kube/config",
    r"\.docker/config\.json",
    r"\.netrc",
    r"\.npmrc",
    r"\.pypirc",
    r"known_hosts",
    r"authorized_keys",
    r"shadow$",
    r"passwd$",
    r"htpasswd",
    r"\.pgpass",
    r"\.my\.cnf",
]


# ── Injection Patterns ──

SQL_INJECTION_PATTERNS = [
    r"(?i)\b(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE|INDEX|VIEW)\b",
    r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
    r"(?i);\s*(DROP|DELETE|INSERT|UPDATE|ALTER)\b",
    r"(?i)'\s*(OR|AND)\s+'?\d+'\s*=\s*'?\d+",
    r'(?i)"\s*(OR|AND)\s+"?\d+"\s*=\s*"?\d+',
    r"(?i)--\s*$",
    r"(?i)\bEXEC\s*\(",
    r"(?i)\bxp_cmdshell\b",
    r"(?i)LOAD_FILE\s*\(",
    r"(?i)INTO\s+OUTFILE\b",
]

XSS_PATTERNS = [
    r"<script[\s>]",
    r"javascript:",
    r"on(load|error|click|mouseover|focus|blur)\s*=",
    r"<iframe[\s>]",
    r"<object[\s>]",
    r"<embed[\s>]",
    r"<svg[\s>].*on\w+=",
    r"expression\s*\(",
    r"url\s*\(\s*['\"]?javascript:",
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(cat|ls|id|whoami|uname|pwd|wget|curl)\b",
    r"\$\(.*\b(cat|ls|id|whoami|curl)\b",
    r"`.*\b(cat|ls|id|whoami|curl)\b.*`",
    r"\|\s*(bash|sh|zsh|csh|ksh)\b",
    r"&&\s*(cat|rm|wget|curl)\s+/",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./\.\./",
    r"%2e%2e%2f",
    r"%252e%252e%252f",
    r"\.\.\\\\",
    r"\.\./etc/passwd",
    r"\.\./etc/shadow",
]

PROMPT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)disregard\s+(all\s+)?(above|previous|prior)",
    r"(?i)you\s+are\s+now\s+(a|an|in)\s+",
    r"(?i)forget\s+(everything|all|your)",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)system\s*:\s*you\s+are",
    r"(?i)override\s+(safety|security|rules|guidelines)",
    r"(?i)pretend\s+(you|to\s+be)",
    r"(?i)act\s+as\s+(if|though|a|an)\b",
    r"(?i)jailbreak",
]


# ── Project Type Detection ──

PROJECT_MARKERS = {
    "package.json": "nodejs",
    "Cargo.toml": "rust",
    "pyproject.toml": "python",
    "setup.py": "python",
    "requirements.txt": "python",
    "Pipfile": "python",
    "go.mod": "go",
    "Makefile": "make",
    "CMakeLists.txt": "cmake",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "build.gradle.kts": "kotlin-gradle",
    "Gemfile": "ruby",
    "composer.json": "php",
    "Package.swift": "swift",
    "*.csproj": "dotnet",
    "mix.exs": "elixir",
    "stack.yaml": "haskell",
    "dune-project": "ocaml",
    "Dockerfile": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "terraform.tf": "terraform",
    "main.tf": "terraform",
    "Vagrantfile": "vagrant",
    "Procfile": "heroku",
    "netlify.toml": "netlify",
    "vercel.json": "vercel",
    "next.config.js": "nextjs",
    "next.config.mjs": "nextjs",
    "next.config.ts": "nextjs",
    "nuxt.config.js": "nuxt",
    "nuxt.config.ts": "nuxt",
    "angular.json": "angular",
    "vue.config.js": "vue",
    "svelte.config.js": "svelte",
    "astro.config.mjs": "astro",
    "gatsby-config.js": "gatsby",
    "remix.config.js": "remix",
    "tailwind.config.js": "tailwind",
    "tailwind.config.ts": "tailwind",
    "webpack.config.js": "webpack",
    "vite.config.js": "vite",
    "vite.config.ts": "vite",
    "rollup.config.js": "rollup",
    "tsconfig.json": "typescript",
    ".eslintrc.json": "eslint",
    ".eslintrc.js": "eslint",
    ".prettierrc": "prettier",
    "jest.config.js": "jest",
    "jest.config.ts": "jest",
    "vitest.config.ts": "vitest",
    "pytest.ini": "pytest",
    "tox.ini": "tox",
    ".flake8": "flake8",
    "mypy.ini": "mypy",
    ".rubocop.yml": "rubocop",
}


# ── Language File Extensions ──

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript-react",
    ".ts": "typescript",
    ".tsx": "typescript-react",
    ".rs": "rust",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".c": "c",
    ".h": "c-header",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp-header",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".scala": "scala",
    ".clj": "clojure",
    ".lua": "lua",
    ".r": "r",
    ".R": "r",
    ".jl": "julia",
    ".dart": "dart",
    ".zig": "zig",
    ".nim": "nim",
    ".v": "vlang",
    ".sol": "solidity",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".fish": "fish",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "sass",
    ".less": "less",
    ".vue": "vue",
    ".svelte": "svelte",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".json": "json",
    ".xml": "xml",
    ".md": "markdown",
    ".rst": "rst",
    ".tf": "terraform",
    ".hcl": "hcl",
    ".proto": "protobuf",
    ".graphql": "graphql",
    ".gql": "graphql",
}
