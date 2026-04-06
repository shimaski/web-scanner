"""Exposed backup and temporary files detection."""

import logging

from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)

BACKUP_PATHS = [
    # Version control
    (".git/config", "HIGH", "Git config exposed"),
    (".git/HEAD", "HIGH", "Git HEAD file exposed"),
    (".gitignore", "LOW", ".gitignore file exposed"),
    (".svn/entries", "HIGH", "SVN entries exposed"),
    (".hg/.hgignore", "HIGH", "Mercurial config exposed"),

    # Backup files
    ("backup.sql", "HIGH", "SQL backup file exposed"),
    ("backup.tar.gz", "HIGH", "Archive backup exposed"),
    ("backup.zip", "HIGH", "ZIP backup exposed"),
    ("db.sql", "HIGH", "Database dump exposed"),
    ("dump.sql", "HIGH", "Database dump exposed"),
    ("database.sql", "HIGH", "Database dump exposed"),
    ("data.sql", "HIGH", "Database dump exposed"),
    ("export.sql", "MEDIUM", "SQL export exposed"),

    # Config backups
    ("config.php.bak", "HIGH", "PHP config backup exposed"),
    ("wp-config.php.bak", "HIGH", "WordPress config backup exposed"),
    (".env.bak", "HIGH", "Environment backup exposed"),
    ("config.yml", "MEDIUM", "YAML config exposed"),
    ("config.json", "MEDIUM", "JSON config exposed"),
    ("settings.json", "MEDIUM", "Settings file exposed"),

    # Temp/editor files
    (".DS_Store", "LOW", "macOS metadata exposed"),
    ("Thumbs.db", "LOW", "Windows thumbnail cache exposed"),
    ("composer.lock", "LOW", "Composer lock file exposed"),
    ("package-lock.json", "LOW", "NPM lock file exposed"),
    ("yarn.lock", "LOW", "Yarn lock file exposed"),
    ("Gemfile.lock", "LOW", "Ruby Gemfile lock exposed"),

    # Log files
    ("debug.log", "MEDIUM", "Debug log exposed"),
    ("error.log", "MEDIUM", "Error log exposed"),
    ("access.log", "MEDIUM", "Access log exposed"),
    ("logs/debug.log", "MEDIUM", "Debug log in /logs/ exposed"),

    # Swagger / docs
    ("swagger.json", "INFO", "API Swagger docs exposed"),
    ("openapi.json", "INFO", "OpenAPI spec exposed"),
    ("api-docs", "INFO", "API documentation accessible"),
]


class BackupScanner(BaseScanner):
    """Detect exposed backup, config, and temporary files."""

    def run(self):
        findings: list[dict] = []

        for path, severity, detail in BACKUP_PATHS:
            resp = self.client.get(path)
            if resp is None:
                continue

            if resp.status_code == 200 and len(resp.text.strip()) > 0:
                findings.append({
                    "severity": severity,
                    "title": f"Exposed file: {path}",
                    "detail": f"URL: {self._full_url(path)}\n{detail}",
                })

        return findings
