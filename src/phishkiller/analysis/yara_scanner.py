"""YARA rule scanning for phishing kit classification.

Requires the optional `yara-python` dependency:
    pip install phishkiller[yara]
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# File extensions worth scanning with YARA
SCANNABLE_EXTENSIONS = {
    ".php", ".js", ".html", ".htm", ".txt", ".json",
    ".conf", ".ini", ".xml", ".inc", ".htaccess",
    ".css",  # .htaccess rules sometimes in CSS-like files
}


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    strings: list[str]


@dataclass
class YaraScanResult:
    matches: list[YaraMatch] = field(default_factory=list)
    rules_loaded: int = 0
    files_scanned: int = 0
    error: str | None = None


class YaraScanner:
    """YARA rule scanner for phishing kit classification."""

    def __init__(self, rules_dir: str | None = None):
        self.rules_dir = rules_dir
        self._compiled_rules = None
        self._rules_count = 0

    def load_rules(self) -> int:
        """Load and compile YARA rules from the rules directory.

        Compiles rules individually so one broken rule file doesn't prevent
        all other rules from loading.
        """
        if not self.rules_dir:
            return 0

        try:
            import yara

            rules_path = Path(self.rules_dir)
            if not rules_path.exists():
                logger.warning("YARA rules directory not found: %s", self.rules_dir)
                return 0

            rule_files = {}
            for yar_file in rules_path.glob("**/*.yar"):
                rule_files[yar_file.stem] = str(yar_file)
            for yar_file in rules_path.glob("**/*.yara"):
                rule_files[yar_file.stem] = str(yar_file)

            if not rule_files:
                return 0

            # Try compiling all at once first (fastest path)
            try:
                self._compiled_rules = yara.compile(filepaths=rule_files)
                self._rules_count = len(rule_files)
                logger.info("Loaded %d YARA rule files from %s", self._rules_count, self.rules_dir)
                return self._rules_count
            except Exception as e:
                logger.warning("Bulk YARA compile failed (%s), trying individual compilation", e)

            # Fall back to individual compilation — skip broken files
            good_files = {}
            bad_count = 0
            for name, filepath in rule_files.items():
                try:
                    yara.compile(filepaths={name: filepath})
                    good_files[name] = filepath
                except Exception:
                    bad_count += 1

            if good_files:
                self._compiled_rules = yara.compile(filepaths=good_files)
                self._rules_count = len(good_files)
                logger.info(
                    "Loaded %d YARA rule files (%d skipped due to errors) from %s",
                    self._rules_count, bad_count, self.rules_dir,
                )
                return self._rules_count

        except ImportError:
            logger.debug("yara-python not installed, YARA scanning disabled")
        except Exception as e:
            logger.error("Failed to compile YARA rules: %s", e)

        return 0

    def scan_file(self, filepath: str) -> YaraScanResult:
        """Scan a single file against loaded YARA rules."""
        if not self._compiled_rules:
            return YaraScanResult(error="No YARA rules loaded")

        try:
            matches = self._compiled_rules.match(filepath)
            return YaraScanResult(
                matches=[
                    YaraMatch(
                        rule=m.rule,
                        namespace=m.namespace,
                        tags=list(m.tags),
                        meta=dict(m.meta),
                        strings=[str(s) for s in m.strings[:10]],
                    )
                    for m in matches
                ],
                rules_loaded=self._rules_count,
                files_scanned=1,
            )
        except Exception as e:
            return YaraScanResult(error=str(e))

    def scan_directory(self, directory: str) -> YaraScanResult:
        """Scan all scannable files in a directory against loaded YARA rules."""
        if not self._compiled_rules:
            return YaraScanResult(error="No YARA rules loaded")

        all_matches: list[YaraMatch] = []
        files_scanned = 0
        errors: list[str] = []

        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                ext = Path(filepath).suffix.lower()

                # Also scan extensionless files (e.g., .htaccess)
                basename = Path(filepath).name.lower()
                if ext not in SCANNABLE_EXTENSIONS and basename != ".htaccess":
                    continue

                try:
                    result = self.scan_file(filepath)
                    files_scanned += 1
                    if result.matches:
                        # Tag matches with source file
                        rel_path = os.path.relpath(filepath, directory)
                        for match in result.matches:
                            match.meta["source_file"] = rel_path
                        all_matches.extend(result.matches)
                except Exception as e:
                    errors.append(f"{filepath}: {e}")

        error_msg = None
        if errors:
            error_msg = f"{len(errors)} scan errors"

        return YaraScanResult(
            matches=all_matches,
            rules_loaded=self._rules_count,
            files_scanned=files_scanned,
            error=error_msg,
        )

    @property
    def rules_loaded(self) -> int:
        return self._rules_count

    @property
    def is_available(self) -> bool:
        """Check if YARA scanning is available (library installed)."""
        try:
            import yara  # noqa: F401
            return True
        except ImportError:
            return False


# Module-level cached scanner — compiled rules persist across tasks within
# each prefork worker process.  Saves ~0.75s per task (892 rule files).
_cached_scanner: YaraScanner | None = None
_cached_rules_dir: str | None = None


def get_cached_scanner(rules_dir: str | None) -> YaraScanner:
    """Return a YaraScanner with pre-compiled rules, cached per worker process.

    Rules are compiled once on first call and reused for all subsequent tasks
    in the same worker process.  A new rules_dir invalidates the cache.
    """
    global _cached_scanner, _cached_rules_dir

    if (
        _cached_scanner is not None
        and _cached_rules_dir == rules_dir
        and _cached_scanner._compiled_rules is not None
    ):
        return _cached_scanner

    scanner = YaraScanner(rules_dir=rules_dir)
    scanner.load_rules()
    _cached_scanner = scanner
    _cached_rules_dir = rules_dir
    logger.info(
        "Cached YARA scanner for worker process (pid=%d, rules=%d)",
        os.getpid(), scanner.rules_loaded,
    )
    return scanner
