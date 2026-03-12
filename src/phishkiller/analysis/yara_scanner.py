"""YARA rule scanning stub — to be implemented as a fast-follow.

Requires the optional `yara-python` dependency:
    pip install phishkiller[yara]
"""

from dataclasses import dataclass, field
from pathlib import Path


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
    error: str | None = None


class YaraScanner:
    """YARA rule scanner for phishing kit classification."""

    def __init__(self, rules_dir: str | None = None):
        self.rules_dir = rules_dir
        self._compiled_rules = None

    def load_rules(self) -> int:
        """Load and compile YARA rules from the rules directory."""
        if not self.rules_dir:
            return 0

        try:
            import yara

            rules_path = Path(self.rules_dir)
            rule_files = {}
            for yar_file in rules_path.glob("**/*.yar"):
                rule_files[yar_file.stem] = str(yar_file)
            for yar_file in rules_path.glob("**/*.yara"):
                rule_files[yar_file.stem] = str(yar_file)

            if rule_files:
                self._compiled_rules = yara.compile(filepaths=rule_files)
                return len(rule_files)
        except ImportError:
            pass
        except Exception:
            pass

        return 0

    def scan_file(self, filepath: str) -> YaraScanResult:
        """Scan a file against loaded YARA rules."""
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
                rules_loaded=self.rules_loaded,
            )
        except Exception as e:
            return YaraScanResult(error=str(e))

    @property
    def rules_loaded(self) -> int:
        return 0 if not self._compiled_rules else 1
