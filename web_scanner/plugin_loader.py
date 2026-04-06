"""Plugin system — dynamically load scanners from a plugins/ directory."""

import importlib
import logging
from pathlib import Path

from web_scanner.scanner import BaseScanner

logger = logging.getLogger(__name__)

PLUGINS_DIR = Path(__file__).parent / "plugins"


def discover_builtin_scanners() -> dict[str, type[BaseScanner]]:
    """Return all built-in scanners."""
    plugins = {}
    for py_file in Path(__file__).parent.glob("*.py"):
        if py_file.name.startswith(("_", "plugins", "main", "web_app", "config", "database")):
            continue
        if py_file.name == "scanner.py" or py_file.name == "http_client.py" or py_file.name == "report.py" or py_file.name == "crawler.py":
            continue

        module_name = py_file.stem
        try:
            mod = importlib.import_module(f"web_scanner.{module_name}")
            for attr_name in dir(mod):
                cls = getattr(mod, attr_name)
                if isinstance(cls, type) and issubclass(cls, BaseScanner) and cls != BaseScanner:
                    key = module_name.replace("_", "").replace("scanner", "").replace("check", "")
                    # Use the class name to derive a short key
                    cls_name = cls.__name__.lower()
                    key = cls_name.replace("scanner", "").replace("check", "").replace("gatherer", "info").replace("gatherer", "info")
                    plugins[key] = cls
        except Exception as e:
            logger.warning("Failed to load scanner: %s (%s)", module_name, e)

    return plugins


def load_plugin_scanner(plugin_path: Path) -> type[BaseScanner] | None:
    """Load a single plugin file and return the scanner class."""
    if not plugin_path.exists():
        return None

    import importlib.util
    spec = importlib.util.spec_from_file_location(plugin_path.stem, plugin_path)
    if spec is None or spec.loader is None:
        return None

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    for attr_name in dir(mod):
        cls = getattr(mod, attr_name)
        if isinstance(cls, type) and issubclass(cls, BaseScanner) and cls != BaseScanner:
            return cls
    return None


def load_plugins() -> dict[str, type[BaseScanner]]:
    """Load all plugins from the plugins/ directory."""
    plugins = {}
    if not PLUGINS_DIR.exists():
        return plugins

    for py_file in PLUGINS_DIR.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        scanner_cls = load_plugin_scanner(py_file)
        if scanner_cls:
            plugins[py_file.stem] = scanner_cls
            logger.info("Loaded plugin: %s -> %s", py_file.stem, scanner_cls.__name__)

    return plugins


def write_plugin_template(name: str, save_to: Path | None = None):
    """Write a plugin template file."""
    target = save_to or (PLUGINS_DIR / f"{name}.py")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f'''"""Plugin: {name}"""

from web_scanner.scanner import BaseScanner
from web_scanner.http_client import HTTPClient
from web_scanner.config import ScanConfig


class{name.replace("_", " ").title().replace(" ", "")}Scanner(BaseScanner):
    """Describe your scanner here."""

    def run(self) -> list[dict]:
        findings: list[dict] = []

        resp = self.client.get("/")
        if resp is None:
            return findings

        # Your scanning logic here
        # self.config has ScanConfig options
        # self.client can do get/post/request

        return findings
''')


if __name__ == "__main__":
    print("Built-in scanners:")
    for name, cls in discover_builtin_scanners().items():
        print(f"  {name}: {cls.__name__}")

    print("\nPlugins:")
    for name, cls in load_plugins().items():
        print(f"  {name}: {cls.__name__}")
    if not load_plugins():
        print("  (no plugins found — drop .py files in plugins/ dir)")
