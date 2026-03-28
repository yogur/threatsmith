from threatsmith.engines.base import Engine
from threatsmith.engines.claude_code import ClaudeCodeEngine
from threatsmith.engines.codex import CodexEngine


def get_engine(
    engine_name: str,
    verbose: bool = False,
    scanner_names: list[str] | None = None,
) -> Engine:
    """Return the correct engine instance for the given engine name."""
    engines = {
        "claude-code": ClaudeCodeEngine,
        "codex": CodexEngine,
    }
    if engine_name not in engines:
        raise ValueError(
            f"Unknown engine: {engine_name!r}. Choose from: {list(engines)}"
        )
    return engines[engine_name](verbose=verbose, scanner_names=scanner_names)


__all__ = ["Engine", "ClaudeCodeEngine", "CodexEngine", "get_engine"]
