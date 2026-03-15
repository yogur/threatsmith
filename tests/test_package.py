import threatsmith
from threatsmith.engines import Engine
from threatsmith.engines.base import Engine as BaseEngine


def test_version():
    assert isinstance(threatsmith.__version__, str)
    assert threatsmith.__version__


def test_engine_exported():
    assert Engine is BaseEngine


def test_engine_is_abstract():
    import inspect

    assert inspect.isabstract(Engine)


def test_engine_execute_signature():
    import inspect

    sig = inspect.signature(Engine.execute)
    params = list(sig.parameters)
    assert "prompt" in params
    assert "working_directory" in params


def test_prompts_package():
    import threatsmith.prompts  # noqa: F401


def test_utils_package():
    import threatsmith.utils  # noqa: F401
