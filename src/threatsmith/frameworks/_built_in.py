"""
Built-in framework pack registrations.

Each framework registers itself here. Importing this module is sufficient to register all
built-in frameworks.
"""

from threatsmith.frameworks.pasta import build_pasta_pack
from threatsmith.frameworks.stride_4q import build_stride_4q_pack
from threatsmith.frameworks.types import register_framework

register_framework(build_stride_4q_pack())

register_framework(build_pasta_pack())

# LINDDUN Pro and MAESTRO are deferred to a future release.
