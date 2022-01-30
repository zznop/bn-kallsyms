"""Binary Ninja plugin for applying kernel symbols from /proc/kallsyms output
"""

from binaryninja import BinaryView, PluginCommand
from .kallsyms import *

def apply_kernel_symbols(view: BinaryView):
    """Registered plugin handler function
    """

    kallsyms = KAllSyms(view)
    kallsyms.start()

PluginCommand.register(
    "kallsyms: Apply kernel symbols",
    "Apply kernel symbols from /proc/kallsyms output",
    apply_kernel_symbols
)
