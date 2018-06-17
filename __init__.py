from binaryninja import *
from .kallsyms import *

def apply_kernel_symbols(view):
    kallsyms = KAllSyms(view)
    kallsyms.start()

PluginCommand.register(
    "kallsyms: Apply kernel symbols",
    "Apply kernel symbols to analysis from kallsyms output",
    apply_kernel_symbols
)
