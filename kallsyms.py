"""Interface for loading symbols into a kernel bndb from /proc/kallsyms output
"""

from binaryninja import (BackgroundTaskThread, BinaryView, Symbol, SymbolType, Architecture,
                         OpenFileNameField, ChoiceField, IntegerField, get_form_input,
                         show_message_box)


def adjust_addr(bin_section_start: int, kallsym_section_start: int, symbol_addr: int) -> int:
    """Adjust the address for the binary (if the load addr differs between a kallsyms output file
    and the binary)
    """
    return int(bin_section_start) + (int(symbol_addr) - int(kallsym_section_start))

def get_architectures() -> dict:
    """Return a key/dict of architectures
    """
    archs = {}
    for arch in list(Architecture):
        archs[arch.name] = arch

    return archs


class KAllSyms(BackgroundTaskThread):
    """Class for loading symbols into a Linux kernel bndb from /proc/kallsyms output
    """

    def __init__(self, view: BinaryView) -> None:
        BackgroundTaskThread.__init__(self, '', True)
        self.view = view
        self.file = None
        self.progress = ''

    def parse_kallsyms_file(self) -> dict:
        """Parse symbol file and return a dictionary of symbols
        """
        symbols = {}
        for line in self.file.readlines():
            columns = line.split()
            addr = int(columns[0], 16)
            typ = columns[1]
            name = columns[2]
            if typ in symbols:
                symbols[typ][name] = addr
            else:
                symbols[typ] = {}
                symbols[typ][name] = addr

        return symbols

    def open_sym_file(self, filepath: str) -> (bool, str):
        """Attempt to open the symbol file
        """
        try:
            self.file = open(filepath, "r", encoding='utf-8')
        except FileNotFoundError:
            return False, f"Failed to open kallsyms output file: \"{filepath}\""

        return True, None

    def make_and_name_func(self, addr: int, name: str, typ) -> None:
        """Make a function and name it
        """
        self.view.add_function(addr)
        func = self.view.get_function_at(addr)
        if not func:
            return

        func.name = name
        func.comment = f'[{typ}]'

    def apply_function_symbols(self, symbols: list, kallsyms_text_start: int,
                               binary_text_start: int, binary_text_end: int):
        """Creates functions and applies symbols
        """
        for typ in ['t', 'T']:
            for name, addr in symbols[typ].items():
                addr = adjust_addr(binary_text_start, kallsyms_text_start, addr)
                if addr < binary_text_end and name is not None:
                    self.make_and_name_func(addr, name, typ)

    def apply_data_symbols(self, symbols: list, kallsyms_text_start: int, binary_text_start: int):
        """Creates data variables and applies symbols
        """
        for typ in ['d', 'D']:
            for name, addr in symbols[typ].items():
                addr = adjust_addr(binary_text_start, kallsyms_text_start, addr)
                if name is not None:
                    self.view.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))

    def apply_symbols(self, symbols: dict, sections: list) -> None:
        """Make functions in text section of kernel image
        """
        binary_text_start = None
        if '.text' in sections:
            binary_text_start = sections['.text'].start
        else:
            archs = get_architectures()
            arch_choices = list(archs.keys())
            arch_field = ChoiceField('Architecture', arch_choices)
            stext_field = IntegerField('stext Symbol Offset')
            get_form_input([arch_field, stext_field], 'Kernel Architecture and stext Offset')
            self.view.platform = archs[arch_choices[arch_field.result]].standalone_platform
            if stext_field.result is None:
                show_message_box('kallsyms', 'Failed to identify stext offset')
                return

            binary_text_start = stext_field.result

        binary_text_end = None
        if '.text' in sections:
            binary_text_end = sections['.text'].end
        else:
            binary_text_end = self.view.end

        kallsyms_text_start = symbols['T']['_stext']
        self.apply_function_symbols(symbols, kallsyms_text_start,
                                    binary_text_start, binary_text_end)
        self.apply_data_symbols(symbols, kallsyms_text_start, binary_text_start)
        self.view.update_analysis_and_wait()

    def run(self) -> None:
        """Run the plugin
        """
        # Open the file
        filepath = OpenFileNameField('kernel symbol file: ')
        get_form_input([filepath], 'Select file containing kallsyms output')
        filepath = filepath.result

        self.progress = 'kallsyms: importing kernel symbols...'
        status, message = self.open_sym_file(filepath)
        if status is False:
            show_message_box('kallsyms', message)
            self.progress = ''
            return

        sections = self.view.sections
        if sections is None:
            show_message_box('kallsyms', 'No sections defined')
            return

        symbols = self.parse_kallsyms_file()
        self.apply_symbols(symbols, sections)
