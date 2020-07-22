from binaryninja import *

class KAllSyms(BackgroundTaskThread):
    def __init__(self, view):
        BackgroundTaskThread.__init__(self, "", True)
        self.view = view
        self.file = None
        self.progress = ""

    def parse_kallsyms_file(self):
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

    def open_sym_file(self, filepath):
        """Attempt to open the symbol file
        """
        try:
            self.file = open(filepath, "r")
        except Exception as e:
            return False, "Failed to open kallsyms output file: \"{}\"".format(filepath)

        return True, None

    def adjust_addr(self, bin_section_start, kallsym_section_start, symbol_addr):
        """Adjust the address for the binary (if the load addr differs between a kallsyms output file and the binary)
        """
        return int(bin_section_start) + (int(symbol_addr) - int(kallsym_section_start))

    def make_and_name_func(self, addr, name, typ):
        """Make a function and name it
        """
        self.view.add_function(addr)
        func = self.view.get_function_at(addr)
        func.name = name
        func.comment = "[{}]".format(typ)

    def get_architectures(self):
        """Return a key/dict of architectures
        """
        archs = {}
        for arch in list(Architecture):
            archs[arch.name] = arch

        return archs

    def make_functions(self, symbols, sections):
        """Make functions in text section of kernel image
        """
        binary_text_start = None
        if ".text" in sections:
            binary_text_start = sections[".text"].start
        else:
            archs = self.get_architectures()
            arch_choices = list(archs.keys())
            arch_field = ChoiceField("Architecture", arch_choices)
            stext_field = IntegerField("stext Symbol Offset")
            get_form_input([arch_field, stext_field], "Kernel Architecture and stext Offset")
            self.view.platform = archs[arch_choices[arch_field.result]].standalone_platform
            if stext_field.result == None:
                show_message_box("kallsyms", "Failed to identify stext offset")
                return

            binary_text_start = stext_field.result

        binary_text_end = None
        if ".text" in sections:
            binary_text_end = sections[".text"].end
        else:
            binary_text_end = self.view.end

        kallsyms_text_start = symbols["T"]["_stext"]
        for name, addr in symbols["T"].items():
            addr = self.adjust_addr(binary_text_start, kallsyms_text_start, addr)
            if addr < binary_text_end and name != None:
                self.make_and_name_func(addr, name, "T")

        for name, addr in symbols["t"].items():
            addr = self.adjust_addr(binary_text_start, kallsyms_text_start, addr)
            if addr < binary_text_end and name != None:
                self.make_and_name_func(addr, name, "t")

        self.view.update_analysis_and_wait() 

    def run(self):
        """Run the plugin
        """
        # Open the file
        filepath = OpenFileNameField("kallsyms file: ")
        get_form_input([filepath], "Select file containing kallsyms output")
        filepath = filepath.result

        self.progress = "kallsyms: importing kernel symbols..."
        status, message = self.open_sym_file(filepath)
        if status is False:
            show_message_box("kallsyms", message)
            self.progress = ""
            return

        sections = self.view.sections
        if sections is None:
            show_message_box("kallsyms", "No sections defined")
            return

        symbols = self.parse_kallsyms_file()
        self.make_functions(symbols, sections)
