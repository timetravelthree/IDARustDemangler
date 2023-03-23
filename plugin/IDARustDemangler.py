import shutil
import subprocess
import os

try:
    import ida_kernwin
    import idautils
    import idaapi
    import idc
except ModuleNotFoundError:
    print("[!] This is an IDA script")
    exit(-1)


class IDARustDemangler():
    """
    IDARustDemangler is a tool that demangles and normalizes symbols for use with the IDA disassembler.
    It replaces or modifies special characters to make them compatible with IDA's syntax, 
    making binary analysis faster and more efficient.
    """

    def __init__(self, debug=False):
        self.debug = debug
        self.num_resolved = 0
        self.hash_prefix = "17h"
        self.delimiters = "><"
        self.badchars = "*,'`" + self.delimiters
        self.queue = {}
        self.resolved = {}
        self.rs_dml = shutil.which("rs-dml")
        assert len(self.rs_dml) > 0, "rs-dml is not installed on your system"

    def add(self, address: int, symbol: str) -> None:
        # Must add support for non legacy symbols

        # If the hash is present
        if symbol.lstrip("_").startswith("Z") and self.hash_prefix in symbol:
            hash = symbol.split(self.hash_prefix)[-1].rstrip("E")

            # If the hash length is not 16 skip as it is not a valid rust legacy symbol
            if len(hash) != 16:
                return

            self.queue[address, hash] = symbol.encode()

    def resolve(self):
        # Pass symbols which should be resolved to the stdin of `rs-dml` and map
        # the results to the correct values
        process_rs_dml = subprocess.Popen(
            [self.rs_dml], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
        resolved_symbols, _ = process_rs_dml.communicate(
            input=b"\n".join(self.queue.values()))
        self.resolved = zip(self.queue.keys(),
                            resolved_symbols.decode().splitlines())

    def apply(self):
        # for each symbol resolved normalize it and apply it to the IDA db

        for (address, hash), symbol in self.resolved:
            normalized = self.ida_normalize(symbol)

            # If normalization succeded and all the character in the normalized
            # symbol are valid set the name in IDA

            if any([badchar in normalized for badchar in self.badchars]) and self.debug:
                print(
                    f"[ERROR] {address:#016x} -> sym:'{symbol}', hash: '{hash}', normalized: '{normalized}'")
                continue

            if self.debug:
                print(
                    f"[*] {address:#016x} -> sym:'{symbol}', hash: '{hash}', normalized: '{normalized}'")

            # set the name and add the hash at the end
            idc.set_name(address, normalized + str(len(hash)) + hash)
            self.num_resolved += 1

    def ida_normalize(self, name: str) -> str:
        """
        This function tries to normalize sybmols to be accepted by IDA
        """

        # Replace bad characters with accepted ones
        # unfortunately there is no way known to me
        # to insert these chars into IDA symbol names

        name = name.replace(" ", "_")
        name = name.replace(",", "")
        name = name.replace("{", "<")
        name = name.replace("}", ">")

        i = 0
        output = "_ZN"

        while i < len(name):
            if name[i] == "<":
                # 'I' corresponds to '<'
                output += "I"
                i += 1
            elif name[i] == ">":
                # 'E' corresponds to '>'
                output += "E"
                i += 1
            elif name[i] == "*":
                # 'P' corresponds to pointer-type word
                output += "P"
                i += 1
            else:

                # if it the `word` starts with "::" skip it
                # as IDA automatically adds it
                if name[i:i+2] == "::":
                    i += 2

                # this should find the closest delimiter to
                # recognize the entire word

                idxs = []

                for special_char in self.delimiters:
                    tmp_idx = name[i+1:].find(special_char)

                    if tmp_idx != -1:
                        idxs.append(tmp_idx)

                if len(idxs) >= 1:
                    idx = min(idxs)
                    word = name[i:i+idx + 1]
                else:
                    word = name[i:]

                if len(word) > 0:
                    if "*" in word:
                        # if '*' is present it means it is a pointer just have
                        # to a number of 'P' at the start of the word
                        # corresponding to the number of '*'
                        output += "P" * word.count("*")
                        i += word.count("*")
                        word = word.replace("*", "")

                    output += str(len(word)) + word

                i += len(word)

        output += "E"
        return output


# Register the actual plugin
class IDARustDemangleHandler(idaapi.plugin_t):
    PLUGIN_NAME = "IDA Rust Demangler"
    PLUGIN_DIRECTORY = "IDARustDemangler"
    PLUGIN_DESCRIPTION = "Rust name demangler"

    flags = idaapi.PLUGIN_UNL
    comment = PLUGIN_DESCRIPTION
    help = PLUGIN_DESCRIPTION
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.r = IDARustDemangler(debug=False)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print(f"[*] {self.PLUGIN_NAME} started!")

        # push every symbol name that is found
        # invalid symbols will be discarded
        for address, name in idautils.Names():
            self.r.add(address, name)

        # resolve with rs-dml
        self.r.resolve()

        # apply the results in ida
        self.r.apply()

        print(f"[*] Demangled {self.r.num_resolved} symbols")
        print(f"[*] {self.PLUGIN_NAME} has finished!")

        return 1

    def term(self):
        pass


class IDARustDemanglerHook(ida_kernwin.UI_Hooks):
    """
    this class is only used to install the icon to the corresponding IDA action
    """

    def __init__(self, cb):
        super().__init__()
        self.cb = cb

    def updated_actions(self):
        if self.cb():
            self.unhook()


def install_icon():
    plugin_name = IDARustDemangleHandler.PLUGIN_NAME
    action_name = "Edit/Plugins/" + plugin_name
    LOGO_PATH = None

    # if the action is not present wait for our hook action
    if action_name not in ida_kernwin.get_registered_actions():
        return False

    # check if in any of the IDA plugins directory if there is
    # our plugin directory and take the logo from there
    for plugin_path in idaapi.get_ida_subdirs("plugins"):
        LOGO_PATH = os.path.join(
            plugin_path, f"{IDARustDemangleHandler.PLUGIN_DIRECTORY}\\rust-logo.png")

        # if the file exists use the first one found
        if os.path.isfile(LOGO_PATH):
            break

    if LOGO_PATH is None:
        print("[?] IDA Rust Demangler logo not found")
        return True

    # load the logo and apply it to the action
    icon = idaapi.load_custom_icon(
        LOGO_PATH, format="png")

    ida_kernwin.update_action_icon(action_name, icon)

    return True


def PLUGIN_ENTRY():
    return IDARustDemangleHandler()


h = IDARustDemanglerHook(install_icon)
h.hook()
