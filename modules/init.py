from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

class Logger:
    def __init__(self, verbosity=0):
        self.verbosity = verbosity

    def _log(self, level, msg, color=""):
        print(f"{color}[{level}] {msg}{Style.RESET_ALL}")

    def info(self, msg):
        if self.verbosity >= 0:
            self._log("INFO", msg, Fore.CYAN)

    def debug(self, msg):
        if self.verbosity >= 2:  # Only show DEBUG with -vv
            self._log("DEBUG", msg, Fore.BLUE)

    def warn(self, msg):
        if self.verbosity >= 0:
            self._log("WARN", msg, Fore.YELLOW)

    def error(self, msg):
        self._log("ERROR", msg, Fore.RED)

    def success(self, msg):
        if self.verbosity >= 0:
            self._log("SUCCESS", msg, Fore.GREEN)
