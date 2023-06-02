from colorama import Fore
from log import logger

# Пресеты колорамы
def print_yellow(message):
    logger.error(Fore.YELLOW + message + Fore.RESET)

def print_red(message):
    logger.warning(Fore.RED + message + Fore.RESET)
