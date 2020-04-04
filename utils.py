import sys
import time
import socket
import random
import colored
import linecache
from colored import stylize
from datetime import datetime


class Logger:

    def __init__(self, title, id_num=None):
        if id_num == None:
            self.identifier = "[{}]".format(title)
        else:
            self.identifier = "[{} {}]".format(title, id_num)

    def info(self, msg, tag="INFO"):
        current_time = datetime.now().strftime("%I:%M:%S.%f %p")
        text = "[{}] {} [{}] → {}".format(
            current_time, self.identifier, tag, msg)
        print(stylize(text, colored.fg("cyan")))

    def error(self, msg, tag="ERROR"):
        current_time = datetime.now().strftime("%I:%M:%S.%f %p")

        exc_type, exc_obj, tb = sys.exc_info()
        f = tb.tb_frame
        lineno = tb.tb_lineno
        filename = f.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, f.f_globals)

        msg = msg + f"\n{lineno} → {line}"

        text = "[{}] {} [{}] → {}".format(
            current_time, self.identifier, tag, msg)
        print(stylize(text, colored.fg("red")))

    def success(self, msg, tag="SUCCESS"):
        current_time = datetime.now().strftime("%I:%M:%S.%f %p")
        text = "[{}] {} [{}] → {}".format(
            current_time, self.identifier, tag, msg)
        print(stylize(text, colored.fg("green")))


if __name__ == "__main__":
    logger = Logger("TASK", "1")
    logger.info("info")
    # logger.error("error")
    logger.success("success")
