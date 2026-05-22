# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import logging
from abc import ABCMeta, abstractmethod


class Cronjob(metaclass=ABCMeta):
    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.success = False

    @abstractmethod
    def run(self):
        pass

    def execute(self):
        try:
            self.log.info("Starting execution")
            self.run()
            self.success = True
        except Exception:
            self.log.exception("Execution failed")
            raise  # <--- this line ensures failures propagate
        finally:
            self.log.info("Finished execution")
