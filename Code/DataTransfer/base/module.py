from abc import ABC, abstractmethod

class BaseModule(ABC):

    name = "base"
    description = "base module"
    category = "generic"

    def __init__(self, target):
        self.target = target

    @abstractmethod
    def run(self):
        pass