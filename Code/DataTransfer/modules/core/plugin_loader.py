import importlib
import pkgutil
from base.module import BaseModule


def load_modules(package, registry):

    for loader, name, ispkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):

        module = importlib.import_module(name)

        for attr in dir(module):

            obj = getattr(module, attr)

            try:
                if issubclass(obj, BaseModule) and obj is not BaseModule:
                    registry.register(obj)

            except TypeError:
                continue