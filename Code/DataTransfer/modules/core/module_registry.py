class ModuleRegistry:

    def __init__(self):
        self.modules = {}

    def register(self, module_class):

        name = module_class.name
        self.modules[name] = module_class

    def list_modules(self):
        return list(self.modules.keys())

    def get(self, name):
        return self.modules.get(name)