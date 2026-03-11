import modules
from modules.core.plugin_loader import load_modules
from modules.core.module_registry import ModuleRegistry

def main():
    registry = ModuleRegistry()

    load_modules(modules, registry)

    # print("Loaded modules:", registry.list_modules())

    module_class = registry.get("port_scan")
    module = module_class("127.0.0.1")

    result = module.run()

    print(result)

if __name__ == '__main__':
    main()