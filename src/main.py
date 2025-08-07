# @category GCL
# @runtime PyGhidra

if __name__ == "__main__":
    try:
        import importlib.util
        import sys
        import os
        import cp

        print(f"Python version: {sys.version}")
    except:
        sys.path.append(os.path.dirname(__file__))
        import cp
    finally:
        plugin = "findcrypt3"
        cp.currentProgram = currentProgram

        plugin_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "plugins")
        )
        plugin_path = os.path.join(plugin_dir, plugin + ".py")

        print(f"Loading plugin from: {plugin_path}")
        spec = importlib.util.spec_from_file_location(plugin, plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.PLUGIN_ENTRY().run(0)
        print("Done")
