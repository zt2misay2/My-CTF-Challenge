import sys
import importlib.util
import os
import sage.all


LOCAL_SOURCE_FILE = "local_misc.py"
TARGET_MODULE_NAME = "sage.arith.misc"


def replace_entire_module():
    spec = importlib.util.spec_from_file_location(TARGET_MODULE_NAME, LOCAL_SOURCE_FILE)
    local_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(local_module)

    sys.modules[TARGET_MODULE_NAME] = local_module


    current_globals = globals()

    for attr_name in dir(local_module):
        if attr_name.startswith("_"):
            continue

        new_obj = getattr(local_module, attr_name)

        if hasattr(sage.all, attr_name):
            setattr(sage.all, attr_name, new_obj)
        current_globals[attr_name] = new_obj

    return local_module


replace_entire_module()
