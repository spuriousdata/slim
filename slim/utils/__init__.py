import importlib


def get_class_from_string(s):
    mod, cls = s.rsplit('.', 1)
    m = importlib.import_module(mod)
    return getattr(m, cls)
