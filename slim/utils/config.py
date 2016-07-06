import os
import sys
import collections
import yaml


this_module = sys.modules[__name__]


def _get(base, key, default=None):
    try:
        return getattr(base, key)
    except AttributeError:
        return default


def __dict_to_object(value):
    newvalue = None
    if isinstance(value, collections.Mapping):
        newvalue = {}
        for k, v in value.items():
            newvalue[k] = __dict_to_object(v)
        return __dict_to_namedtuple(newvalue)
    elif isinstance(value, collections.MutableSequence):  # matches list() but not str()
        newvalue = []
        for x in value:
            newvalue.append(__dict_to_object(x))
    else:
        newvalue = value
    return newvalue


def __dict_to_namedtuple(value, name='DictObject'):
    nt = collections.namedtuple(name, value.keys())
    return nt(**value)


def __setup(configfile):
    with open(configfile, 'rt') as fp:
        data = yaml.load(fp)
    for k, v in data.items():
        setattr(this_module, k, __dict_to_object(v))


__setup(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..',
                     'conf', "slim-defaults.yaml"))
