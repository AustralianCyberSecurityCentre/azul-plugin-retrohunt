"""Environment context for finding exe paths."""

import os


class ExecutableNotFound(OSError):
    """Unable to find requested executable on paths."""

    pass


def find_executable(name, extra_paths=None):
    """Return full path to requested executable."""
    paths = list(os.environ["PATH"].split(os.pathsep))
    if extra_paths:
        paths.extend(extra_paths)
    for p in paths:
        f = os.path.join(p, name)
        if os.path.isfile(f):
            return f
    raise ExecutableNotFound("Executable '{}' not found in path: {}".format(name, paths))


extra_paths = (os.path.join(os.path.dirname(__file__), "bin"),)
executables = {
    "bgparse": find_executable("bgparse", extra_paths=extra_paths),
}
