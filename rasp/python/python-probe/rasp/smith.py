import inspect
import traceback

from rasp.probe import *


def smith_hook(func, class_id, method_id, constructor=False, can_block=False, check_recursion=False):
    def smith_wrapper(*args, **kwargs):
        if check_recursion:
            current = inspect.currentframe().f_back

            while current:
                if current.f_code.co_name == smith_wrapper.__name__ and current.f_locals.get('func') == func:
                    return func(*args, **kwargs)

                current = current.f_back

        trace = Trace(
            class_id,
            method_id,
            [str(i) for i in args[int(constructor):]],
            {key: str(value) for key, value in kwargs.items()},
            [
                '{}({}:{})'.format(frame[2], frame[0], frame[1])
                if isinstance(frame, tuple) else
                '{}({}:{})'.format(frame.name, frame.filename, frame.lineno)
                for frame in reversed(traceback.extract_stack())
            ]
        )

        if can_block and block(trace):
            send(trace)
            raise RuntimeError('API blocked by RASP')

        if surplus(class_id, method_id):
            send(trace)

        return func(*args, **kwargs)

    return smith_wrapper
