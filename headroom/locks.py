"""Cross-platform file locking for headroom.

Unix uses :func:`fcntl.flock` directly, preserving the existing advisory,
whole-file shared/exclusive semantics.  Windows uses ``msvcrt.locking`` on
byte zero.  Windows locks are mandatory rather than advisory, have no shared
mode, and must be unlocked before the file is closed.  Both backends release
locks when the process dies; after abrupt Windows termination, release occurs
when the OS closes the process handle.  ``LK_LOCK`` retries once per second
for ten attempts rather than waiting indefinitely like blocking ``flock``.
"""
import contextlib
import errno
import os

if os.name == "nt":
    import msvcrt as _msvcrt
    _fcntl = None
else:
    import fcntl as _fcntl
    _msvcrt = None


class UnsupportedOnWindows(RuntimeError):
    """Raised when code requests a lock mode unavailable on Windows."""


def _descriptor(fileobj):
    return fileobj if isinstance(fileobj, int) else fileobj.fileno()


def _seek_zero(fileobj):
    os.lseek(_descriptor(fileobj), 0, os.SEEK_SET)


def exclusive(fileobj, blocking=True) -> bool:
    """Acquire an exclusive lock, returning ``False`` on nonblocking contention."""
    if _msvcrt is None:
        flags = _fcntl.LOCK_EX
        if not blocking:
            flags |= _fcntl.LOCK_NB
        try:
            _fcntl.flock(fileobj, flags)
        except BlockingIOError:
            return False
        return True

    _seek_zero(fileobj)
    mode = _msvcrt.LK_LOCK if blocking else _msvcrt.LK_NBLCK
    try:
        _msvcrt.locking(_descriptor(fileobj), mode, 1)
    except OSError as error:
        if not blocking and error.errno in {
                errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            return False
        raise
    return True


def shared(fileobj) -> bool:
    """Acquire a shared lock, which Windows cannot represent safely."""
    if _msvcrt is not None:
        raise UnsupportedOnWindows("shared file locks are unavailable on Windows")
    _fcntl.flock(fileobj, _fcntl.LOCK_SH)
    return True


def unlock(fileobj) -> None:
    """Release a lock before closing its file or descriptor."""
    if _msvcrt is None:
        _fcntl.flock(fileobj, _fcntl.LOCK_UN)
        return
    _seek_zero(fileobj)
    _msvcrt.locking(_descriptor(fileobj), _msvcrt.LK_UNLCK, 1)


def close(fileobj):
    """Close a held lease, explicitly unlocking first where Windows requires it."""
    try:
        if _msvcrt is not None:
            unlock(fileobj)
    finally:
        if isinstance(fileobj, int):
            os.close(fileobj)
        else:
            fileobj.close()


@contextlib.contextmanager
def exclusive_lock(fileobj, blocking=True):
    """Context-manager form of :func:`exclusive`."""
    acquired = exclusive(fileobj, blocking=blocking)
    try:
        yield acquired
    finally:
        if acquired:
            unlock(fileobj)


@contextlib.contextmanager
def shared_lock(fileobj):
    """Context-manager form of :func:`shared`."""
    shared(fileobj)
    try:
        yield
    finally:
        unlock(fileobj)
