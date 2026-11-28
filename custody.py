"""Private single-writer file custody, adapted from the supplied v0.3 pilot."""

import contextlib, fcntl, hashlib, json, os, secrets, stat

DIR=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC

READ=os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC

CREATE=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC

class Stop(Exception):
    pass

def need(test, reason):
    if not test:
        raise Stop(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def wire(obj):
    return (json.dumps(obj, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
                       allow_nan=False) + "\n").encode("ascii")

def decode(raw):
    def unique(pairs):
        obj = dict(pairs)
        need(len(pairs) == len(obj), "duplicate_json_key")
        return obj
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise Stop("invalid_json") from None

@contextlib.contextmanager
def private_dir(parent, name):
    fd = os.open(name, DIR, dir_fd=parent)
    try:
        info = os.fstat(fd)
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
             "unsafe_directory")
        yield fd
    finally:
        os.close(fd)

def identity(info):
    return [info.st_dev, info.st_ino]

def read_object(parent, name, cap=8192):
    fd = os.open(name, READ, dir_fd=parent)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
             info.st_size <= cap, "unsafe_file")
        raw = f.read(cap + 1)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(len(raw) == info.st_size == after.st_size and after.st_nlink == 1 and
             after.st_ctime_ns == info.st_ctime_ns and identity(named) == identity(info), "unstable_file")
        return raw, identity(info)

def read_file(parent, name, cap=8192):
    return read_object(parent, name, cap)[0]

def exists(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True

def create_file(parent, name, raw):
    fd = os.open(name, CREATE, 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    os.fsync(parent)

def install_stage(parent, staged, name):
    os.replace(staged, name, src_dir_fd=parent, dst_dir_fd=parent)
    os.fsync(parent)

def mkdir(fd, name):
    os.mkdir(name, 0o700, dir_fd=fd)
    os.fsync(fd)

def atomic_new(fd, name, data):
    # Caller holds an exclusive lock on the private mission directory.
    need(not exists(fd, name), "immutable_destination_exists")
    temp = ".tmp-" + secrets.token_hex(12)
    create_file(fd, temp, data)
    need(not exists(fd, name), "immutable_destination_changed")
    install_stage(fd, temp, name)

@contextlib.contextmanager
def locked(parent, name):
    with private_dir(parent, name) as fd:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd

@contextlib.contextmanager
def root(path):
    need(os.getuid() != 0 and getattr(os,"geteuid",os.getuid)() != 0 and path.is_absolute() and ".." not in path.parts, "nonroot_absolute_root")
    fd = os.open("/", DIR)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        s = os.fstat(fd)
        need(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700, "private_root")
        yield fd
    finally:
        os.close(fd)

def names(directory):
    # A pinned private dirfd remains open for this operation on both paths.
    if os.listdir in os.supports_fd:
        return os.listdir(directory)
    path = "/proc/self/fd/" + str(directory)
    before = os.fstat(directory)
    need(stat.S_ISDIR(before.st_mode) and identity(os.stat(path)) == identity(before), "dirfd_listing_unavailable")
    result = os.listdir(path)
    need(identity(os.stat(path)) == identity(before), "dirfd_listing_changed")
    return result
