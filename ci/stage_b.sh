#!/usr/bin/env bash
# Stage B: disposable Android emulator + non-root Termux Python capabilities.
# Zero model requests, zero credentials, zero autonomous editing.
set -Eeuo pipefail
[[ "$GITHUB_ACTIONS" == true ]] || exit 20
[[ "$(adb shell getprop ro.product.cpu.abi | tr -d '\r')" == x86_64 ]] || exit 21
fingerprint=$(adb shell getprop ro.build.fingerprint | tr -d '\r')
[[ "$fingerprint" == *generic* || "$fingerprint" == *sdk_gphone* || "$fingerprint" == *emulator* ]] || exit 22
[[ "$(adb shell run-as com.termux id -u | tr -d '\r')" != 0 ]] || exit 23
p=/data/data/com.termux/files/usr
h=/data/data/com.termux/files/home
run="run-as com.termux $p/bin/env -i HOME=$h PREFIX=$p TMPDIR=$p/tmp PATH=$p/bin:/system/bin LANG=C.UTF-8"
echo 'STAGE_B: one attempt to install native Python under non-root Termux'
adb shell "$run $p/bin/bash -c 'apt-get update -qq && apt-get install -y python'"
# Transfer a synthetic-only script directly into the private Termux directory.
adb shell -T 'run-as com.termux /system/bin/sh -c "mkdir -p files/home/freedom-stage-b && cat > files/home/freedom-stage-b/probe.py"' <<'PY'
import errno, itertools, json, os, pathlib, stat, subprocess, sys, tempfile
home='/data/data/com.termux/files/home'
prefix='/data/data/com.termux/files/usr'
def require(x, name):
    if not x: raise RuntimeError(name)
require(os.getuid()!=0 and sys.executable.startswith(prefix+'/'), 'native_nonroot_python')
require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'isolated_python')
require(set(os.environ)<={'HOME','PREFIX','PATH','TMPDIR','LANG','LC_ALL','LC_CTYPE'}, 'clean_environment')
with tempfile.TemporaryDirectory(dir=home,prefix='freedom-b-') as td:
    root=pathlib.Path(td)
    st=root.lstat()
    require(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)&0o077==0,'private_workspace')
    d=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open('file',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
        os.write(fd,b'before'); os.fsync(fd)
        original=(os.fstat(fd).st_dev,os.fstat(fd).st_ino); os.close(fd); os.fsync(d)
        os.symlink('file','link',dir_fd=d)
        try: f=os.open('link',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d)
        except OSError as e: require(e.errno in (errno.ELOOP,errno.EMLINK),'nofollow')
        else: os.close(f); raise RuntimeError('symlink_followed')
        # Termux's CPython Android build lacks os.link, but Android 15 ships
        # /system/bin/ln. This is a preflight-only fixture operation: it is
        # NOT part of the trusted checker or a model-exposed command interface.
        # Fail closed if the executable or filesystem cannot create the alias.
        alias = subprocess.run(['/system/bin/ln', str(root/'file'), str(root/'hard')],
                               cwd='/', env={'PATH':'/system/bin'},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True, timeout=5)
        st=os.stat('file',dir_fd=d,follow_symlinks=False)
        diag=dict(rc=alias.returncode,stderr=alias.stderr.decode(errors='replace').replace(str(root),'<fixture>')[:400],
                  abi=os.uname().machine,uid=os.getuid(),python=sys.version.split()[0],has_os_link=hasattr(os,'link'),
                  source_device=st.st_dev,parent_device=os.fstat(d).st_dev,source_owner=st.st_uid,
                  source_mode=oct(stat.S_IMODE(st.st_mode)),source_inode=st.st_ino,nlink=st.st_nlink,
                  context=pathlib.Path('/proc/self/attr/current').read_bytes().rstrip(bytes([0,10])).decode())
        if alias.returncode:
            # A second regular unprivileged call records errno; cannot pass the original gate.
            try:
                import ctypes
                fn=ctypes.CDLL(None,use_errno=True).link
                fn.argtypes=[ctypes.c_char_p,ctypes.c_char_p]; fn.restype=ctypes.c_int
                ctypes.set_errno(0)
                rc=fn(os.fsencode(root/'file'),os.fsencode(root/'errno-fixture'))
                num=ctypes.get_errno() if rc else 0
                diag.update(libc_rc=rc,libc_errno=num,libc_reason=errno.errorcode.get(num,'UNRECOGNIZED') if num else 'OK')
            except (ImportError,AttributeError,OSError) as ex: diag['errno_probe_error']=type(ex).__name__
        print('FREEDOM_ALIAS_DIAGNOSTIC '+json.dumps(diag,sort_keys=True),flush=True)
        require(alias.returncode == 0, 'hardlink_creation_failed')
        original_st = os.stat('hard', dir_fd=d, follow_symlinks=False)
        current_st = os.stat('file', dir_fd=d, follow_symlinks=False)
        require((original_st.st_dev, original_st.st_ino) ==
                (current_st.st_dev, current_st.st_ino) and
                original_st.st_nlink == 2 and current_st.st_nlink == 2,
                'hardlink_visible')
        f=os.open('staged',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=d)
        os.write(f,b'after');os.fsync(f);os.close(f)
        os.replace('staged','file',src_dir_fd=d,dst_dir_fd=d);os.fsync(d)
        f=os.open('file',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d)
        require(os.read(f,30)==b'after' and (os.fstat(f).st_dev,os.fstat(f).st_ino)!=original,'atomic_commit')
        os.close(f)
        parent_fd=os.open('canary',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600,dir_fd=d)
        os.set_inheritable(parent_fd,True)
        try:
            child='''import errno,itertools,json,os,sys
if set(os.environ)-{'LC_ALL','LC_CTYPE'}: sys.exit(2)
if not (sys.flags.isolated and sys.flags.no_site): sys.exit(2)
for n in os.listdir('/proc/self/fd'):
 try:
  if int(n)>2: os.fstat(int(n)); sys.exit(2)
 except OSError as e:
  if e.errno != errno.EBADF: raise
raw=sys.stdin.buffer.read(100)
if raw!=b'ready':sys.exit(2)
records=({}, {'status':'ready'}, {'status':'blocked'}, {'status':None})
passed=sum(1 for k in range(5) for xs in itertools.product(range(4),repeat=k) if sum(records[i].get('status')=='ready' for i in xs)==xs.count(1))
print(json.dumps({'choice':'ready','checked':passed}))'''
            def call(data):
                return subprocess.run([sys.executable,'-I','-S','-B','-c',child],cwd='/',env={'LC_ALL':'C'},close_fds=True,input=data,capture_output=True,timeout=12)
            good=call(b'ready')
            require(good.returncode==0 and json.loads(good.stdout)=={'choice':'ready','checked':341},'isolated_checker_341')
            require(call(b'unreviewed').returncode==2,'unreviewed_code_denied')
        finally: os.close(parent_fd)
    finally: os.close(d)
print('STAGE_B_LOCAL_PREFLIGHT_PASS: 341/341, nonroot, private fs, nofollow, atomic commit, closed fd')
PY
adb shell "$run $p/bin/python -I -S -B $h/freedom-stage-b/probe.py"
echo 'STAGE_B_PASS: disposable Android native Python preflight'
echo 'ANDROID_CODING_GO=0 NO_REAL_PROJECTS=1 NO_KEYS=1'
