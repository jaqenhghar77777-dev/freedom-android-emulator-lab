"""Native checker for a bounded pure Python expression. Standalone child, stdlib only."""
import ast
import errno
import json
import os
import sys

HEADER = b"def adjusted(x, d, cap):\n    return "
BASE = HEADER + b"x\n"
EXAMPLES = [[2,1,5,3],[1,-4,5,0],[5,4,5,5],[0,0,0,0],[-3,4,2,1]]
VECTORS = (json.dumps(EXAMPLES,separators=(",",":"))+"\n").encode("ascii")
LIMIT = 31

def render(raw):
    if type(raw) is not str or not 0 < len(raw) <= 256 or any(not 32 <= ord(c) <= 126 for c in raw):
        raise ValueError("answer_format")
    ops = json.loads(raw)
    if type(ops) is not list or not 1 <= len(ops) <= LIMIT:
        raise ValueError("token_count")
    stack = []
    for word in ops:
        if type(word) is not str:
            raise ValueError("token_type")
        if word in ("x","d","cap","zero"):
            stack.append("0" if word=="zero" else word)
            continue
        if word not in ("add","sub","min","max") or len(stack)<2:
            raise ValueError("opcode_or_stack")
        b, a = stack.pop(), stack.pop()
        if word in ("min","max"):
            stack.append(f"{word}({a}, {b})")
        else:
            symbol = "+" if word=="add" else "-"
            stack.append(f"({a} {symbol} {b})")
    if len(stack)!=1:
        raise ValueError("stack_arity")
    return HEADER + stack[0].encode("ascii") + b"\n"

def approved_module(code):
    # Independently reconstruct canonical bytes from a syntax tree before compiling.
    if len(code)>480 or not code.startswith(HEADER) or not code.endswith(b"\n") or code.count(b"\n")!=2:
        raise ValueError("source_template")
    expression = code[len(HEADER):-1].decode("ascii")
    tree = ast.parse(expression,mode="eval").body
    count = 0
    def visit(node):
        nonlocal count
        count += 1
        if count>LIMIT: raise ValueError("source_size")
        if type(node) is ast.Name and node.id in ("x","d","cap"): return node.id
        if type(node) is ast.Constant and type(node.value) is int and node.value==0: return "0"
        if type(node) is ast.BinOp and type(node.op) in (ast.Add,ast.Sub):
            symbol = "+" if type(node.op) is ast.Add else "-"
            return f"({visit(node.left)} {symbol} {visit(node.right)})"
        if (type(node) is ast.Call and type(node.func) is ast.Name and node.func.id in ("min","max")
                and len(node.args)==2 and not node.keywords):
            return f"{node.func.id}({visit(node.args[0])}, {visit(node.args[1])})"
        raise ValueError("instruction")
    if visit(tree) != expression: raise ValueError("noncanonical_source")
    return compile(code,"<synthetic-adjust>","exec")

def verify(code):
    compiled = approved_module(code)
    globals_ = {"__builtins__":{}, "min":min, "max":max}
    exec(compiled,globals_)
    fn = globals_["adjusted"]
    examples = sum(fn(x,d,c)==e for x,d,c,e in EXAMPLES)
    passed=0
    for x in range(-4,5):
        for d in range(-4,5):
            for cap in range(5):
                total=x+d
                expected=0 if total<0 else cap if total>cap else total
                passed += fn(x,d,cap)==expected
    return {"supplied":examples,"supplied_total":5,"exhaustive":passed,"exhaustive_total":405}

def clean():
    if (not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
            or os.getcwd()!="/" or set(os.environ)-{"LC_ALL","LC_CTYPE"}):
        raise ValueError("unclean_startup")
    for name in os.listdir("/proc/self/fd"):
        if int(name)<=2: continue
        try: os.fstat(int(name))
        except OSError as err:
            if err.errno==errno.EBADF: continue
            raise
        raise ValueError("inherited_descriptor")

def main():
    clean()
    raw=sys.stdin.buffer.read(481)
    if len(raw)>480: raise ValueError("size")
    def stop_io(event,args):
        if event=="open" or event.startswith("socket.") or event in (
            "subprocess.Popen","os.exec","os.fork","os.forkpty","os.system","os.spawn","os.posix_spawn"):
            raise ValueError("unexpected_runtime_io")
    sys.addaudithook(stop_io)
    print(json.dumps(verify(raw),separators=(",",":")))

if __name__=="__main__":
    try: main()
    except (OSError,ValueError,SyntaxError,RecursionError): sys.exit(2)
