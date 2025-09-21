import sys
import re
import ast

HEX_RE = re.compile(r'CLng\(\s*[\'"]?&H([0-9A-Fa-f]+)[\'"]?\s*\)', re.IGNORECASE)
EXEC_RE = re.compile(r'Execute', re.IGNORECASE)

class EvalError(Exception):
    pass

def replace_clng_hex(expr):
    """Replace CLng("&HHEX") with decimal literal."""
    def repl(m):
        return str(int(m.group(1), 16))
    return HEX_RE.sub(repl, expr)

def safe_eval_expr(expr):
    """Safely evaluate a simple arithmetic expression and return int result.

    Allowed: +, -, *, /, //, unary +/-, parentheses, integer/float literals.
    Division '/' is performed as float division and converted to int (like VBScript usage here).
    """
    node = ast.parse(expr, mode='eval')

    def _eval(n):
        if isinstance(n, ast.Expression):
            return _eval(n.body)
        # constants
        if hasattr(ast, 'Constant') and isinstance(n, ast.Constant):
            if isinstance(n.value, (int, float)):
                return n.value
            raise EvalError("Unsupported constant type: %r" % type(n.value))
        if isinstance(n, ast.Num):  # older Python
            return n.n
        if isinstance(n, ast.BinOp):
            left = _eval(n.left)
            right = _eval(n.right)
            if isinstance(n.op, ast.Add):
                return left + right
            if isinstance(n.op, ast.Sub):
                return left - right
            if isinstance(n.op, ast.Mult):
                return left * right
            if isinstance(n.op, ast.Div):
                if right == 0:
                    raise EvalError("Division by zero")
                return int(left / right)
            if isinstance(n.op, ast.FloorDiv):
                if right == 0:
                    raise EvalError("Division by zero")
                return left // right
            raise EvalError("Unsupported binary operator: %r" % ast.dump(n.op))
        if isinstance(n, ast.UnaryOp):
            val = _eval(n.operand)
            if isinstance(n.op, ast.UAdd):
                return +val
            if isinstance(n.op, ast.USub):
                return -val
            raise EvalError("Unsupported unary operator: %r" % ast.dump(n.op))
        raise EvalError("Unsupported AST node: %r" % ast.dump(n))

    return int(_eval(node))

def extract_execute_paren(text):
    m = EXEC_RE.search(text)
    if not m:
        raise RuntimeError("No 'Execute' found in input")
    pos = m.end()
    while pos < len(text) and text[pos].isspace():
        pos += 1
    if pos >= len(text) or text[pos] != '(':
        return text[m.end():]
    start = pos
    pos += 1
    depth = 1
    in_quote = None
    while pos < len(text) and depth > 0:
        ch = text[pos]
        if in_quote:
            if ch == in_quote:
                if pos + 1 < len(text) and text[pos+1] == in_quote:
                    pos += 2
                    continue
                in_quote = None
                pos += 1
                continue
            else:
                pos += 1
                continue
        else:
            if ch == '"' or ch == "'":
                in_quote = ch
                pos += 1
                continue
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            pos += 1
    if depth != 0:
        raise RuntimeError("Unbalanced parentheses after Execute")
    return text[start+1:pos-1]

def find_chr_parts(expr):
    i = 0
    lower = expr.lower()
    while True:
        idx = lower.find('chr', i)
        if idx == -1:
            return
        j = idx + 3
        while j < len(expr) and expr[j].isspace():
            j += 1
        if j >= len(expr) or expr[j] != '(':
            i = idx + 3
            continue
        start = j
        j += 1
        depth = 1
        in_quote = None
        while j < len(expr) and depth > 0:
            ch = expr[j]
            if in_quote:
                if ch == in_quote:
                    if j + 1 < len(expr) and expr[j+1] == in_quote:
                        j += 2
                        continue
                    in_quote = None
                    j += 1
                    continue
                else:
                    j += 1
                    continue
            else:
                if ch == '"' or ch == "'":
                    in_quote = ch
                    j += 1
                    continue
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                j += 1
        if depth != 0:
            raise RuntimeError("Unbalanced parentheses inside chr(...)")
        inner = expr[start+1:j-1]
        yield (idx, j, inner)
        i = j

def deobfuscate_text(text):
    expr = extract_execute_paren(text)
    chars = []
    for start, end, inner in find_chr_parts(expr):
        transformed = replace_clng_hex(inner).strip()
        if transformed == "":
            raise RuntimeError("Empty expression inside chr()")
        try:
            val = safe_eval_expr(transformed)
        except Exception as e:
            raise RuntimeError("Failed to evaluate expression '%s' -> '%s': %s" % (inner, transformed, e))
        if not (0 <= val <= 0x10FFFF):
            raise RuntimeError("Value out of Unicode range: %r" % val)
        if sys.version_info[0] < 3:
            ch = unichr(val)
        else:
            ch = chr(val)
        chars.append(ch)
    result = "".join(chars)
    if re.search(r'vbcrlf', expr, re.IGNORECASE):
        result += "\r\n"
    return result

def main(argv):
    if len(argv) < 2:
        print("Usage: python vb_deobfuscator.py obfuscated.vbs [out.txt]")
        return 1
    infile = argv[1]
    outfile = argv[2] if len(argv) > 2 else None
    with open(infile, 'r') as f:
        text = f.read()
    try:
        out = deobfuscate_text(text)
    except Exception as e:
        print("Error:", e)
        return 2
    if outfile:
        with open(outfile, 'w') as f:
            f.write(out)
        print("Wrote deobfuscated output to: %s" % outfile)
    else:
        print("--- Deobfuscated output ---")
        sys.stdout.write(out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
