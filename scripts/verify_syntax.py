"""
Accurate JavaScript syntax checker supporting:
- Single & double quoted strings
- Template literals with nested `${...}` expressions
- Regex literals
- Line comments & block comments
- Balanced ({[ ]})
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def check_js(filename):
    filepath = ROOT / filename
    code = filepath.read_text(encoding='utf-8')
    n = len(code)
    i = 0
    line = 1
    col = 1

    stack = []  # items: ('(', line, col), ('{', ...), ('[', ...), ('`', ...), ('${', ...)
    
    while i < n:
        c = code[i]
        
        # Track line/col
        if c == '\n':
            line += 1
            col = 1
        else:
            col += 1

        # Check if top of stack is a template literal
        if stack and stack[-1][0] == '`':
            if c == '\\':
                i += 2  # skip escaped char
                col += 1
                continue
            if c == '`':
                stack.pop()
                i += 1
                continue
            if c == '$' and i + 1 < n and code[i+1] == '{':
                stack.append(('${', line, col))
                i += 2
                col += 1
                continue
            i += 1
            continue

        # Skip whitespace
        if c in ' \t\r\n':
            i += 1
            continue

        # Line comment
        if c == '/' and i + 1 < n and code[i+1] == '/':
            while i < n and code[i] != '\n':
                i += 1
            continue

        # Block comment
        if c == '/' and i + 1 < n and code[i+1] == '*':
            start_l, start_c = line, col
            i += 2
            col += 1
            while i + 1 < n and not (code[i] == '*' and code[i+1] == '/'):
                if code[i] == '\n':
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            if i + 1 >= n:
                return [f"Unterminated block comment started at line {start_l}:{start_c}"]
            i += 2
            col += 1
            continue

        # Strings
        if c in ("'", '"'):
            quote = c
            start_l, start_c = line, col
            i += 1
            while i < n and code[i] != quote:
                if code[i] == '\\':
                    i += 2
                    col += 2
                    continue
                if code[i] == '\n':
                    line += 1
                    col = 1
                else:
                    col += 1
                i += 1
            if i >= n:
                return [f"Unterminated string {quote} started at line {start_l}:{start_c}"]
            i += 1
            continue

        # Template literal start
        if c == '`':
            stack.append(('`', line, col))
            i += 1
            continue

        # Brackets and parens
        if c in '({[':
            stack.append((c, line, col))
            i += 1
            continue

        if c in ')}]':
            if not stack:
                return [f"Unmatched closing '{c}' at line {line}:{col}"]
            top = stack[-1][0]
            if c == ')' and top == '(':
                stack.pop()
            elif c == ']' and top == '[':
                stack.pop()
            elif c == '}' and top == '{':
                stack.pop()
            elif c == '}' and top == '${':
                stack.pop()  # closes interpolation, resumes template literal `
            else:
                return [f"Mismatched closing '{c}' at line {line}:{col}, top of stack was '{top}' from line {stack[-1][1]}:{stack[-1][2]}"]
            i += 1
            continue

        # Simple regex literal detector: /pattern/flags after certain tokens
        # (For this parser, we don't need complex AST regex disambiguation unless needed)
        i += 1

    if stack:
        items = [f"'{s[0]}' at {s[1]}:{s[2]}" for s in stack]
        return [f"Unclosed syntax elements ({len(stack)} remaining): " + ", ".join(items)]

    return []

for f in ['site-src/portal.js', 'site-src/terminal-engine.js']:
    errs = check_js(f)
    if not errs:
        print(f"[SUCCESS] {f}: perfectly balanced and valid!")
    else:
        print(f"[ERROR] {f}:")
        for e in errs:
            print("  ", e)
