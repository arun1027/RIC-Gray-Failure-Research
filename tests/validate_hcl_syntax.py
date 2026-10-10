import sys

def check_hcl(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    stack = []
    in_string = False
    escape = False
    in_line_comment = False
    in_block_comment = False
    i = 0
    line = 1
    col = 1
    while i < len(content):
        ch = content[i]
        if ch == '\n':
            line += 1
            col = 1
            in_line_comment = False
            i += 1
            continue
        col += 1
        if in_line_comment:
            i += 1
            continue
        if in_block_comment:
            if ch == '*' and i + 1 < len(content) and content[i+1] == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '#' or (ch == '/' and i + 1 < len(content) and content[i+1] == '/'):
            in_line_comment = True
            i += 1
            continue
        if ch == '/' and i + 1 < len(content) and content[i+1] == '*':
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch in '({[':
            stack.append((ch, line, col))
        elif ch in ')}]':
            if not stack:
                print(f"Error in {filename}: Unmatched closing {ch} at line {line}:{col}")
                return False
            top, l, c = stack.pop()
            matches = {'(': ')', '{': '}', '[': ']'}
            if matches[top] != ch:
                print(f"Error in {filename}: Mismatched {top} (line {l}) with {ch} (line {line})")
                return False
        i += 1
    if stack:
        print(f"Error in {filename}: Unclosed {stack}")
        return False
    print(f"OK: {filename}")
    return True

all_ok = True
for path in ['terraform/aws-eks/main.tf', 'terraform/aws-eks/variables.tf', 'terraform/aws-eks/outputs.tf']:
    if not check_hcl(path):
        all_ok = False

if not all_ok:
    sys.exit(1)
print("All HCL files successfully syntax-checked for balanced delimiters!")

