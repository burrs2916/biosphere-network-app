#!/usr/bin/env python3
import re

with open('src/core/engine/database.rs', 'r') as f:
    content = f.read()

# Strategy: Find each method body and determine if it's read or write
# Then replace self.conn.lock().unwrap() within that method body

# Split content into methods
# We'll use a state machine approach
lines = content.split('\n')
result_lines = []
method_type = 'write'  # default
brace_depth = 0
in_method = False

for i, line in enumerate(lines):
    # Detect method start
    if re.match(r'\s+pub fn \w+', line) or re.match(r'\s+fn \w+', line):
        # Look ahead to find the method body and determine type
        # Scan forward to find INSERT/UPDATE/DELETE vs SELECT
        method_body = []
        temp_depth = 0
        found_open = False
        for j in range(i, min(i + 100, len(lines))):
            method_body.append(lines[j])
            temp_depth += lines[j].count('{') - lines[j].count('}')
            if '{' in lines[j]:
                found_open = True
            if found_open and temp_depth <= 0:
                break
        
        body_text = '\n'.join(method_body)
        
        # Check for write operations
        if any(op in body_text for op in ['INSERT ', 'UPDATE ', 'DELETE ', 'VACUUM', 'ANALYZE', 'REINDEX', 'execute_batch']):
            method_type = 'write'
        elif 'SELECT' in body_text or 'query_row' in body_text or 'query_map' in body_text:
            method_type = 'read'
        else:
            # Default to write for safety
            method_type = 'write'
    
    # Replace self.conn.lock().unwrap() with appropriate call
    if 'self.conn.lock().unwrap()' in line:
        if method_type == 'read':
            line = line.replace('self.conn.lock().unwrap()', 'self.conn.read().unwrap()')
        else:
            line = line.replace('self.conn.lock().unwrap()', 'self.conn.write().unwrap()')
    
    result_lines.append(line)

with open('src/core/engine/database.rs', 'w') as f:
    f.write('\n'.join(result_lines))

# Count replacements
read_count = sum(1 for line in result_lines if 'self.conn.read().unwrap()' in line)
write_count = sum(1 for line in result_lines if 'self.conn.write().unwrap()' in line)
lock_count = sum(1 for line in result_lines if 'self.conn.lock().unwrap()' in line)
print(f'Done! read={read_count}, write={write_count}, remaining lock={lock_count}')
