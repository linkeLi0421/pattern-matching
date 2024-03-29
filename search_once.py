import re
import os
import csv

file_path_list = []
function_name_list = []
unprotected_var_list = []
csv_data = []


def get_function_body(content, function_body_start):
    brackets = []
    function_body_end = function_body_start
    for i in range(len(content) - function_body_start):
        if content[function_body_start + i] == '{':
            brackets.append(1)
        if content[function_body_start + i] == '}':
            brackets.pop()
            if len(brackets) == 0:
                function_body_end = function_body_start + i
                break
    function_body = content[function_body_start:function_body_end + 1]

    return function_body, function_body_end + 1


def get_function_def(content, function_body_start):
    index1 = content.rfind('(', 0, function_body_start - 1)
    index2 = content.rfind('\n', 0, index1)  # -1 means ignore the first '\n'
    function_definition = content[index2: function_body_start]
    function_definition = function_definition.replace('\n', '')
    function_definition = function_definition.replace('\t', '')
    function_definition = re.sub(r'\s{2,}', ' ', function_definition)

    return function_definition


def in_lock(function_body, position):
    pattern = r'\w+lock.*\('
    # enable_sync_clock() will be matched as a lock wrongly
    locks = re.finditer(pattern, function_body)
    for lock in locks:
        if 'unlock' in lock.group():
            continue
        n1 = function_body.count('{', lock.start(), position[0])
        n2 = function_body.count('}', lock.start(), position[0])
        ul = function_body.count(lock.group(0).replace('lock', 'unlock'), lock.start(), position[0])
        ul += function_body.count(lock.group(0).replace('lock', 'release'), lock.start(), position[0])
        if n1 == n2 and lock.start() < position[0] and ul == 0:
            return 1

    return 0


def is_vardef(function_body, position):
    vardef_pattern = r'\b(?:int|char|float|double|long|short)\s+(\w+)\s*(?:\[\s*\d*\s*\])?\s*;'
    matches = re.finditer(vardef_pattern, function_body)
    for match in matches:
        start_pos = match.start(1)
        end_pos = match.end(1)
        if start_pos <= position[0] <= end_pos:
            return True

    struct_pattern = r'struct\s+(\w+)\s+(\w+)\s*;'
    matches = re.finditer(struct_pattern, function_body)
    for match in matches:
        start_pos = match.start()
        end_pos = match.end()
        if start_pos <= position[0] <= end_pos:
            return True

    return False


def is_plain_write(function_body, position):
    if function_body[position[1] + 1] == '=' and function_body[position[1] + 2] == ' ':
        return True
    return False


def not_in_func_ignore(function_body, position):
    ignore_funcs = ['WRITE_ONCE', 'READ_ONCE', 'WARN_ON_ONCE', 'xchg', 'smp_store_mb', 'smp_store_release',
                    'smp_load_acquire', 'atomic_inc', 'atomic_inc_and_test', 'set_bit', 'test_and_set_bit']
    for ignore_func in ignore_funcs:
        if function_body.rfind(ignore_func, 0, position[0]) <= function_body.rfind(')', 0, position[0]):
            pass
        else:
            return False
    return True


def is_indentifier(function_body, position):
    return function_body[position[1]] != '_' and function_body[position[0] - 1] != '_' and function_body[position[0] - 1] != '&'


def is_in_comment(function_body, position):
    return '*' not in function_body[function_body.rfind('\n', 0, position[0]):function_body.find('\n', position[0])]


def is_in_string(function_body, position):
    return not (function_body.rfind('\n', 0, position[0]) < function_body.rfind('\"', 0, position[0]) \
            and function_body.find('\n', position[0]) > function_body.rfind('\"', 0, position[0])) \
            and function_body.find('\n', position[0]) > function_body.rfind('\"', 0, position[0])


def find_unprotected_accesses(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    start = 0
    function_body_start = content.find('{', start)
    while function_body_start != -1:
        function_body, function_body_end = get_function_body(content, function_body_start)
        function_definition = get_function_def(content, function_body_start)

        rw_once_obj_set = set()

        read_pattern = re.compile(r'READ_ONCE\(')
        matches = read_pattern.finditer(function_body)
        for match in matches:
            brackets = 0
            for i in range(match.end() - 1, len(function_body)):
                if function_body[i] == '(':
                    brackets += 1
                if function_body[i] == ')':
                    brackets -= 1
                if brackets == 0:
                    rw_once_obj_set.add(function_body[match.end(): i])
                    break

        unprotected_accesses = []

        def find_all_positions(pattern, text):
            positions = []
            for match in re.finditer(pattern, text):
                start, end = match.span()
                if start != end:
                    positions.append((start, end))
            return positions

        for obj in rw_once_obj_set:
            # Find all positions of "item" in the text
            positions = find_all_positions(re.escape(obj), function_body)

            for position in positions:
                if not_in_func_ignore(function_body, position) \
                    and is_indentifier(function_body, position)\
                    and is_in_comment(function_body, position) \
                    and is_in_string(function_body, position)\
                    and not is_vardef(function_body, position)\
                    and not is_plain_write(function_body, position):
                    if not in_lock(function_body, position):
                        unprotected_accesses.append(obj)
        if len(unprotected_accesses) != 0:
            csv_data.append(('https://elixir.bootlin.com/linux/v6.6/source/' + file_path[26:], function_definition,
                             ','.join(unprotected_accesses)))
            print(file_path, '\n', function_definition, '\n', function_body)
            print('unprotected_accesses: ', unprotected_accesses, '\n')

        # for the next loop
        start = function_body_end
        function_body_start = content.find('{', start)



def generate_csv(data):
    # Specify the CSV file name
    csv_file_name = "output.csv"

    # Write data to CSV file
    with open(csv_file_name, mode='w', newline='') as csv_file:
        fieldnames = ['File Path', 'Function Name', 'Unprotected Accesses']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Write header
        writer.writeheader()

        # Write data rows
        for file_path, function_name, unprotected_accesses in data:
            writer.writerow(
                {'File Path': file_path, 'Function Name': function_name, 'Unprotected Accesses': unprotected_accesses})

    print(f"CSV file '{csv_file_name}' has been generated.")


if __name__ == "__main__":
    # Provide the path to the Linux kernel source file
    dir_path = '/Users/link/linux-all/linux-v6.6'
    for main_dir, dirs, file_name_list in os.walk(dir_path):
        for file in file_name_list:
            if file.endswith('.c'):
                file_path = os.path.join(main_dir, file)
                if os.path.exists(file_path):
                    find_unprotected_accesses(file_path)
                else:
                    print(f"File not found: {file_path}")
    generate_csv(csv_data)
