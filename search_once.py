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
    function_body = content[function_body_start:function_body_end + 1], function_body_end + 1

    return function_body


def get_function_def(content, function_body_start):
    index1 = content.rfind('(', 0, function_body_start - 1)
    index2 = content.rfind('\n', 0, index1)
    function_definition = content[index2: function_body_start]  # -1 means ignore the first '\n'
    function_definition = function_definition.replace('\n', '')
    function_definition = function_definition.replace('\t', '')

    return function_definition


def in_lock(function_body, position):
    pattern = r'\w+_lock.*\('
    locks = re.finditer(pattern, function_body)
    for lock in locks:
        n1 = function_body.count('{', lock.start(), position)
        n2 = function_body.count('}', lock.start(), position)
        ul = function_body.count(lock.group(0).replace('lock', 'unlock'), lock.start(), position)
        if n1 == n2 and ul == 0:
            return 1

    return 0


def find_unprotected_accesses(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    start = 0
    function_body_start = content.find('{', start)
    while function_body_start != -1:
        function_body, function_body_end = get_function_body(content, function_body_start)
        start = function_body_end
        function_definition = get_function_def(content, function_body_start)
        function_body_start = content.find('{', start)

        rw_once_obj_set = set()

        read_pattern = re.compile(r'READ_ONCE\([^\)]*\)')
        matches = read_pattern.findall(function_body)
        for match in matches:
            rw_once_obj_set.add(match[10:-1])

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
            # print(file_path, obj)
            positions = find_all_positions(re.escape(obj), function_body)
            #  function_body[int(position[0])-5:int(position[0])] != "ONCE(" \

            for position in positions:
                if function_body.rfind('WRITE_ONCE(', 0, int(position[0])) < function_body.rfind(')', 0,
                                                                                                 int(position[0])) \
                        and function_body.rfind('READ_ONCE(', 0, int(position[0])) < function_body.rfind(')', 0, int(
                    position[0])) \
                        and function_body.rfind('WARN_ON_ONCE', 0, int(position[0])) < function_body.rfind(')', 0, int(
                    position[0])) \
                        and function_body.rfind('xchg', 0, int(position[0])) < function_body.rfind(')', 0,
                                                                                                   int(position[0])) \
                        and function_body[int(position[0]) - 1] != '_' \
                        and function_body[int(position[1])] != '_' \
                        and function_body[int(position[0]) - 1] != '&' \
                        and '*' not in function_body[
                                       function_body.rfind('\n', 0, int(position[0])):function_body.find('\n', int(
                                           position[0]))] \
                        and not (
                        function_body.rfind('\n', 0, int(position[0])) < function_body.rfind('\"', 0, int(position[0])) \
                        and function_body.find('\n', int(position[0])) > function_body.rfind('\"', 0, int(position[0]))) \
                        and function_body.find('\n', int(position[0])) > function_body.rfind('\"', 0, int(position[0])):
                    # print('llk: ', function_body[int(position[0])-5:int(position[1])+5], function_body[int(position[1])])
                    if not in_lock(function_body, int(position[0])):
                        unprotected_accesses.append(obj)
        if len(unprotected_accesses) != 0:
            csv_data.append(('https://elixir.bootlin.com/linux/v6.6/source/' + file_path[26:], function_definition,
                             ','.join(unprotected_accesses)))
            print(file_path, '\n', function_definition, '\n', function_body)
            print('unprotected_accesses: ', unprotected_accesses, '\n')


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
