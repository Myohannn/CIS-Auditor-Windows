# input .audit file
# output version source file

from bs4 import BeautifulSoup
import pandas as pd
import re


regexes = {
    'type': re.compile(r'type\s+:\s+(.*?)\n'),
    'description': re.compile(r'description\s+:\s+(.*?)\n'),
    'value_data': re.compile(r'value_data\s+:\s+(.*?)\n'),
    'reg_key': re.compile(r'reg_key\s+:\s+(.*?)\n'),
    'reg_item': re.compile(r'reg_item\s+:\s+(.*?)\n'),
    'audit_policy_subcategory': re.compile(r'audit_policy_subcategory\s+:\s+(.*?)\n'),
    'key_item': re.compile(r'key_item\s+:\s+(.*?)\n')
}


def read_file(filename):
    contents = ''
    try:
        # display('Reading {}'.format(filename), verbose=True)
        with open(filename, 'r') as file_in:
            contents = file_in.read()
    except Exception as e:
        print('ERROR: reading file: {}: {}'.format(filename, e))

    return contents


def find_element(audit):
    data = []

    soup = BeautifulSoup(audit, 'lxml')

    # Find all the custom_item elements
    items = soup.find_all('custom_item')

    # Extract the required data from each custom_item
    for item in items:
        item_str = str(item).replace('"', '')

        type = regexes['type'].search(item_str)
        type = type.group(1) if type else None

        description = regexes['description'].search(item_str)
        description = description.group(1) if description else None

        if description[0].isdigit():
            index = re.search(r'(.*?)\s', description)
            index = index.group(1) if index else None
            description = description.replace(index, '').strip()
        else:
            index = 0

        value_data = regexes['value_data'].search(item_str)
        value_data = value_data.group(1) if value_data else None

        reg_key = regexes['reg_key'].search(item_str)
        reg_key = reg_key.group(1) if reg_key else None

        reg_item = regexes['reg_item'].search(item_str)
        reg_item = reg_item.group(1) if reg_item else None

        key_item = regexes['key_item'].search(item_str)
        key_item = key_item.group(1) if key_item else None

        if key_item:
            reg_item = key_item

        audit_policy_subcategory = regexes['audit_policy_subcategory'].search(
            item_str)
        audit_policy_subcategory = audit_policy_subcategory.group(
            1) if audit_policy_subcategory else None
        
        # Append the data to the list
        data.append(["", type, index, description,
                    reg_key, reg_item, audit_policy_subcategory, value_data])

    return data


def output_file(data, out_fname):
    # Create a DataFrame from the data
    df = pd.DataFrame(data, columns=['Checklist', 'Type', 'Index', 'Description',
                                     'Reg Key',  'Reg Item', 'Audit Policy Subcategory', 'Value Data'])

    # Write the DataFrame to an Excel file
    df.to_excel(out_fname, index=False)
    print(f"File export success --- {out_fname}")


if __name__ == '__main__':

    src_fname = 'src/test.audit'
    audit = read_file(src_fname)

    data = find_element(audit)

    out_fname = 'out\source.xlsx'
    output_file(data, out_fname)
