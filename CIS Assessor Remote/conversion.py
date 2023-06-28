from bs4 import BeautifulSoup
import pandas as pd
import re


regexes = {
    'type': re.compile(r'type\s+:\s+(.*?)\n'),
    'description': re.compile(r'description\s+:\s+(.*?)\n'),
    'value_data': re.compile(r'value_data\s+:\s+(.*?)\n'),
    'reg_key': re.compile(r'reg_key\s+:\s+(.*?)\n'),
    'reg_item': re.compile(r'reg_item\s+:\s+(.*?)\n'),
    'reg_option': re.compile(r'reg_option\s+:\s+(.*?)\n'),
    'audit_policy_subcategory': re.compile(r'audit_policy_subcategory\s+:\s+(.*?)\n'),
    'key_item': re.compile(r'key_item\s+:\s+(.*?)\n'),
    'right_type': re.compile(r'right_type\s+:\s+(.*?)\n')
}


data_dict = {

    "PASSWORD_POLICY": [],
    "REGISTRY_SETTING": [],
    "LOCKOUT_POLICY": [],
    "USER_RIGHTS_POLICY": [],
    "CHECK_ACCOUNT": [],
    "BANNER_CHECK": [],
    "ANONYMOUS_SID_SETTING": [],
    "AUDIT_POLICY_SUBCATEGORY": [],
    "REG_CHECK": [],

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

    soup = BeautifulSoup(audit, 'lxml')

    # Find all the custom_item elements
    items = soup.find_all('custom_item')

    # Extract the required data from each custom_item
    for item in items:
        item_str = str(item)
        # item_str = str(item).replace('"', '')

        type = regexes['type'].search(item_str)
        type = type.group(1) if type else None

        if type == "AUDIT_POWERSHELL":
            continue
        else:
            type = type.strip()

        description = regexes['description'].search(item_str)
        description = description.group(1) if description else None
        description = description.replace('"', '')

        if description[0].isdigit():
            index = re.search(r'(.*?)\s', description)
            index = index.group(1) if index else None
            description = description.replace(index, '').strip()
        else:
            index = 0

        index = str(index).strip()

        value_data = regexes['value_data'].search(item_str)
        value_data = value_data.group(1) if value_data else None
        value_data = str(value_data).replace('"', '')
        value_data = str(value_data).replace('&amp;&amp;', '&&')

        reg_key = regexes['reg_key'].search(item_str)
        reg_key = (reg_key.group(1)).replace('"', '') if reg_key else None

        reg_item = regexes['reg_item'].search(item_str)
        reg_item = (reg_item.group(1)).replace('"', '') if reg_item else None

        reg_option = regexes['reg_option'].search(item_str)
        reg_option = (reg_option.group(1)).replace(
            '"', '') if reg_option else None

        key_item = regexes['key_item'].search(item_str)
        key_item = key_item.group(1) if key_item else None

        if key_item:
            reg_item = key_item.replace('"', '')

        audit_policy_subcategory = regexes['audit_policy_subcategory'].search(
            item_str)
        audit_policy_subcategory = (audit_policy_subcategory.group(
            1)).replace('"', '') if audit_policy_subcategory else None

        right_type = regexes['right_type'].search(item_str)
        right_type = (right_type.group(1)).replace(
            '"', '') if right_type else None

        if type == 'BANNER_CHECK':
            value_data = ''
        elif type == 'ANONYMOUS_SID_SETTING':
            value_data = '0'
        elif type == 'REG_CHECK':
            reg_key = value_data
            value_data = ''
        elif type == 'CHECK_ACCOUNT':
            if index == '2.3.1.4':
                value_data = 'Administrator'
            elif index == '2.3.1.2':
                value_data = 'No'
        elif type == 'PASSWORD_POLICY':
            if value_data == 'Enabled':
                value_data = 1
            elif value_data == 'Disabled':
                value_data = 0
            elif value_data == '@PASSWORD_HISTORY@':
                value_data = 24
            elif value_data == '@MAXIMUM_PASSWORD_AGE@':
                value_data = 365
            elif value_data == '@MINIMUM_PASSWORD_AGE@':
                value_data = 1
            elif value_data == '@MINIMUM_PASSWORD_LENGTH@':
                value_data = 14
        elif type == 'REGISTRY_SETTING':
            if index == '0':
                value_data = 'Windows 10 Enterprise'
            elif index == '2.3.7.9':
                value_data = '1 || 2 || 3'
            elif index == '2.3.10.6':
                value_data = 'Null'
            elif index == '2.3.10.7':
                value_data = value_data.replace(' && ', '')
            elif index == '2.3.10.8':
                value_data = value_data.replace(' && ', '')
            elif index == '2.3.10.11':
                value_data = 'Null'
            elif index == '19.1.3.3':
                value_data = '[0..900]'

        data_dict[type].append([1, type, index, description,
                                reg_key, reg_item, reg_option, audit_policy_subcategory, right_type, value_data])

    # return data


def output_file(data, writer):

    for type, data in data_dict.items():
        df = pd.DataFrame(data, columns=['Checklist', 'Type', 'Index', 'Description',
                                         'Reg Key',  'Reg Item', 'Reg Option', 'Audit Policy Subcategory', 'Right type', 'Value Data'])
        df.to_excel(writer, sheet_name=type, index=False)


if __name__ == '__main__':

    src_fname = 'src/test.audit'
    audit = read_file(src_fname)

    data = find_element(audit)

    out_fname = 'out\source_v4.xlsx'
    writer = pd.ExcelWriter(out_fname, engine='openpyxl')

    output_file(data, writer)
    writer.save()
    print(f"File export success --- {out_fname}")
