from bs4 import BeautifulSoup
import pandas as pd
import re
import argparse

# The regular expressions to extract required data
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


# The dictionary maps different audit categories
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
    "WMI_POLICY": []
}


def read_file(filename: str) -> str:
    '''This function will read the content of the provided file
    '''

    contents = ''
    try:
        with open(filename, 'r') as file_in:
            contents = file_in.read()
    except Exception as e:
        print('ERROR: reading file: {}: {}'.format(filename, e))

    return contents


def find_element(audit: str) -> None:
    '''This function will find the required elements based on the regular expression (regexes),
    and the content (audit). Finally, it will save the results into a dictionary (data_dict)
    '''

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

        # Clean the data
        if type == 'BANNER_CHECK':
            value_data = ''
        elif type == 'ANONYMOUS_SID_SETTING':
            value_data = '0'
        elif type == 'REG_CHECK':
            reg_key = value_data
            value_data = ''
        elif type == 'CHECK_ACCOUNT':
            if 'Rename administrator account' in description:
                value_data = 'Administrator'
            elif 'Disabled' in description:
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
                value_data = 'Windows'
            elif 'Lock Workstation' in description:
                value_data = '1 || 2 || 3'
            elif 'None' in description:
                value_data = 'Null'
            elif ' Remotely accessible registry paths' in description:
                value_data = value_data.replace(' && ', '')
            elif 'Screen saver timeout' in description:
                value_data = '[0..900]'

        data_dict[type].append([1, type, index, description,
                                reg_key, reg_item, reg_option, audit_policy_subcategory, right_type, value_data])


def output_file(out_fname):
    '''This function will save the result into the given path (out_fname)
    '''

    writer = pd.ExcelWriter(out_fname, engine='openpyxl')

    for type, data in data_dict.items():
        df = pd.DataFrame(data, columns=['Checklist', 'Type', 'Index', 'Description',
                                         'Reg Key',  'Reg Item', 'Reg Option', 'Audit Policy Subcategory', 'Right type', 'Value Data'])
        df.to_excel(writer, sheet_name=type, index=False)

    writer.close()


if __name__ == '__main__':

    my_parser = argparse.ArgumentParser(
        description='A Customizable Multiprocessing Remote Security Audit Program')

    # Add the arguments
    my_parser.add_argument('--audit',
                           type=str,
                           required=True,
                           help='The path of audit file')

    # Execute parse_args()
    args = my_parser.parse_args()

    print('Aduit file:', args.audit)

    # src_fname = 'src/CIS/CIS_MS_Windows_11_Enterprise_Level_1_v1.0.0.audit'
    # src_fname = 'src/CIS/CIS_Microsoft_Windows_Server_2019_Benchmark_v2.0.0_L1_DC.audit'
    src_fname = args.audit

    # read .audit file
    audit = read_file(src_fname)

    # extract the required audit data
    data = find_element(audit)

    # save the data into an Excel file
    # out_fname = 'src\win_server_2022_ms_v1.xlsx'
    out_fname = 'src\\Audit\\' + \
        src_fname.split("\\")[-1].replace("audit", "xlsx")

    output_file(out_fname)

    print(f"File export success --- {out_fname}")
