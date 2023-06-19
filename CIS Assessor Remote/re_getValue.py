import re

from bs4 import BeautifulSoup
import pandas as pd
import re

text = r"""
    <custom_item>
      type        : USER_RIGHTS_POLICY
      description : "2.2.1 Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
      info        : "This security setting is used by Credential Manager during Backup and Restore. No accounts should have this user right, as it is only assigned to Winlogon. Users' saved credentials might be compromised if this user right is assigned to other entities.

The recommended state for this setting is: No One.

Rationale:

If an account is given this right the user of the account may create an application that calls into Credential Manager and is returned the credentials for another user.

Impact:

None - this is the default behavior."
      solution    : "To establish the recommended configuration via GP, set the following UI path to No One:

Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller

Default Value:

No one."
      reference   : "800-171|3.1.1,800-171|3.1.5,800-171|3.3.8,800-171|3.3.9,800-53|AC-2,800-53|AC-3,800-53|AC-6,800-53|AC-6(1),800-53|AC-6(7),800-53|AU-9(4),800-53r5|AC-2,800-53r5|AC-3,800-53r5|AC-6,800-53r5|AC-6(1),800-53r5|AC-6(7),800-53r5|AU-9(4),CN-L3|7.1.3.2(b),CN-L3|7.1.3.2(d),CN-L3|7.1.3.2(g),CN-L3|8.1.4.2(d),CN-L3|8.1.4.2(f),CN-L3|8.1.4.3(d),CN-L3|8.1.4.11(b),CN-L3|8.1.10.2(c),CN-L3|8.1.10.6(a),CN-L3|8.5.3.1,CN-L3|8.5.4.1(a),CSCv7|4.8,CSCv8|6.8,CSF|DE.CM-1,CSF|DE.CM-3,CSF|PR.AC-1,CSF|PR.AC-4,CSF|PR.DS-5,CSF|PR.PT-1,CSF|PR.PT-3,GDPR|32.1.b,HIPAA|164.306(a)(1),HIPAA|164.312(a)(1),HIPAA|164.312(b),ISO/IEC-27001|A.9.2.1,ISO/IEC-27001|A.9.2.5,ISO/IEC-27001|A.9.4.1,ISO/IEC-27001|A.9.4.4,ISO/IEC-27001|A.9.4.5,ISO/IEC-27001|A.12.4.2,ITSG-33|AC-2,ITSG-33|AC-3,ITSG-33|AC-6,ITSG-33|AC-6(1),ITSG-33|AU-9(4),ITSG-33|AU-9(4)(a),ITSG-33|AU-9(4)(b),LEVEL|1A,NESA|M1.1.3,NESA|M1.2.2,NESA|M5.2.3,NESA|M5.5.2,NESA|T4.2.1,NESA|T5.1.1,NESA|T5.2.2,NESA|T5.4.1,NESA|T5.4.4,NESA|T5.4.5,NESA|T5.5.4,NESA|T5.6.1,NESA|T7.5.2,NESA|T7.5.3,NIAv2|AM1,NIAv2|AM3,NIAv2|AM23f,NIAv2|AM28,NIAv2|AM31,NIAv2|GS3,NIAv2|GS4,NIAv2|GS8c,NIAv2|NS5j,NIAv2|SM5,NIAv2|SM6,NIAv2|SS13c,NIAv2|SS14e,NIAv2|SS15c,NIAv2|SS29,NIAv2|VL3b,PCI-DSSv3.2.1|7.1.2,PCI-DSSv3.2.1|10.5,PCI-DSSv3.2.1|10.5.2,PCI-DSSv4.0|7.2.1,PCI-DSSv4.0|7.2.2,PCI-DSSv4.0|10.3.2,QCSC-v1|3.2,QCSC-v1|5.2.2,QCSC-v1|6.2,QCSC-v1|8.2.1,QCSC-v1|13.2,QCSC-v1|15.2,SWIFT-CSCv1|5.1,TBA-FIISB|31.1,TBA-FIISB|31.4.2,TBA-FIISB|31.4.3"
      see_also    : "https://workbench.cisecurity.org/benchmarks/12412"
      value_type  : USER_RIGHT
      value_data  : ""
      right_type  : SeTrustedCredManAccessPrivilege

"""

def read_file(filename):
    contents = ''
    try:
        # display('Reading {}'.format(filename), verbose=True)
        with open(filename, 'r') as file_in:
            contents = file_in.read()
    except Exception as e:
        print('ERROR: reading file: {}: {}'.format(filename, e))

    return contents

text = read_file("src/test_right.audit")



data = []

soup = BeautifulSoup(text, 'lxml')

# Find all the custom_item elements
items = soup.find_all('custom_item')

# Extract the required data from each custom_item
for item in items:
    # item_str = str(item).replace('"', '')
    item_str = str(item)


    pattern = re.compile(r'value_data\s+:\s+(.*?)\n')
    
    value_data = pattern.search(item_str)
    value_data = value_data.group(1) if value_data else None
    print(value_data)





# pattern = re.compile(r'value_data\s+:\s+(.*?)\n')

# value_data = pattern.findall(text)
print(value_data)
# value_data = value_data.group(1) if value_data else None

# print(value_data)
