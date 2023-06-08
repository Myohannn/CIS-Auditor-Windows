import re

text = """
<custom_item>
      type        : REGISTRY_SETTING
      description : "2.3.6.1 Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
      info        : "This policy setting determines whether a domain member should attempt to negotiate encryption for all secure channel traffic that it initiates.
      value_type  : POLICY_DWORD
      value_data  : 1
      reg_key     : "HKLM\\System\\Currentcontrolset\\Services\\Netlogon\\Parameters"
      reg_item    : "sealsecurechannel"
      reg_option  : CAN_NOT_BE_NULL
    </custom_item>
<custom_item>
      type        : REGISTRY_SETTING
      description : "2.3.6.3 Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
      info        : "This policy setting determines whether a domain member should attempt to negotiate encryption for all secure channel traffic that it initiates.
      value_type  : POLICY_DWORD
      value_data  : 1
      reg_key     : "HKLM\\System\\Currentcontrolset\\Services\\Netlogon\\Parameters"
      reg_item    : "sealsecurechannel"
      reg_option  : CAN_NOT_BE_NULL
    </custom_item>
"""

pattern = r'(value_data\s*:\s*)\d+'

# Pattern to match the existing value_data line for 2.3.6.3
pattern = r'(description : "2.3.6.3 [^<]+value_data\s*:\s*)\d+'

# Replacement line with the new value
replacement = r'\1 2'

# Use re.sub to replace the pattern
modified_text = re.sub(pattern, replacement, text, flags=re.DOTALL)

print(modified_text)
