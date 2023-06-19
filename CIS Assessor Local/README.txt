1. Index 18.9.19.5 is hardcoded
2. Use Level 1 is enough
3. PASSWORD_POLICY: 
    1. Manually modify all expexted values
        1. Enabled → 1, Disabled → 0
4. CHECK_ACCOUNT: 
    1. 2.3.1.2: Modify “Disabled” → “No
    2. 2.3.1.4: Modify “Administrator”
5. ANONYMOUS_SID_SETTING: 
    1. 2.3.10.1 Manually modify expexted value: Disabled → 0
6. BANNER_CHECK:
    1. 2.3.7.5 & 2.3.7.6: Manually modify expexted value to “Blank Message”
7. LOCKOUT_POLICY
    1. Manually modify all expexted values
8. REGISTRY_SETTING:
    1. Delete index 0: “Windows 10 is installed”
    2. 2.3.7.9: ^(1|2|3)$ → 1 || 2 || 3
    3. 19.1.3.3: ^(900|[1-9][0-9]|[1-8][0-9]{2})$ → [0..900]
    4. 2.3.10.11: Value Data → Value Not found