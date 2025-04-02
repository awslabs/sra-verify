"""
GuardDuty security checks.
"""
from sraverify.services.guardduty.checks.sra_gd_1 import SRA_GD_1
from sraverify.services.guardduty.checks.sra_gd_2 import SRA_GD_2
from sraverify.services.guardduty.checks.sra_gd_3 import SRA_GD_3

# Map check IDs to check classes for easy lookup
CHECKS = {
    "SRA-GD-1": SRA_GD_1,
    "SRA-GD-2": SRA_GD_2,
    "SRA-GD-3": SRA_GD_3
    # Add more checks here as they are implemented
}
