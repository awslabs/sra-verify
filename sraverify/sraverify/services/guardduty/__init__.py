"""
GuardDuty security checks.
"""
from sraverify.services.guardduty.checks.sra_gd_1 import SRA_GD_1
from sraverify.services.guardduty.checks.sra_gd_2 import SRA_GD_2
from sraverify.services.guardduty.checks.sra_gd_3 import SRA_GD_3
from sraverify.services.guardduty.checks.sra_gd_4 import SRA_GD_4
from sraverify.services.guardduty.checks.sra_gd_5 import SRA_GD_5
from sraverify.services.guardduty.checks.sra_gd_6 import SRA_GD_6
from sraverify.services.guardduty.checks.sra_gd_7 import SRA_GD_7
from sraverify.services.guardduty.checks.sra_gd_9 import SRA_GD_9
from sraverify.services.guardduty.checks.sra_gd_14 import SRA_GD_14
from sraverify.services.guardduty.checks.sra_gd_15 import SRA_GD_15
from sraverify.services.guardduty.checks.sra_gd_16 import SRA_GD_16
from sraverify.services.guardduty.checks.sra_gd_17 import SRA_GD_17
from sraverify.services.guardduty.checks.sra_gd_19 import SRA_GD_19
from sraverify.services.guardduty.checks.sra_gd_27 import SRA_GD_27
from sraverify.services.guardduty.checks.sra_gd_28 import SRA_GD_28
from sraverify.services.guardduty.checks.sra_gd_29 import SRA_GD_29

# Map check IDs to check classes for easy lookup
CHECKS = {
    "SRA-GD-1": SRA_GD_1,
    "SRA-GD-2": SRA_GD_2,
    "SRA-GD-3": SRA_GD_3,
    "SRA-GD-4": SRA_GD_4,
    "SRA-GD-5": SRA_GD_5,
    "SRA-GD-6": SRA_GD_6,
    "SRA-GD-7": SRA_GD_7,
    "SRA-GD-9": SRA_GD_9,
    "SRA-GD-14": SRA_GD_14,
    "SRA-GD-15": SRA_GD_15,
    "SRA-GD-16": SRA_GD_16,
    "SRA-GD-17": SRA_GD_17,
    "SRA-GD-19": SRA_GD_19,
    "SRA-GD-27": SRA_GD_27,
    "SRA-GD-28": SRA_GD_28,
    "SRA-GD-29": SRA_GD_29
    # Add more checks here as they are implemented
}
