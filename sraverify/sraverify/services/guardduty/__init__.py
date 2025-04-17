"""
GuardDuty security checks.
"""
from sraverify.services.guardduty.checks.sra_guardduty_01 import SRA_GUARDDUTY_01
from sraverify.services.guardduty.checks.sra_guardduty_02 import SRA_GUARDDUTY_02
from sraverify.services.guardduty.checks.sra_guardduty_03 import SRA_GUARDDUTY_03
from sraverify.services.guardduty.checks.sra_guardduty_04 import SRA_GUARDDUTY_04
from sraverify.services.guardduty.checks.sra_guardduty_05 import SRA_GUARDDUTY_05
from sraverify.services.guardduty.checks.sra_guardduty_06 import SRA_GUARDDUTY_06
from sraverify.services.guardduty.checks.sra_guardduty_07 import SRA_GUARDDUTY_07
from sraverify.services.guardduty.checks.sra_guardduty_08 import SRA_GUARDDUTY_08
from sraverify.services.guardduty.checks.sra_guardduty_09 import SRA_GUARDDUTY_09
from sraverify.services.guardduty.checks.sra_guardduty_10 import SRA_GUARDDUTY_10
from sraverify.services.guardduty.checks.sra_guardduty_11 import SRA_GUARDDUTY_11
from sraverify.services.guardduty.checks.sra_guardduty_12 import SRA_GUARDDUTY_12
from sraverify.services.guardduty.checks.sra_guardduty_13 import SRA_GUARDDUTY_13
from sraverify.services.guardduty.checks.sra_guardduty_14 import SRA_GUARDDUTY_14
from sraverify.services.guardduty.checks.sra_guardduty_15 import SRA_GUARDDUTY_15
from sraverify.services.guardduty.checks.sra_guardduty_16 import SRA_GUARDDUTY_16
from sraverify.services.guardduty.checks.sra_guardduty_17 import SRA_GUARDDUTY_17
from sraverify.services.guardduty.checks.sra_guardduty_18 import SRA_GUARDDUTY_18
from sraverify.services.guardduty.checks.sra_guardduty_19 import SRA_GUARDDUTY_19
from sraverify.services.guardduty.checks.sra_guardduty_20 import SRA_GUARDDUTY_20
from sraverify.services.guardduty.checks.sra_guardduty_21 import SRA_GUARDDUTY_21
from sraverify.services.guardduty.checks.sra_guardduty_22 import SRA_GUARDDUTY_22
from sraverify.services.guardduty.checks.sra_guardduty_23 import SRA_GUARDDUTY_23
from sraverify.services.guardduty.checks.sra_guardduty_24 import SRA_GUARDDUTY_24
from sraverify.services.guardduty.checks.sra_guardduty_25 import SRA_GUARDDUTY_25

# Map check IDs to check classes for easy lookup
CHECKS = {
    "SRA-GUARDDUTY-01": SRA_GUARDDUTY_01,
    "SRA-GUARDDUTY-02": SRA_GUARDDUTY_02,
    "SRA-GUARDDUTY-03": SRA_GUARDDUTY_03,
    "SRA-GUARDDUTY-04": SRA_GUARDDUTY_04,
    "SRA-GUARDDUTY-05": SRA_GUARDDUTY_05,
    "SRA-GUARDDUTY-06": SRA_GUARDDUTY_06,
    "SRA-GUARDDUTY-07": SRA_GUARDDUTY_07,
    "SRA-GUARDDUTY-08": SRA_GUARDDUTY_08,
    "SRA-GUARDDUTY-09": SRA_GUARDDUTY_09,
    "SRA-GUARDDUTY-10": SRA_GUARDDUTY_10,
    "SRA-GUARDDUTY-11": SRA_GUARDDUTY_11,
    "SRA-GUARDDUTY-12": SRA_GUARDDUTY_12,
    "SRA-GUARDDUTY-13": SRA_GUARDDUTY_13,
    "SRA-GUARDDUTY-14": SRA_GUARDDUTY_14,
    "SRA-GUARDDUTY-15": SRA_GUARDDUTY_15,
    "SRA-GUARDDUTY-16": SRA_GUARDDUTY_16,
    "SRA-GUARDDUTY-17": SRA_GUARDDUTY_17,
    "SRA-GUARDDUTY-18": SRA_GUARDDUTY_18,
    "SRA-GUARDDUTY-19": SRA_GUARDDUTY_19,
    "SRA-GUARDDUTY-20": SRA_GUARDDUTY_20,
    "SRA-GUARDDUTY-21": SRA_GUARDDUTY_21,
    "SRA-GUARDDUTY-22": SRA_GUARDDUTY_22,
    "SRA-GUARDDUTY-23": SRA_GUARDDUTY_23,
    "SRA-GUARDDUTY-24": SRA_GUARDDUTY_24,
    "SRA-GUARDDUTY-25": SRA_GUARDDUTY_25
    # Add more checks here as they are implemented
}
