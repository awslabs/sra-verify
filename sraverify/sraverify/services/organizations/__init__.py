"""
AWS Organizations security checks.
"""
from sraverify.services.organizations.checks.sra_organizations_01 import SRA_ORGANIZATIONS_01
from sraverify.services.organizations.checks.sra_organizations_02 import SRA_ORGANIZATIONS_02
from sraverify.services.organizations.checks.sra_organizations_03 import SRA_ORGANIZATIONS_03
from sraverify.services.organizations.checks.sra_organizations_04 import SRA_ORGANIZATIONS_04
from sraverify.services.organizations.checks.sra_organizations_05 import SRA_ORGANIZATIONS_05
from sraverify.services.organizations.checks.sra_organizations_06 import SRA_ORGANIZATIONS_06
from sraverify.services.organizations.checks.sra_organizations_07 import SRA_ORGANIZATIONS_07
from sraverify.services.organizations.checks.sra_organizations_08 import SRA_ORGANIZATIONS_08
from sraverify.services.organizations.checks.sra_organizations_09 import SRA_ORGANIZATIONS_09

# Map check IDs to check classes for easy lookup
CHECKS = {
    "SRA-ORGANIZATIONS-01": SRA_ORGANIZATIONS_01,
    "SRA-ORGANIZATIONS-02": SRA_ORGANIZATIONS_02,
    "SRA-ORGANIZATIONS-03": SRA_ORGANIZATIONS_03,
    "SRA-ORGANIZATIONS-04": SRA_ORGANIZATIONS_04,
    "SRA-ORGANIZATIONS-05": SRA_ORGANIZATIONS_05,
    "SRA-ORGANIZATIONS-06": SRA_ORGANIZATIONS_06,
    "SRA-ORGANIZATIONS-07": SRA_ORGANIZATIONS_07,
    "SRA-ORGANIZATIONS-08": SRA_ORGANIZATIONS_08,
    "SRA-ORGANIZATIONS-09": SRA_ORGANIZATIONS_09,
}
