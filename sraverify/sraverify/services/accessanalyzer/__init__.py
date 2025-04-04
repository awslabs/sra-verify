"""
IAM Access Analyzer service checks.
"""
from sraverify.services.accessanalyzer.checks.sra_iaa_1 import SRA_IAA_1
from sraverify.services.accessanalyzer.checks.sra_iaa_2 import SRA_IAA_2
from sraverify.services.accessanalyzer.checks.sra_iaa_3 import SRA_IAA_3
from sraverify.services.accessanalyzer.checks.sra_iaa_4 import SRA_IAA_4

# Map check IDs to check classes for easy lookup
CHECKS = {
    "SRA-IAA-1": SRA_IAA_1,
    "SRA-IAA-2": SRA_IAA_2,
    "SRA-IAA-3": SRA_IAA_3,
    "SRA-IAA-4": SRA_IAA_4
}
