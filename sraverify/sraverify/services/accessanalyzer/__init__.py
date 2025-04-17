"""
Accessanalyzer security checks.
"""
from sraverify.services.accessanalyzer.checks.sra_accessanalyzer_01 import SRA_ACCESSANALYZER_01
from sraverify.services.accessanalyzer.checks.sra_accessanalyzer_02 import SRA_ACCESSANALYZER_02
from sraverify.services.accessanalyzer.checks.sra_accessanalyzer_03 import SRA_ACCESSANALYZER_03
from sraverify.services.accessanalyzer.checks.sra_accessanalyzer_04 import SRA_ACCESSANALYZER_04

# Register checks
CHECKS = {
    "SRA-ACCESSANALYZER-01": SRA_ACCESSANALYZER_01,
    "SRA-ACCESSANALYZER-02": SRA_ACCESSANALYZER_02,
    "SRA-ACCESSANALYZER-03": SRA_ACCESSANALYZER_03,
    "SRA-ACCESSANALYZER-04": SRA_ACCESSANALYZER_04,
}
