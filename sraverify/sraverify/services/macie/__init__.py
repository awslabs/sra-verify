"""
Macie security checks.
"""
from sraverify.services.macie.checks.sra_macie_01 import SRA_MACIE_01
from sraverify.services.macie.checks.sra_macie_02 import SRA_MACIE_02
from sraverify.services.macie.checks.sra_macie_03 import SRA_MACIE_03
from sraverify.services.macie.checks.sra_macie_04 import SRA_MACIE_04
from sraverify.services.macie.checks.sra_macie_05 import SRA_MACIE_05
from sraverify.services.macie.checks.sra_macie_06 import SRA_MACIE_06
from sraverify.services.macie.checks.sra_macie_07 import SRA_MACIE_07
from sraverify.services.macie.checks.sra_macie_08 import SRA_MACIE_08
from sraverify.services.macie.checks.sra_macie_09 import SRA_MACIE_09
from sraverify.services.macie.checks.sra_macie_10 import SRA_MACIE_10

# Register checks
CHECKS = {
    "SRA-MACIE-01": SRA_MACIE_01,
    "SRA-MACIE-02": SRA_MACIE_02,
    "SRA-MACIE-03": SRA_MACIE_03,
    "SRA-MACIE-04": SRA_MACIE_04,
    "SRA-MACIE-05": SRA_MACIE_05,
    "SRA-MACIE-06": SRA_MACIE_06,
    "SRA-MACIE-07": SRA_MACIE_07,
    "SRA-MACIE-08": SRA_MACIE_08,
    "SRA-MACIE-09": SRA_MACIE_09,
    "SRA-MACIE-10": SRA_MACIE_10,
}
