"""
Macie security checks.
"""
from sraverify.services.macie.checks.sra_macie_1 import SRA_MACIE_1
from sraverify.services.macie.checks.sra_macie_2 import SRA_MACIE_2
from sraverify.services.macie.checks.sra_macie_3 import SRA_MACIE_3
from sraverify.services.macie.checks.sra_macie_4 import SRA_MACIE_4
from sraverify.services.macie.checks.sra_macie_5 import SRA_MACIE_5
from sraverify.services.macie.checks.sra_macie_6 import SRA_MACIE_6
from sraverify.services.macie.checks.sra_macie_7 import SRA_MACIE_7
from sraverify.services.macie.checks.sra_macie_8 import SRA_MACIE_8
from sraverify.services.macie.checks.sra_macie_9 import SRA_MACIE_9
from sraverify.services.macie.checks.sra_macie_10 import SRA_MACIE_10

CHECKS = {
    "SRA-MACIE-1": SRA_MACIE_1,
    "SRA-MACIE-2": SRA_MACIE_2,
    "SRA-MACIE-3": SRA_MACIE_3,
    "SRA-MACIE-4": SRA_MACIE_4,
    "SRA-MACIE-5": SRA_MACIE_5,
    "SRA-MACIE-6": SRA_MACIE_6,
    "SRA-MACIE-7": SRA_MACIE_7,
    "SRA-MACIE-8": SRA_MACIE_8,
    "SRA-MACIE-9": SRA_MACIE_9,
    "SRA-MACIE-10": SRA_MACIE_10,
}
