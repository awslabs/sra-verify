"""SecurityHub service checks."""

from sraverify.services.securityhub.checks.sra_securityhub_01 import SRA_SECURITYHUB_01
from sraverify.services.securityhub.checks.sra_securityhub_02 import SRA_SECURITYHUB_02
from sraverify.services.securityhub.checks.sra_securityhub_03 import SRA_SECURITYHUB_03
from sraverify.services.securityhub.checks.sra_securityhub_04 import SRA_SECURITYHUB_04
from sraverify.services.securityhub.checks.sra_securityhub_05 import SRA_SECURITYHUB_05
from sraverify.services.securityhub.checks.sra_securityhub_06 import SRA_SECURITYHUB_06
from sraverify.services.securityhub.checks.sra_securityhub_07 import SRA_SECURITYHUB_07
from sraverify.services.securityhub.checks.sra_securityhub_08 import SRA_SECURITYHUB_08
from sraverify.services.securityhub.checks.sra_securityhub_09 import SRA_SECURITYHUB_09
from sraverify.services.securityhub.checks.sra_securityhub_10 import SRA_SECURITYHUB_10
from sraverify.services.securityhub.checks.sra_securityhub_11 import SRA_SECURITYHUB_11

CHECKS = {
    "SRA-SECURITYHUB-01": SRA_SECURITYHUB_01,
    "SRA-SECURITYHUB-02": SRA_SECURITYHUB_02,
    "SRA-SECURITYHUB-03": SRA_SECURITYHUB_03,
    "SRA-SECURITYHUB-04": SRA_SECURITYHUB_04,
    "SRA-SECURITYHUB-05": SRA_SECURITYHUB_05,
    "SRA-SECURITYHUB-06": SRA_SECURITYHUB_06,
    "SRA-SECURITYHUB-07": SRA_SECURITYHUB_07,
    "SRA-SECURITYHUB-08": SRA_SECURITYHUB_08,
    "SRA-SECURITYHUB-09": SRA_SECURITYHUB_09,
    "SRA-SECURITYHUB-10": SRA_SECURITYHUB_10,
    "SRA-SECURITYHUB-11": SRA_SECURITYHUB_11,
}
