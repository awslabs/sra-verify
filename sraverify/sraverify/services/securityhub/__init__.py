"""SecurityHub service checks."""

from sraverify.services.securityhub.checks.sra_sh_1 import SRA_SH_1
from sraverify.services.securityhub.checks.sra_sh_2 import SRA_SH_2
from sraverify.services.securityhub.checks.sra_sh_3 import SRA_SH_3
from sraverify.services.securityhub.checks.sra_sh_4 import SRA_SH_4
from sraverify.services.securityhub.checks.sra_sh_5 import SRA_SH_5
from sraverify.services.securityhub.checks.sra_sh_6 import SRA_SH_6
from sraverify.services.securityhub.checks.sra_sh_7 import SRA_SH_7
from sraverify.services.securityhub.checks.sra_sh_8 import SRA_SH_8
from sraverify.services.securityhub.checks.sra_sh_9 import SRA_SH_9
from sraverify.services.securityhub.checks.sra_sh_10 import SRA_SH_10
from sraverify.services.securityhub.checks.sra_sh_11 import SRA_SH_11

CHECKS = {
    "SRA-SH-1": SRA_SH_1,
    "SRA-SH-2": SRA_SH_2,
    "SRA-SH-3": SRA_SH_3,
    "SRA-SH-4": SRA_SH_4,
    "SRA-SH-5": SRA_SH_5,
    "SRA-SH-6": SRA_SH_6,
    "SRA-SH-7": SRA_SH_7,
    "SRA-SH-8": SRA_SH_8,
    "SRA-SH-9": SRA_SH_9,
    "SRA-SH-10": SRA_SH_10,
    "SRA-SH-11": SRA_SH_11,
}
