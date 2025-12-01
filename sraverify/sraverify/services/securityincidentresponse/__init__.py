from sraverify.services.securityincidentresponse.checks.sra_securityincidentresponse_01 import SRA_SECURITYINCIDENTRESPONSE_01
from sraverify.services.securityincidentresponse.checks.sra_securityincidentresponse_02 import SRA_SECURITYINCIDENTRESPONSE_02
from sraverify.services.securityincidentresponse.checks.sra_securityincidentresponse_03 import SRA_SECURITYINCIDENTRESPONSE_03
from sraverify.services.securityincidentresponse.checks.sra_securityincidentresponse_04 import SRA_SECURITYINCIDENTRESPONSE_04
from sraverify.services.securityincidentresponse.checks.sra_securityincidentresponse_05 import SRA_SECURITYINCIDENTRESPONSE_05

CHECKS = {
    "SRA-SECURITYINCIDENTRESPONSE-01": SRA_SECURITYINCIDENTRESPONSE_01,
    "SRA-SECURITYINCIDENTRESPONSE-02": SRA_SECURITYINCIDENTRESPONSE_02,
    "SRA-SECURITYINCIDENTRESPONSE-03": SRA_SECURITYINCIDENTRESPONSE_03,
    "SRA-SECURITYINCIDENTRESPONSE-04": SRA_SECURITYINCIDENTRESPONSE_04,
    "SRA-SECURITYINCIDENTRESPONSE-05": SRA_SECURITYINCIDENTRESPONSE_05,
}
