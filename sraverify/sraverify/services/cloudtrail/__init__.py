"""
Cloudtrail security checks.
"""
from sraverify.services.cloudtrail.checks.sra_cloudtrail_01 import SRA_CLOUDTRAIL_01
from sraverify.services.cloudtrail.checks.sra_cloudtrail_02 import SRA_CLOUDTRAIL_02
from sraverify.services.cloudtrail.checks.sra_cloudtrail_03 import SRA_CLOUDTRAIL_03
from sraverify.services.cloudtrail.checks.sra_cloudtrail_04 import SRA_CLOUDTRAIL_04
from sraverify.services.cloudtrail.checks.sra_cloudtrail_05 import SRA_CLOUDTRAIL_05
from sraverify.services.cloudtrail.checks.sra_cloudtrail_06 import SRA_CLOUDTRAIL_06
from sraverify.services.cloudtrail.checks.sra_cloudtrail_07 import SRA_CLOUDTRAIL_07
from sraverify.services.cloudtrail.checks.sra_cloudtrail_08 import SRA_CLOUDTRAIL_08
from sraverify.services.cloudtrail.checks.sra_cloudtrail_09 import SRA_CLOUDTRAIL_09
from sraverify.services.cloudtrail.checks.sra_cloudtrail_10 import SRA_CLOUDTRAIL_10
from sraverify.services.cloudtrail.checks.sra_cloudtrail_11 import SRA_CLOUDTRAIL_11
from sraverify.services.cloudtrail.checks.sra_cloudtrail_12 import SRA_CLOUDTRAIL_12
from sraverify.services.cloudtrail.checks.sra_cloudtrail_13 import SRA_CLOUDTRAIL_13

# Register checks
CHECKS = {
    "SRA-CLOUDTRAIL-01": SRA_CLOUDTRAIL_01,
    "SRA-CLOUDTRAIL-02": SRA_CLOUDTRAIL_02,
    "SRA-CLOUDTRAIL-03": SRA_CLOUDTRAIL_03,
    "SRA-CLOUDTRAIL-04": SRA_CLOUDTRAIL_04,
    "SRA-CLOUDTRAIL-05": SRA_CLOUDTRAIL_05,
    "SRA-CLOUDTRAIL-06": SRA_CLOUDTRAIL_06,
    "SRA-CLOUDTRAIL-07": SRA_CLOUDTRAIL_07,
    "SRA-CLOUDTRAIL-08": SRA_CLOUDTRAIL_08,
    "SRA-CLOUDTRAIL-09": SRA_CLOUDTRAIL_09,
    "SRA-CLOUDTRAIL-10": SRA_CLOUDTRAIL_10,
    "SRA-CLOUDTRAIL-11": SRA_CLOUDTRAIL_11,
    "SRA-CLOUDTRAIL-12": SRA_CLOUDTRAIL_12,
    "SRA-CLOUDTRAIL-13": SRA_CLOUDTRAIL_13,
}
