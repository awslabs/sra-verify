"""
S3 security checks.
"""
from sraverify.services.s3.checks.sra_s3_02 import SRA_S3_02
from sraverify.services.s3.checks.sra_s3_03 import SRA_S3_03
from sraverify.services.s3.checks.sra_s3_04 import SRA_S3_04
from sraverify.services.s3.checks.sra_s3_05 import SRA_S3_05

# Register checks
CHECKS = {
    "SRA-S3-02": SRA_S3_02,
    "SRA-S3-03": SRA_S3_03,
    "SRA-S3-04": SRA_S3_04,
    "SRA-S3-05": SRA_S3_05,
}
