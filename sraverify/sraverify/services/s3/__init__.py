"""
S3 security checks.
"""
from sraverify.services.s3.checks.sra_s3_2 import SRA_S3_2
from sraverify.services.s3.checks.sra_s3_3 import SRA_S3_3
from sraverify.services.s3.checks.sra_s3_4 import SRA_S3_4
from sraverify.services.s3.checks.sra_s3_5 import SRA_S3_5

# Map check IDs to check classes for easy lookup
CHECKS = {
    "SRA-S3-2": SRA_S3_2,
    "SRA-S3-3": SRA_S3_3,
    "SRA-S3-4": SRA_S3_4,
    "SRA-S3-5": SRA_S3_5
    # Add more checks here as they are implemented
}
