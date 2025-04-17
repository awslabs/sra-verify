"""
EC2 security checks.
"""
from sraverify.services.ec2.checks.sra_ec2_1 import SRA_EC2_1

CHECKS = {
    "SRA-EC2-1": SRA_EC2_1,
}
