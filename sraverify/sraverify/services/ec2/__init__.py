"""
EC2 security checks.
"""
from sraverify.services.ec2.checks.sra_ec2_01 import SRA_EC2_01

CHECKS = {
    "SRA-EC2-01": SRA_EC2_01,
}
