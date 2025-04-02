"""
CloudTrail service checks.
"""
from sraverify.services.cloudtrail.checks.sra_ct_1 import SRA_CT_1

# Export all checks
CHECKS = {
    "SRA-CT-1": SRA_CT_1
}
