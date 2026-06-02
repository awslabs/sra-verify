"""
IAM Attack Path security checks.

Detects privilege escalation paths through IAM principal relationships
using in-memory privilege graph analysis.
"""
from sraverify.services.iam_attack_paths.checks.sra_iap_1 import SRA_IAP_1
from sraverify.services.iam_attack_paths.checks.sra_iap_2 import SRA_IAP_2
from sraverify.services.iam_attack_paths.checks.sra_iap_3 import SRA_IAP_3
from sraverify.services.iam_attack_paths.checks.sra_iap_4 import SRA_IAP_4
from sraverify.services.iam_attack_paths.checks.sra_iap_5 import SRA_IAP_5
from sraverify.services.iam_attack_paths.checks.sra_iap_6 import SRA_IAP_6
from sraverify.services.iam_attack_paths.checks.sra_iap_7 import SRA_IAP_7
from sraverify.services.iam_attack_paths.checks.sra_iap_8 import SRA_IAP_8

# Map check IDs to check classes for easy lookup
CHECKS = {
    "SRA-IAP-1": SRA_IAP_1,
    "SRA-IAP-2": SRA_IAP_2,
    "SRA-IAP-3": SRA_IAP_3,
    "SRA-IAP-4": SRA_IAP_4,
    "SRA-IAP-5": SRA_IAP_5,
    "SRA-IAP-6": SRA_IAP_6,
    "SRA-IAP-7": SRA_IAP_7,
    "SRA-IAP-8": SRA_IAP_8,
}
