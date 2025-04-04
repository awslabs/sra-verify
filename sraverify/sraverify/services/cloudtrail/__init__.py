"""
CloudTrail security checks.
"""
from sraverify.services.cloudtrail.checks.sra_ct_1 import SRA_CT_1
from sraverify.services.cloudtrail.checks.sra_ct_2 import SRA_CT_2
from sraverify.services.cloudtrail.checks.sra_ct_3 import SRA_CT_3
from sraverify.services.cloudtrail.checks.sra_ct_4 import SRA_CT_4
from sraverify.services.cloudtrail.checks.sra_ct_5 import SRA_CT_5
from sraverify.services.cloudtrail.checks.sra_ct_6 import SRA_CT_6
from sraverify.services.cloudtrail.checks.sra_ct_7 import SRA_CT_7
from sraverify.services.cloudtrail.checks.sra_ct_8 import SRA_CT_8
from sraverify.services.cloudtrail.checks.sra_ct_9 import SRA_CT_9
from sraverify.services.cloudtrail.checks.sra_ct_10 import SRA_CT_10
from sraverify.services.cloudtrail.checks.sra_ct_11 import SRA_CT_11
from sraverify.services.cloudtrail.checks.sra_ct_12 import SRA_CT_12
from sraverify.services.cloudtrail.checks.sra_ct_13 import SRA_CT_13

CHECKS = {
    "SRA-CT-1": SRA_CT_1,
    "SRA-CT-2": SRA_CT_2,
    "SRA-CT-3": SRA_CT_3,
    "SRA-CT-4": SRA_CT_4,
    "SRA-CT-5": SRA_CT_5,
    "SRA-CT-6": SRA_CT_6,
    "SRA-CT-7": SRA_CT_7,
    "SRA-CT-8": SRA_CT_8,
    "SRA-CT-9": SRA_CT_9,
    "SRA-CT-10": SRA_CT_10,
    "SRA-CT-11": SRA_CT_11,
    "SRA-CT-12": SRA_CT_12,
    "SRA-CT-13": SRA_CT_13,
}
