"""
Audit Manager security checks.
"""
from sraverify.services.auditmanager.checks.sra_auditmanager_01 import SRA_AUDITMANAGER_01
from sraverify.services.auditmanager.checks.sra_auditmanager_02 import SRA_AUDITMANAGER_02

CHECKS = {
    "SRA-AUDITMANAGER-01": SRA_AUDITMANAGER_01,
    "SRA-AUDITMANAGER-02": SRA_AUDITMANAGER_02,
}
