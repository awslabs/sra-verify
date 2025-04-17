"""
Inspector security checks.
"""
from sraverify.services.inspector.checks.sra_inspector_01 import SRA_INSPECTOR_01
from sraverify.services.inspector.checks.sra_inspector_02 import SRA_INSPECTOR_02
from sraverify.services.inspector.checks.sra_inspector_03 import SRA_INSPECTOR_03
from sraverify.services.inspector.checks.sra_inspector_04 import SRA_INSPECTOR_04
from sraverify.services.inspector.checks.sra_inspector_05 import SRA_INSPECTOR_05
from sraverify.services.inspector.checks.sra_inspector_06 import SRA_INSPECTOR_06
from sraverify.services.inspector.checks.sra_inspector_07 import SRA_INSPECTOR_07
from sraverify.services.inspector.checks.sra_inspector_08 import SRA_INSPECTOR_08
from sraverify.services.inspector.checks.sra_inspector_09 import SRA_INSPECTOR_09
from sraverify.services.inspector.checks.sra_inspector_10 import SRA_INSPECTOR_10
from sraverify.services.inspector.checks.sra_inspector_11 import SRA_INSPECTOR_11

# Register checks
CHECKS = {
    "SRA-INSPECTOR-01": SRA_INSPECTOR_01,
    "SRA-INSPECTOR-02": SRA_INSPECTOR_02,
    "SRA-INSPECTOR-03": SRA_INSPECTOR_03,
    "SRA-INSPECTOR-04": SRA_INSPECTOR_04,
    "SRA-INSPECTOR-05": SRA_INSPECTOR_05,
    "SRA-INSPECTOR-06": SRA_INSPECTOR_06,
    "SRA-INSPECTOR-07": SRA_INSPECTOR_07,
    "SRA-INSPECTOR-08": SRA_INSPECTOR_08,
    "SRA-INSPECTOR-09": SRA_INSPECTOR_09,
    "SRA-INSPECTOR-10": SRA_INSPECTOR_10,
    "SRA-INSPECTOR-11": SRA_INSPECTOR_11,
}
