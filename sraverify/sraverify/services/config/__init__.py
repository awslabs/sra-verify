"""
AWS Config security checks.
"""
from sraverify.services.config.checks.sra_config_01 import SRA_CONFIG_01
from sraverify.services.config.checks.sra_config_02 import SRA_CONFIG_02
from sraverify.services.config.checks.sra_config_03 import SRA_CONFIG_03
from sraverify.services.config.checks.sra_config_04 import SRA_CONFIG_04
from sraverify.services.config.checks.sra_config_05 import SRA_CONFIG_05
from sraverify.services.config.checks.sra_config_06 import SRA_CONFIG_06
from sraverify.services.config.checks.sra_config_07 import SRA_CONFIG_07
from sraverify.services.config.checks.sra_config_08 import SRA_CONFIG_08
from sraverify.services.config.checks.sra_config_09 import SRA_CONFIG_09
from sraverify.services.config.checks.sra_config_10 import SRA_CONFIG_10
from sraverify.services.config.checks.sra_config_11 import SRA_CONFIG_11

# Register checks
CHECKS = {
    "SRA-CONFIG-01": SRA_CONFIG_01,
    "SRA-CONFIG-02": SRA_CONFIG_02,
    "SRA-CONFIG-03": SRA_CONFIG_03,
    "SRA-CONFIG-04": SRA_CONFIG_04,
    "SRA-CONFIG-05": SRA_CONFIG_05,
    "SRA-CONFIG-06": SRA_CONFIG_06,
    # "SRA-CONFIG-07": SRA_CONFIG_07,
    # "SRA-CONFIG-08": SRA_CONFIG_08,
    "SRA-CONFIG-09": SRA_CONFIG_09,
    "SRA-CONFIG-10": SRA_CONFIG_10,
    "SRA-CONFIG-11": SRA_CONFIG_11,
}
