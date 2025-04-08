"""
AWS Config security checks.
"""
from sraverify.services.config.checks.sra_config_1 import SRA_CONFIG_1
from sraverify.services.config.checks.sra_config_2 import SRA_CONFIG_2
from sraverify.services.config.checks.sra_config_3 import SRA_CONFIG_3
from sraverify.services.config.checks.sra_config_4 import SRA_CONFIG_4
from sraverify.services.config.checks.sra_config_5 import SRA_CONFIG_5
from sraverify.services.config.checks.sra_config_6 import SRA_CONFIG_6
#from sraverify.services.config.checks.sra_config_7 import SRA_CONFIG_7 # duplicate of CONFIG_3
#from sraverify.services.config.checks.sra_config_8 import SRA_CONFIG_8 # not looking for variables Config Rules
from sraverify.services.config.checks.sra_config_9 import SRA_CONFIG_9
from sraverify.services.config.checks.sra_config_10 import SRA_CONFIG_10
from sraverify.services.config.checks.sra_config_11 import SRA_CONFIG_11

# Register checks
CHECKS = {
    "SRA-CONFIG-1": SRA_CONFIG_1,
    "SRA-CONFIG-2": SRA_CONFIG_2,
    "SRA-CONFIG-3": SRA_CONFIG_3,
    "SRA-CONFIG-4": SRA_CONFIG_4,
    "SRA-CONFIG-5": SRA_CONFIG_5,
    "SRA-CONFIG-6": SRA_CONFIG_6,
    # "SRA-CONFIG-7": SRA_CONFIG_7,
    # "SRA-CONFIG-8": SRA_CONFIG_8,
    "SRA-CONFIG-9": SRA_CONFIG_9,
    "SRA-CONFIG-10": SRA_CONFIG_10,
    "SRA-CONFIG-11": SRA_CONFIG_11,
}
