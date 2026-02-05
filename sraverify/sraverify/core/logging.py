"""
Logging configuration for SRA Verify.
"""
import logging
import sys

# Create a logger
logger = logging.getLogger("sraverify")

# Create handlers
console_handler = logging.StreamHandler(sys.stderr)

# Create formatters
default_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
console_formatter = logging.Formatter(default_format)

# Add formatters to handlers
console_handler.setFormatter(console_formatter)

# Add handlers to logger
logger.addHandler(console_handler)

# Set default level
logger.setLevel(logging.INFO)

def configure_logging(debug=False):
    """
    Configure logging level based on debug flag.
    
    Args:
        debug: If True, set logging level to DEBUG, otherwise INFO
    """
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    else:
        logger.setLevel(logging.INFO)
