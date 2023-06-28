import logging

from getRegValue import get_registry_actual_value, compare_reg_value

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.FileHandler('mylog.log', mode='w')
handler.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

# Use the logger to record events
try:
    a = actual_value_list = get_registry_actual_value([], [])
    
    pass
except Exception as e:
    logger.error('Failed to execute script: %s', e)
    logger.debug("This is a debug message")
    logger.info("This is an informational message")
    logging.warning("This is a warning")
    logging.error("This is an error message")
    logging.critical("This is a critical error message")
