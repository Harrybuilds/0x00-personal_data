!#/usr/bin/env python3
import re
import logging


PII_FIELDS = ("email", "password", "ssn", "phone_number", "date_of_birth")

def filter_datum(fields, redaction, message, separator):
    """
    Function that obfuscates specific fields in a log message.
    
    Args:
    fields (list): List of field names to obfuscate.
    redaction (str): The string used to obfuscate the field values.
    message (str): The log message to process.
    separator (str): The separator used in the message to separate fields.
    
    Returns:
    str: The log message with the specified fields obfuscated.
    """
    return re.sub(r'(' + '|'.join([f'{fields}=[^;]+']) + r')', lambda m: m.group(0).replace(m.group(0).split('=')[1], redaction), message)

def get_logger() -> logging.Logger:
    """ 
    Returns a logger with RedactingFormatter to redact sensitive data in log messages.
    """
    # Create a logger named "user_data"
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Do not propagate messages to other loggers

    # Create a StreamHandler and set the formatter to RedactingFormatter
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    # Add the StreamHandler to the logger
    logger.addHandler(stream_handler)

    return logger

class RedactingFormatter(logging.Formatter):
    """ 
    Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
    """
    Format the log message, redacting specified fields.
    """
    message = super(RedactingFormatter, self).format(record)
    return filter_datum(self.fields, self.REDACTION, message, self.SEPARATOR)

