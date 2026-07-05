import pytest
from blackwall.logging import setup_logging

def test_setup_logging_pipeline(capsys, log_output, caplog):
    import structlog
    import logging
    import json
    import sys

    original_config = structlog.get_config()
    
    # Capture standard logger output by explicitly adding a StreamHandler to the root logger
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers[:]
    original_level = root_logger.level
    
    root_logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    root_logger.handlers = [handler]

    try:
        # Setup logging to apply the production-like structlog pipeline
        setup_logging()

        # Emit log
        logger = structlog.get_logger("test_logger")
        logger.info("test message", key="value")

        # Capture output
        captured = capsys.readouterr()
        
        # Find the line that is valid JSON with the expected message
        json_line = None
        for line in caplog.text.strip().split("\n"):
            try:
                data = json.loads(line)
                if data.get("event") == "test message":
                    json_line = data
                    break
            except json.JSONDecodeError:
                continue

        if json_line is None:
            for line in captured.out.strip().split("\n"):
                try:
                    data = json.loads(line)
                    if data.get("event") == "test message":
                        json_line = data
                        break
                except json.JSONDecodeError:
                    continue

        assert json_line is not None, f"Expected JSON log not found. caplog: {caplog.text}, stdout: {captured.out}"
        assert json_line["event"] == "test message"
        assert json_line["key"] == "value"
        assert "timestamp" in json_line
        assert json_line["level"] == "info"
        assert json_line["logger"] == "test_logger"

    finally:
        # Restore root logger handlers and level
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)

        # Restore original test configuration so subsequent tests don't break
        structlog.configure(
            processors=original_config.get("processors"),
            wrapper_class=original_config.get("wrapper_class"),
            context_class=original_config.get("context_class"),
            logger_factory=original_config.get("logger_factory"),
            cache_logger_on_first_use=original_config.get("cache_logger_on_first_use"),
        )
