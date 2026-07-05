import os
import tempfile
import gzip
from blackwall.telemetry import setup_telemetry, get_tracer, get_metric
from blackwall.logging import setup_logging
from opentelemetry import trace
import logging

def test_telemetry_initialization():
    # Calling setup_telemetry multiple times should not crash and should return True
    success = setup_telemetry()
    assert success is True

    # Verify idempotent behavior - second call should also return True
    success2 = setup_telemetry()
    assert success2 is True

def test_get_tracer_and_metric():
    setup_telemetry()
    tracer = get_tracer("test_tracer")
    assert isinstance(tracer, trace.Tracer)
    
    metric = get_metric("interceptions_total")
    assert metric is not None
    
    # Check that a span can be created
    with tracer.start_as_current_span("test_span") as span:
        span.set_attribute("test_attr", "value")
        assert span.is_recording()

def test_logging_rotation_and_compression():
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # Setup logging to temporary directory
            setup_logging(log_level=logging.DEBUG, log_dir=tmpdir)

            import structlog
            log = structlog.get_logger("blackwall")
            log.info("Test message")

            log_file = os.path.join(tmpdir, "blackwall.log")
            assert os.path.exists(log_file)

            # Verify content
            with open(log_file, "r") as f:
                content = f.read()
                assert "Test message" in content

            # Rotate manually by calling the rotator directly with a dummy file
            dummy_source = os.path.join(tmpdir, "dummy.log")
            dummy_dest = os.path.join(tmpdir, "dummy.log.gz")

            with open(dummy_source, "w") as f:
                f.write("Rotated content")

            from blackwall.logging import _gzip_rotator
            _gzip_rotator(dummy_source, dummy_dest)

            assert os.path.exists(dummy_dest)
            assert not os.path.exists(dummy_source)

            with gzip.open(dummy_dest, "rt") as f:
                gz_content = f.read()
                assert "Rotated content" in gz_content
        finally:
            # Close and remove handlers to prevent resource leaks
            blackwall_logger = logging.getLogger("blackwall")
            for handler in blackwall_logger.handlers[:]:
                handler.close()
                blackwall_logger.removeHandler(handler)
