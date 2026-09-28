
def install_enhancements():
    from .enhanced.detector import detect_format_enhanced
    from .core import pipeline
    from .core import detector as detector_module
    pipeline.detect_format = detect_format_enhanced
    detector_module.detect_format = detect_format_enhanced
