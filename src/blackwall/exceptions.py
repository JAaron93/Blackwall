class APIRateLimitException(Exception):
    """Exception raised when the Gemini API rate limit is exceeded."""

    def __init__(self, message: str = "Gemini API rate limit exceeded"):
        super().__init__(message)
