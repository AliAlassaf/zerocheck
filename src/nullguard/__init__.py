"""NullGuard: tell a verified negative from a blind spot."""

from .catalog import load_catalog
from .models import Gap, GapReason, Question, Result, Source, Verdict
from .verifier import Verifier

__version__ = "0.1.0"
__all__ = ["Gap", "GapReason", "Question", "Result", "Source", "Verdict", "Verifier", "load_catalog"]
