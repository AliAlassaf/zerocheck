from datetime import datetime, timedelta, timezone

from nullguard import intervals as iv

T = lambda h: datetime(2026, 1, 1, h, tzinfo=timezone.utc)  # noqa: E731


def test_union_merges_overlaps_and_touching():
    assert iv.union([(T(3), T(5)), (T(1), T(2)), (T(2), T(4))]) == [(T(1), T(5))]


def test_subtract():
    assert iv.subtract((T(0), T(10)), [(T(2), T(3)), (T(5), T(12))]) == [(T(0), T(2)), (T(3), T(5))]
    assert iv.subtract((T(0), T(10)), []) == [(T(0), T(10))]
    assert iv.subtract((T(0), T(10)), [(T(0), T(10))]) == []


def test_clip_and_total():
    assert iv.clip((T(1), T(5)), (T(3), T(9))) == (T(3), T(5))
    assert iv.clip((T(1), T(2)), (T(3), T(9))) is None
    assert iv.total([(T(1), T(3)), (T(2), T(4))]) == timedelta(hours=3)
