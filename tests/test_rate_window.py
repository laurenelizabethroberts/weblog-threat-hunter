from datetime import datetime, timezone, timedelta
from webloghunter.parser import LogRecord
from webloghunter.detectors import analyze
from webloghunter.config import Config

def mk_t(base: datetime, secs: int) -> datetime:
    return base + timedelta(seconds=secs)

def mk_rec(host: str, dt: datetime, path: str, status: int, ua: str = "Mozilla/5.0"):
    return LogRecord(
        raw="",
        host=host, ident=None, user=None,
        time=dt, method="GET", path=path, protocol="HTTP/1.1",
        status=status, bytes=0, referer=None, user_agent=ua
    )

def test_dirbust_rate_bucket():
    base = datetime(2020, 10, 10, 13, 55, 0, tzinfo=timezone.utc)
    # 8 x 404 within 60s → should trigger if threshold=8
    recs = [mk_rec("192.0.2.55", mk_t(base, i), f"/not-here-{i}", 404) for i in range(0, 50, 6)]  # ~9 hits but within a minute
    cfg = Config(dirbust_threshold=8, window_seconds=60)
    fnds = analyze(recs, cfg)
    assert any(f.type == "DIRBUST" and f.host == "192.0.2.55" for f in fnds)

def test_bruteforce_rate_bucket():
    base = datetime(2020, 10, 10, 13, 55, 0, tzinfo=timezone.utc)
    recs = [mk_rec("203.0.113.9", mk_t(base, s), "/login", 401, "curl/7.68.0") for s in (0,5,10,15)]
    cfg = Config(bruteforce_threshold=4, window_seconds=60)
    fnds = analyze(recs, cfg)
    assert any(f.type == "BRUTE_FORCE" and f.host == "203.0.113.9" for f in fnds)
