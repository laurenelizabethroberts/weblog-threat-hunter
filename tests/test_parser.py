from datetime import datetime, timezone, timedelta
from webloghunter.parser import parse_line

def test_parse_common_line():
    line = '127.0.0.1 - - [10/Oct/2020:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
    rec = parse_line(line)
    assert rec.host == "127.0.0.1"
    assert rec.ident is None
    assert rec.user is None
    assert rec.time == datetime(2020, 10, 10, 13, 55, 36, tzinfo=timezone.utc)
    assert rec.method == "GET"
    assert rec.path == "/index.html"
    assert rec.protocol == "HTTP/1.1"
    assert rec.status == 200
    assert rec.bytes == 2326
    assert rec.referer is None
    assert rec.user_agent == "Mozilla/5.0"

def test_parse_combined_line_with_values():
    line = '203.0.113.9 - alice [10/Oct/2020:13:56:10 +0000] "POST /login HTTP/1.1" 401 512 "https://example.com/" "curl/7.68.0"'
    rec = parse_line(line)
    assert rec.host == "203.0.113.9"
    assert rec.ident is None
    assert rec.user == "alice"
    assert rec.time.utcoffset() == timedelta(0)
    assert rec.method == "POST"
    assert rec.path == "/login"
    assert rec.status == 401
    assert rec.bytes == 512
    assert rec.referer == "https://example.com/"
    assert rec.user_agent == "curl/7.68.0"
