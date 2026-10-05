from client import Outbox


def test_outbox_is_bounded(tmp_path):
    q = Outbox(str(tmp_path / "q.db"), max_items=5)
    for i in range(12):
        q.put("/x", {"i": i})
    rows = q.peek(100)
    assert q.size() == 5
    assert [__import__("json").loads(b)["i"] for _, _, b in rows] == [7, 8, 9, 10, 11]  # oldest dropped
