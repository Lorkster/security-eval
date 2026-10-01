"""What notes-api is meant to do. Every test here passes on the code as it is."""

from notes import auth, db, handlers, render


def test_list_notes_by_title(conn):
    rows = db.list_notes(conn, 1, "title")
    assert [r["title"] for r in rows] == ["Archive", "Shopping"]


def test_list_notes_by_created(conn):
    rows = db.list_notes(conn, 1, "created")
    assert [r["id"] for r in rows] == [2, 1]


def test_list_notes_only_the_owners(conn):
    assert {r["id"] for r in db.list_notes(conn, 2, "created")} == {3}


def test_search_matches_part_of_a_title(conn):
    assert [r["id"] for r in db.search_notes(conn, 1, "hop")] == [1]


def test_get_note(conn):
    assert db.get_note(conn, 1)["title"] == "Shopping"
    assert db.get_note(conn, 99) is None


def test_handler_lists_notes_sorted(conn, alice, make_request):
    status, page = handlers.list_notes(conn, alice, make_request({"sort": "title"}))
    assert status == 200
    assert page.index("Archive") < page.index("Shopping")


def test_handler_lists_notes_by_default(conn, alice, make_request):
    status, _ = handlers.list_notes(conn, alice, make_request())
    assert status == 200


def test_show_own_note(conn, alice, make_request):
    status, page = handlers.show_note(conn, alice, make_request(), 1)
    assert status == 200
    assert "Shopping" in page


def test_show_missing_note(conn, alice, make_request):
    assert handlers.show_note(conn, alice, make_request(), 99)[0] == 404


def test_delete_own_note(conn, alice, make_request):
    assert handlers.delete_note(conn, alice, make_request(), 1)[0] == 204
    assert db.get_note(conn, 1) is None


def test_delete_someone_elses_note(conn, alice, make_request):
    assert handlers.delete_note(conn, alice, make_request(), 3)[0] == 404
    assert db.get_note(conn, 3) is not None


def test_internal_stats_with_the_token(conn, alice, make_request):
    request = make_request(headers={"X-Service-Token": "test-service-token"})
    assert handlers.internal_stats(conn, alice, request) == (200, "3")


def test_internal_stats_without_the_token(conn, alice, make_request):
    assert handlers.internal_stats(conn, alice, make_request())[0] == 403


def test_password_hash_is_repeatable():
    assert auth.hash_password("pw", "salt") == auth.hash_password("pw", "salt")


def test_password_hash_depends_on_salt_and_password():
    assert auth.hash_password("pw", "salt") != auth.hash_password("pw", "pepper")
    assert auth.hash_password("pw", "salt") != auth.hash_password("pw2", "salt")


def test_service_token():
    assert auth.check_service_token("test-service-token")
    assert not auth.check_service_token("wrong")


def test_sessions():
    token = auth.new_session()
    assert len(token) >= 32
    assert auth.check_session(token, token)
    assert not auth.check_session(token, auth.new_session())


def test_note_page_shows_title_and_escapes_body():
    page = render.note_page({"title": "Shopping", "body": "<b>milk</b>"})
    assert "Shopping" in page
    assert "<b>" not in page


def test_note_list_escapes_titles():
    assert "<i>" not in render.note_list([{"title": "<i>x</i>"}])


def test_etag_is_stable():
    assert render.etag(b"abc") == render.etag(b"abc")
