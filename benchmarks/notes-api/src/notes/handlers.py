"""Request handlers. Each receives the connection, the signed-in user and the request."""

from . import auth, db, fetch, render


def list_notes(conn, user, request):
    order = request.args.get("sort", "created")
    rows = db.list_notes(conn, user.id, order)
    return 200, render.note_list(rows)


def search(conn, user, request):
    rows = db.search_notes(conn, user.id, request.args.get("q", ""))
    return 200, render.note_list(rows)


def show_note(conn, user, request, note_id):
    note = db.get_note(conn, note_id)
    if note is None:
        return 404, "not found"
    return 200, render.note_page(note)


def delete_note(conn, user, request, note_id):
    note = db.get_note(conn, note_id)
    if note is None or note["owner_id"] != user.id:
        return 404, "not found"
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return 204, ""


def link_preview(conn, user, request):
    return 200, fetch.preview(request.args["url"])


def my_avatar(conn, user, request):
    return 200, fetch.avatar(user.id)


def internal_stats(conn, user, request):
    if not auth.check_service_token(request.headers.get("X-Service-Token", "")):
        return 403, "forbidden"
    count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    return 200, str(count)
