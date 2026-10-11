"""A separately installed, benign export dependency."""
def export_note(note):
    return f"Note {note['id']}\n{note['text']}\n"
