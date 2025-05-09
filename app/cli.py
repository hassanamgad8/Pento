import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash

@click.command("create-user")
@click.argument("username")
@click.argument("password")
@with_appcontext
def create_user(username, password):
    """Create a user from the CLI."""
    from app import db                    # ⬅️ lazy import to avoid circular issue
    from app.models import User           # ⬅️ same here

    if User.query.filter_by(username=username).first():
        click.echo(f"⚠️ User '{username}' already exists.")
        return

    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    click.echo(f"✅ User '{username}' created.")
