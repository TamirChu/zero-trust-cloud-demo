
import os
from urllib.parse import urlencode

from flask import (
    Flask,
    redirect,
    url_for,
    session,
    render_template_string,
)
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY is not configured.")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

oauth = OAuth(app)

keycloak = oauth.register(
    name="keycloak",
    client_id=os.environ.get("KC_CLIENT_ID"),
    client_secret=os.environ.get("KC_CLIENT_SECRET"),
    server_metadata_url=os.environ.get("KC_SERVER_METADATA_URL"),
    client_kwargs={
        "scope": "openid profile email",
    },
)


@app.route("/")
def home():
    user = session.get("user")

    if user:
        return render_template_string(
            """
            <h1>Zero Trust Cloud Workload</h1>
            <p>Authenticated user:
                <strong>{{ user.get('preferred_username', 'Unknown') }}</strong>
            </p>
            <p><a href="{{ url_for('protected') }}">
                Access Protected Resource
            </a></p>
            <p><a href="{{ url_for('logout') }}">Logout</a></p>
            """,
            user=user,
        )

    return """
    <h1>Zero Trust Cloud Workload</h1>
    <p>This resource is hosted in the cloud as part of the
    hybrid cloud proof-of-concept.</p>
    <p>Access to protected resources is controlled by Zero Trust policies.</p>
    <p><a href="/login">Login with Keycloak</a></p>
    """


@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)

    # Ask Keycloak to authenticate the user again, even if an SSO
    # session already exists.
    return keycloak.authorize_redirect(
        redirect_uri,
        prompt="login",
    )


@app.route("/callback")
def callback():
    token = keycloak.authorize_access_token()

    user = token.get("userinfo")

    if not user:
        user = keycloak.userinfo(token=token)

    session.clear()
    session["user"] = dict(user)
    session["access_token"] = token.get("access_token")
    session["id_token"] = token.get("id_token")

    return redirect(url_for("home"))


@app.route("/protected")
def protected():
    user = session.get("user")

    if not user:
        return redirect(url_for("login"))

    roles = user.get("realm_access", {}).get("roles", [])

    if "zt-access" not in roles:
        return """
        <h1>Access Denied</h1>
        <p>You are authenticated, but you are not authorized
        to access this resource.</p>
        <p>Required role: <strong>zt-access</strong></p>
        <p><a href="/">Return Home</a></p>
        """, 403

    return """
    <h1>Access Granted</h1>
    <p>You are authenticated and authorized by the Zero Trust policy.</p>
    <p>Required role <strong>zt-access</strong> verified.</p>
    <p><a href="/">Return Home</a></p>
    """


@app.route("/logout")
def logout():
    # Save the values needed to end the Keycloak SSO session.
    id_token = session.get("id_token")
    client_id = os.environ.get("KC_CLIENT_ID")
    post_logout_uri = url_for("home", _external=True)

    # Always clear the local Flask session.
    session.clear()

    try:
        metadata = keycloak.load_server_metadata()
        logout_endpoint = metadata.get("end_session_endpoint")
    except Exception:
        logout_endpoint = None

    if not logout_endpoint:
        # Local logout still succeeds if Keycloak metadata is unavailable.
        return redirect(url_for("home"))

    params = {
        "client_id": client_id,
        "post_logout_redirect_uri": post_logout_uri,
    }

    if id_token:
        params["id_token_hint"] = id_token

    logout_url = logout_endpoint + "?" + urlencode(params)

    return redirect(logout_url)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

