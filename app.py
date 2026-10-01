import os
from flask import Flask, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
print("Render SECRET_KEY configured:", bool(app.config.get("SECRET_KEY")))
oauth = OAuth(app)

keycloak = oauth.register(
    name="keycloak",
    client_id=os.environ.get("KC_CLIENT_ID"),
    client_secret=os.environ.get("KC_CLIENT_SECRET"),
    server_metadata_url=os.environ.get("KC_SERVER_METADATA_URL"),
    client_kwargs={
        "scope": "openid profile email"
    }
)


@app.route("/")
def home():
    user = session.get("user")

    if user:
        return render_template_string("""
        <h1>Zero Trust Cloud Workload</h1>
        <p>Authenticated user: <strong>{{ user.get('preferred_username') }}</strong></p>
        <p><a href="/protected">Access Protected Resource</a></p>
        <p><a href="/logout">Logout</a></p>
        """, user=user)

    return """
    <h1>Zero Trust Cloud Workload</h1>
    <p>This resource is hosted in the cloud as part of the hybrid cloud proof-of-concept.</p>
    <p>Access to protected resources is controlled by Zero Trust policies.</p>
    <a href="/login">Login with Keycloak</a>
    """


@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)
    return keycloak.authorize_redirect(redirect_uri)


@app.route("/callback")
def callback():
    token = keycloak.authorize_access_token()

    user = token.get("userinfo")

    if not user:
        user = keycloak.userinfo(token=token)

    session["user"] = user
    session["access_token"] = token.get("access_token")

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
        <p>You are authenticated, but you are not authorized to access this resource.</p>
        <p>Required role: <strong>zt-access</strong></p>
        <a href="/">Return Home</a>
        """

    return """
    <h1>Access Granted</h1>
    <p>You are authenticated and authorized by the Zero Trust policy.</p>
    <p>Required role <strong>zt-access</strong> verified.</p>
    <a href="/">Return Home</a>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
