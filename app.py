from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h1>Zero Trust Cloud Workload</h1>
    <p>This resource is hosted in the cloud as part of the hybrid cloud proof-of-concept.</p>
    <p>Access to protected resources will be controlled by Zero Trust policies.</p>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
