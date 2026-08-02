"""PhishGuard web dashboard: paste a URL, get a visual risk report."""
from __future__ import annotations

from flask import Flask, render_template, request

from ..analyzer import analyze

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    submitted_url = ""
    offline = False

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()
        offline = bool(request.form.get("offline"))
        if not submitted_url:
            error = "Please enter a URL."
        else:
            if not submitted_url.startswith(("http://", "https://")):
                submitted_url = f"http://{submitted_url}"
            try:
                result = analyze(submitted_url, offline=offline)
            except Exception as exc:
                error = f"Could not analyze this URL: {exc}"

    return render_template(
        "index.html",
        result=result,
        error=error,
        submitted_url=submitted_url,
        offline=offline,
    )


def main():
    app.run(debug=True, port=5000)


if __name__ == "__main__":
    main()
