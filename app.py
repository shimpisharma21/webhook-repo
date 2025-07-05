import os, hmac, hashlib, time
from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient(os.getenv("MONGODB_URI"))
col = client.events_db.events

SECRET = os.getenv("WEBHOOK_SECRET").encode()


def verify_sig(payload, sig_header):
    sha_name, signature = sig_header.split("=", 1)
    mac = hmac.new(SECRET, payload, hashlib.sha1)
    return hmac.compare_digest(mac.hexdigest(), signature)


@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        # Dump the incoming request so you can see exactly what’s arriving
        print("=== WEBHOOK RECEIVED ===")
        print("Headers:", dict(request.headers))
        print("Body   :", request.get_data().decode())

        # Optional: skip signature verification if there's no header (for testing)
        sig_header = request.headers.get("X-Hub-Signature")
        if sig_header:
            if not verify_sig(request.get_data(), sig_header):
                print("⚠️  Invalid signature:", sig_header)
                return "Invalid signature", 403
        else:
            print(
                "⚠️  No signature header — skipping verification (test mode)")


        # Minimal payload extraction (updated to match new webhook payload)
        evt = request.json or {}
        doc = {
            "type":        evt.get("event_type"),    # "push" or "pull_request"
            "action":      evt.get("pr_action"),     # "opened"/"closed" or ""
            "from_branch": evt.get("from_branch"),   # e.g. "feature-xyz"
            "to_branch":   evt.get("to_branch"),     # e.g. "main"
            "author":      evt.get("author"),        # GitHub username
            "timestamp":   time.time()
        }

        print("→ Inserting:", doc)
        col.insert_one(doc)
        return "", 204

    except Exception as e:
        # Print stack trace so you can see exactly what went wrong
        import traceback
        traceback.print_exc()
        return "Internal Server Error", 500


@app.route("/events")
def events():
    items = list(col.find().sort("timestamp", -1).limit(20))
    for i in items:
        i["_id"] = str(i["_id"])
    return jsonify(items)


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 3000)))

