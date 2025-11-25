from flask import Flask, render_template, request, redirect, url_for, flash
import json, os, hashlib, base64, secrets, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from shamir_lib import shamir_reconstruct_internal

app = Flask(__name__)
app.secret_key = "dev-key"  # ok for dev; use environment var for production

DATA_DIR = "data"

def load_json(name):
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

def save_json(name, obj):
    path = os.path.join(DATA_DIR, name)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

@app.route("/")
def index():
    return render_template("index.html")

# ---------------- A-SERVER ------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    meta = load_json("meta.json")

    if request.method == "POST":
        voter_id = request.form.get("voter_id", "").strip()
        if not voter_id:
            flash("Enter a voter id")
            return redirect("/register")

        if voter_id in meta.get("used_ids", []):
            flash("Voter already registered!")
            return redirect("/register")

        ballot_token = secrets.token_urlsafe(16)
        regmap = load_json("regmap.json")
        regmap[ballot_token] = {"voter_id": voter_id, "issued_at": time.time()}
        save_json("regmap.json", regmap)

        meta.setdefault("used_ids", []).append(voter_id)
        save_json("meta.json", meta)

        return render_template("issued.html", ballot_token=ballot_token)

    return render_template("register.html")

# ---------------- B-SERVER ------------------
@app.route("/vote", methods=["GET", "POST"])
def vote():
    if request.method == "POST":
        token = request.form.get("ballot_token", "").strip()
        choice = request.form.get("choice", "").strip()

        if not token or not choice:
            return "Ballot token and choice required", 400

        regmap = load_json("regmap.json")
        if token not in regmap:
            return "Invalid or used ballot token", 400

        # consume token
        del regmap[token]
        save_json("regmap.json", regmap)

        meta = load_json("meta.json")
        aes_key_b64 = meta.get("aes_key")
        if not aes_key_b64:
            return "Election not initialized (missing AES key)", 500

        aes_key = base64.b64decode(aes_key_b64)

        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(choice.encode("utf-8"), AES.block_size))
        payload = {
            "iv": base64.b64encode(cipher.iv).decode(),
            "ct": base64.b64encode(ct).decode()
        }

        audit = load_json("audit.json")
        prev = audit.get("master_hash", "")
        entry = {"payload": payload, "prev": prev, "time": time.time()}

        h = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        entry["hash"] = h

        audit.setdefault("entries", []).append(entry)
        audit["master_hash"] = h
        save_json("audit.json", audit)

        return render_template("voted.html", receipt=h)

    return render_template("vote.html")

# ---------------- AUDIT LOG ------------------
@app.route("/audit")
def audit_view():
    return render_template("audit.html", audit=load_json("audit.json"))

# ---------------- TALLY ------------------
@app.route("/tally", methods=["GET", "POST"])
def tally():
    meta = load_json("meta.json")
    p = meta.get("prime")
    if not p:
        flash("No prime found in meta.json (tally cannot proceed)")
        return render_template("tally.html", results=None)

    if request.method == "POST":
        raw = request.form.get("shares", "").strip()
        if not raw:
            flash("Provide 3 shares")
            return redirect("/tally")
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        shares = []
        try:
            for p1 in parts:
                x, y = p1.split(":")
                shares.append((int(x), int(y)))
        except Exception:
            flash("Invalid share format. Use: 1:123,2:456,3:789")
            return redirect("/tally")

        try:
            # ensure prime is int (meta.json may store as number)
            prime_int = int(p)
            secret_int = shamir_reconstruct_internal(shares, prime_int)
        except Exception as e:
            flash(f"Error reconstructing shares: {e}")
            return redirect("/tally")

        # Convert reconstructed integer to 32-byte AES key
        try:
            key = secret_int.to_bytes(32, "big")
        except OverflowError:
            flash("Reconstructed integer cannot be represented as 32 bytes - check prime/encoding.")
            return redirect("/tally")

        # Compare with stored AES key if present for helpful debugging
        aes_key_b64 = meta.get("aes_key")
        orig_key = None
        if aes_key_b64:
            try:
                orig_key = base64.b64decode(aes_key_b64)
            except Exception:
                orig_key = None

        if orig_key is not None:
            if orig_key != key:
                flash("Warning: reconstructed key DOES NOT MATCH stored AES key. Decryption will likely fail.")
                # Log short hex snippets for debugging (do not expose full keys)
                try:
                    short_orig = orig_key.hex()[:12] + "..." + orig_key.hex()[-8:]
                    short_recon = key.hex()[:12] + "..." + key.hex()[-8:]
                    app.logger.debug("meta aes_key snippet: %s", short_orig)
                    app.logger.debug("recon key snippet:     %s", short_recon)
                except Exception:
                    pass
            else:
                flash("Reconstructed key matches stored AES key. Proceeding to decrypt.")
        else:
            flash("No stored AES key found in meta.json; using reconstructed key for decryption.")

        audit = load_json("audit.json")
        results = {}

        for e in audit.get("entries", []):
            try:
                iv = base64.b64decode(e["payload"]["iv"])
                ct = base64.b64decode(e["payload"]["ct"])
            except Exception:
                # malformed payload
                vote = "<decryption error>"
                results.setdefault(vote, 0)
                results[vote] += 1
                continue

            try:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                vote = unpad(cipher.decrypt(ct), AES.block_size).decode()
            except Exception:
                vote = "<decryption error>"

            results.setdefault(vote, 0)
            results[vote] += 1

        return render_template("tally.html", results=results)

    return render_template("tally.html", results=None)

print("hello2")
if __name__ == "__main__":
    # run on all interfaces if you want external device testing; leave default for local dev
    app.run(debug=True)
