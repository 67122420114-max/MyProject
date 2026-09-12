import os
import json
import base64
from flask import Flask, render_template, request, jsonify, session
import webauthn
from webauthn.helpers import (
    options_to_json,
    bytes_to_base64url,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

# RP (Relying Party) Configuration
# WebAuthn strictly requires matching domain / hostname (e.g., 'localhost' for local testing)
RP_NAME = "FIDO2 Passwordless Auth System"
DATA_FILE = os.path.join(os.path.dirname(__file__), "users.json")


def get_rp_id():
    """Extract Relying Party ID from Request Host (e.g. 'localhost' or domain)."""
    host = request.host.split(":")[0]
    return host if host else "localhost"


def get_origin():
    """Extract Request Origin (e.g. 'http://localhost:5000' or 'https://your-domain.com')."""
    return request.host_url.rstrip("/")


def load_db():
    """Load database from users.json file."""
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_db(db):
    """Save database to users.json file."""
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    """Step 1 of Registration: Receive user info, create WebAuthn creation options."""
    data = request.json or {}
    username = data.get("username", "").strip()
    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()
    phone_number = data.get("phone_number", "").strip()

    if not username or not first_name or not last_name or not phone_number:
        return jsonify({"success": False, "message": "กรุณากรอกข้อมูลให้ครบถ้วนทุกช่อง"}), 400

    db = load_db()
    
    # Generate unique user ID bytes
    if username in db and "user_id" in db[username]:
        user_id = base64url_to_bytes(db[username]["user_id"])
    else:
        user_id = os.urandom(16)

    rp_id = get_rp_id()

    # Create WebAuthn registration options
    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        user_display_name=f"{first_name} {last_name}",
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        ),
    )

    # Store challenge and temporary user metadata in session/DB
    user_id_b64 = bytes_to_base64url(user_id)
    challenge_b64 = bytes_to_base64url(options.challenge)

    session["reg_challenge"] = challenge_b64
    session["reg_user"] = {
        "username": username,
        "first_name": first_name,
        "last_name": last_name,
        "phone_number": phone_number,
        "user_id": user_id_b64,
    }

    return jsonify({"success": True, "options": json.loads(options_to_json(options))})


@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    """Step 2 of Registration: Verify WebAuthn response & save user credential."""
    try:
        credential_data = request.json or {}
        challenge_b64 = session.get("reg_challenge")
        user_info = session.get("reg_user")

        if not challenge_b64 or not user_info:
            return jsonify({"success": False, "message": "ไม่พบข้อมูล Session การสมัครสมาชิก กรุณาลองใหม่อีกครั้ง"}), 400

        rp_id = get_rp_id()
        origin = get_origin()

        # Verify registration response
        verification = webauthn.verify_registration_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origin,
        )

        username = user_info["username"]
        db = load_db()

        # Store user profile & credential details
        if username not in db:
            db[username] = {
                "username": username,
                "first_name": user_info["first_name"],
                "last_name": user_info["last_name"],
                "phone_number": user_info["phone_number"],
                "user_id": user_info["user_id"],
                "credentials": [],
            }

        cred_id_b64 = bytes_to_base64url(verification.credential_id)
        pub_key_b64 = bytes_to_base64url(verification.credential_public_key)

        # Update or append credential
        db[username]["credentials"].append({
            "id": cred_id_b64,
            "public_key": pub_key_b64,
            "sign_count": verification.sign_count,
        })

        save_db(db)

        # Clear registration session
        session.pop("reg_challenge", None)
        session.pop("reg_user", None)

        return jsonify({
            "success": True,
            "message": f"ลงทะเบียนสำเร็จสำหรับคุณ {user_info['first_name']} {user_info['last_name']}",
            "user": {
                "username": username,
                "first_name": user_info["first_name"],
                "last_name": user_info["last_name"],
                "phone_number": user_info["phone_number"],
            }
        })

    except Exception as e:
        app.logger.error(f"Registration Error: {e}")
        return jsonify({"success": False, "message": f"การยืนยัน Credential ล้มเหลว: {str(e)}"}), 400


@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    """Step 1 of Authentication: Receive username, return WebAuthn assertion options."""
    data = request.json or {}
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"success": False, "message": "กรุณากรอก Username"}), 400

    db = load_db()
    user = db.get(username)

    if not user or not user.get("credentials"):
        return jsonify({"success": False, "message": "ไม่พบผู้ใช้หรืออุปกรณ์ FIDO2 ในระบบ กรุณาสมัครสมาชิกก่อน"}), 404

    # Convert stored allowed credentials
    allowed_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred["id"]))
        for cred in user["credentials"]
    ]

    rp_id = get_rp_id()

    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allowed_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_b64 = bytes_to_base64url(options.challenge)
    session["auth_challenge"] = challenge_b64
    session["auth_username"] = username

    return jsonify({"success": True, "options": json.loads(options_to_json(options))})


@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    """Step 2 of Authentication: Verify WebAuthn signature & log user in."""
    try:
        credential_data = request.json or {}
        challenge_b64 = session.get("auth_challenge")
        username = session.get("auth_username")

        if not challenge_b64 or not username:
            return jsonify({"success": False, "message": "ไม่พบ Session การเข้าสู่ระบบ กรุณาลองใหม่อีกครั้ง"}), 400

        db = load_db()
        user = db.get(username)

        if not user:
            return jsonify({"success": False, "message": "ไม่พบข้อมูลผู้ใช้งาน"}), 404

        cred_id_str = credential_data.get("id")
        target_cred = None
        for cred in user.get("credentials", []):
            if cred["id"] == cred_id_str:
                target_cred = cred
                break

        if not target_cred:
            return jsonify({"success": False, "message": "อุปกรณ์ FIDO2 นี้ไม่ตรงกับข้อมูลในระบบ"}), 400

        rp_id = get_rp_id()
        origin = get_origin()

        # Verify authentication response
        verification = webauthn.verify_authentication_response(
            credential=credential_data,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(target_cred["public_key"]),
            credential_current_sign_count=target_cred["sign_count"],
        )

        # Update signature count
        target_cred["sign_count"] = verification.new_sign_count
        save_db(db)

        # Clear session challenge
        session.pop("auth_challenge", None)

        return jsonify({
            "success": True,
            "message": "เข้าสู่ระบบสำเร็จ!",
            "user": {
                "username": user["username"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "phone_number": user["phone_number"],
            }
        })

    except Exception as e:
        app.logger.error(f"Authentication Error: {e}")
        return jsonify({"success": False, "message": f"การยืนยันตัวตนล้มเหลว: {str(e)}"}), 400


@app.route("/api/users", methods=["GET"])
def list_users():
    """List usernames registered in system for quick selection."""
    db = load_db()
    users_list = [
        {
            "username": u["username"],
            "name": f"{u['first_name']} {u['last_name']}",
            "phone": u["phone_number"]
        }
        for u in db.values()
    ]
    return jsonify({"success": True, "users": users_list})


if __name__ == "__main__":
    print("==================================================")
    print(" FIDO2 WebAuthn Passwordless Auth Server")
    print(" Server is running on: http://localhost:5000")
    print("==================================================")
    app.run(host="0.0.0.0", port=5000, debug=True)
