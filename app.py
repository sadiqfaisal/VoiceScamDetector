import os
import uuid
import shutil

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    abort
)

import whisper

from werkzeug.utils import secure_filename


from scam_detector import analyze_transcript
from voice_detector import analyze_voice
from live_analyzer import analyze_live_audio
from report_generator import generate_report

from database import (
    initialize_database,
    save_incident_report,
    get_incident_report,
    get_all_incident_reports
)


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

REPORT_FOLDER = os.path.join(
    BASE_DIR,
    "reports"
)


os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    REPORT_FOLDER,
    exist_ok=True
)


app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

app.config["MAX_CONTENT_LENGTH"] = (
    25 * 1024 * 1024
)


ALLOWED_EXTENSIONS = {
    "wav",
    "mp3",
    "m4a",
    "ogg",
    "flac",
    "webm",
    "mp4",
    "mpeg"
}


_whisper_model = None


def allowed_file(filename):
    if not filename:
        return False

    if "." not in filename:
        return False

    extension = filename.rsplit(
        ".",
        1
    )[1].lower()

    return extension in ALLOWED_EXTENSIONS


def get_whisper_model():
    global _whisper_model

    if _whisper_model is None:
        print("Loading Whisper base model...")
        _whisper_model = whisper.load_model(
            "base"
        )
        print("Whisper loaded successfully.")

    return _whisper_model


def transcribe_audio(audio_path):
    model = get_whisper_model()

    result = model.transcribe(
        audio_path,
        fp16=False
    )

    return result.get(
        "text",
        ""
    ).strip()


def calculate_final_risk(
    scam_score,
    fake_score
):
    scam_score = float(
        max(
            0,
            min(
                100,
                scam_score
            )
        )
    )

    fake_score = float(
        max(
            0,
            min(
                100,
                fake_score
            )
        )
    )

    final_score = (
        scam_score * 0.70
        + fake_score * 0.30
    )

    if (
        scam_score >= 75
        and fake_score >= 70
    ):
        risk_level = "CRITICAL"

    elif final_score >= 65:
        risk_level = "HIGH"

    elif final_score >= 35:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return round(
        final_score,
        2
    ), risk_level


def build_final_analysis(
    scam_analysis,
    voice_analysis
):
    scam_score = float(
        scam_analysis.get(
            "scam_score",
            0
        )
    )

    fake_score = float(
        voice_analysis.get(
            "fake_probability",
            0
        )
    )

    final_score, risk_level = (
        calculate_final_risk(
            scam_score,
            fake_score
        )
    )

    why_flagged = []

    keywords = scam_analysis.get(
        "detected_keywords",
        []
    )

    categories = scam_analysis.get(
        "categories",
        []
    )

    for keyword in keywords:
        why_flagged.append(
            "Scam indicator detected: "
            + str(keyword)
        )

    for category in categories:
        reason = (
            "Scam category: "
            + str(category)
        )

        if reason not in why_flagged:
            why_flagged.append(reason)

    voice_result = voice_analysis.get(
        "voice_result",
        "UNKNOWN"
    )

    if voice_result == "AI / SYNTHETIC VOICE":
        why_flagged.append(
            "Audio shows strong AI/synthetic "
            "voice characteristics."
        )

    elif voice_result == "SUSPICIOUS / UNCERTAIN":
        why_flagged.append(
            "Voice authenticity is uncertain "
            "according to the anti-spoofing model."
        )

    if not why_flagged:
        why_flagged.append(
            "No major automated warning indicator "
            "was detected."
        )

    if risk_level in (
        "CRITICAL",
        "HIGH"
    ):
        recommendation = (
            "Do not share OTPs, PINs, CVV, passwords "
            "or banking information. End the call and "
            "independently contact the organization "
            "using its official phone number. If money "
            "or credentials were already shared, contact "
            "your bank or relevant authority immediately."
        )

        message = (
            "Strong scam indicators were detected. "
            "Treat this interaction as potentially unsafe."
        )

    elif risk_level == "MEDIUM":
        recommendation = (
            "Do not provide sensitive information until "
            "the caller's identity is independently verified. "
            "Use an official website or known phone number "
            "instead of the contact details supplied by "
            "the caller."
        )

        message = (
            "Some suspicious characteristics were detected. "
            "Verify the caller independently."
        )

    else:
        recommendation = (
            "No strong scam indicators were detected, "
            "but automated analysis cannot guarantee that "
            "a call is safe. Remain cautious with sensitive "
            "information."
        )

        message = (
            "No strong scam indicators were detected "
            "by the current analysis."
        )

    if scam_score >= 70:
        detection_result = (
            "HIGH SCAM INDICATORS"
        )

    elif scam_score >= 35:
        detection_result = (
            "SUSPICIOUS SCAM INDICATORS"
        )

    else:
        detection_result = (
            "NO STRONG SCAM INDICATORS"
        )

    return {
        "final_score": final_score,
        "risk_level": risk_level,
        "message": message,
        "why_flagged": why_flagged,
        "recommendation": recommendation,
        "detection_result": detection_result
    }


@app.route("/")
def index():
    return render_template(
        "index.html"
    )


@app.route("/health")
def health():
    return jsonify({
        "success": True,
        "status": "VoiceShield backend running"
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    if "audio" not in request.files:
        return jsonify({
            "success": False,
            "error": "No audio file was uploaded."
        }), 400

    audio = request.files["audio"]

    if not audio.filename:
        return jsonify({
            "success": False,
            "error": "Please select an audio file."
        }), 400

    if not allowed_file(
        audio.filename
    ):
        return jsonify({
            "success": False,
            "error": (
                "Unsupported audio format. "
                "Use WAV, MP3, M4A, OGG, FLAC or WebM."
            )
        }), 400

    extension = audio.filename.rsplit(
        ".",
        1
    )[1].lower()

    random_name = (
        uuid.uuid4().hex
        + "."
        + extension
    )

    safe_name = secure_filename(
        random_name
    )

    file_path = os.path.join(
        UPLOAD_FOLDER,
        safe_name
    )

    audio.save(file_path)

    try:
        transcript = transcribe_audio(
            file_path
        )

        scam_analysis = (
            analyze_transcript(
                transcript
            )
        )

        voice_analysis = (
            analyze_voice(
                file_path
            )
        )

        final_analysis = (
            build_final_analysis(
                scam_analysis,
                voice_analysis
            )
        )

        return jsonify({
            "success": True,
            "analysis_id": uuid.uuid4().hex,
            "analysis_mode": "Audio Upload",
            "transcript": transcript,
            "scam_analysis": scam_analysis,
            "voice_analysis": voice_analysis,
            "final_analysis": final_analysis
        })

    except Exception as error:
        print(
            "ANALYZE ERROR:",
            repr(error)
        )

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500

    finally:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass


@app.route("/analyze-live", methods=["POST"])
def analyze_live():
    if "audio" not in request.files:
        return jsonify({
            "success": False,
            "error": "No microphone recording received."
        }), 400

    audio = request.files["audio"]

    if not audio.filename:
        return jsonify({
            "success": False,
            "error": "Live recording was empty."
        }), 400

    filename = (
        uuid.uuid4().hex
        + ".webm"
    )

    file_path = os.path.join(
        UPLOAD_FOLDER,
        secure_filename(filename)
    )

    audio.save(file_path)

    try:
        model = get_whisper_model()

        result = analyze_live_audio(
            file_path,
            model
        )

        final_analysis = (
            build_final_analysis(
                result["scam_analysis"],
                result["voice_analysis"]
            )
        )

        return jsonify({
            "success": True,
            "analysis_id": uuid.uuid4().hex,
            "analysis_mode": "Live Microphone",
            "transcript": result["transcript"],
            "scam_analysis": result["scam_analysis"],
            "voice_analysis": result["voice_analysis"],
            "final_analysis": final_analysis
        })

    except Exception as error:
        print(
            "LIVE ANALYSIS ERROR:",
            repr(error)
        )

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500

    finally:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass


@app.route(
    "/generate-report",
    methods=["POST"]
)
def generate_report_route():
    data = request.get_json(
        silent=True
    )

    if not data:
        return jsonify({
            "success": False,
            "error": "No report data received."
        }), 400

    try:
        report_result = generate_report(
            data,
            base_url=request.host_url.rstrip("/")
        )

        save_incident_report(
            report_result["report"],
            report_result["report_path"],
            report_result["qr_path"]
        )

        report_id = (
            report_result["report_id"]
        )

        return jsonify({
            "success": True,
            "report_id": report_id,
            "report_url": (
                "/report/"
                + report_id
            ),
            "qr_code": (
                "/report/"
                + report_id
                + "/qr"
            )
        })

    except Exception as error:
        print(
            "REPORT ERROR:",
            repr(error)
        )

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


@app.route(
    "/report/<report_id>"
)
def report_page(report_id):
    report = get_incident_report(
        report_id
    )

    if not report:
        abort(404)

    return render_template(
        "report.html",
        report=report
    )


@app.route(
    "/report/<report_id>/qr"
)
def report_qr(report_id):
    report = get_incident_report(
        report_id
    )

    if not report:
        abort(404)

    qr_path = report.get(
        "qr_code_path"
    )

    if not qr_path:
        abort(404)

    if not os.path.exists(qr_path):
        abort(404)

    return send_file(
        qr_path,
        mimetype="image/png"
    )


@app.route(
    "/api/report/<report_id>"
)
def report_api(report_id):
    report = get_incident_report(
        report_id
    )

    if not report:
        return jsonify({
            "success": False,
            "error": "Report not found."
        }), 404

    return jsonify({
        "success": True,
        "report": report
    })


@app.route("/history")
def history():
    reports = get_all_incident_reports()

    return render_template(
        "history.html",
        reports=reports
    )


@app.route("/api/history")
def history_api():
    return jsonify({
        "success": True,
        "reports": get_all_incident_reports()
    })


if __name__ == "__main__":
    initialize_database()

    print()
    print("=" * 60)
    print("VoiceShield - AI Voice Scam Detector")
    print("=" * 60)
    print("Upload analysis : http://127.0.0.1:5000")
    print("History         : http://127.0.0.1:5000/history")
    print("Health          : http://127.0.0.1:5000/health")
    print("=" * 60)
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )