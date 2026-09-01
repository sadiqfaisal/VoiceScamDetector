import os
import glob
import shutil


# ==========================================
# AUTOMATIC FFMPEG SETUP
# ==========================================

def setup_ffmpeg():

    # Check whether FFmpeg is already available
    if shutil.which("ffmpeg"):
        print("FFmpeg detected.")
        return

    search_locations = [

        os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Microsoft",
            "WinGet",
            "Packages"
        ),

        r"C:\Program Files",

        r"C:\Program Files (x86)"

    ]

    for location in search_locations:

        if not os.path.exists(location):
            continue

        try:

            matches = glob.glob(
                os.path.join(
                    location,
                    "**",
                    "ffmpeg.exe"
                ),
                recursive=True
            )

            if matches:

                ffmpeg_path = matches[0]

                ffmpeg_directory = os.path.dirname(
                    ffmpeg_path
                )

                os.environ["PATH"] += (
                    os.pathsep
                    +
                    ffmpeg_directory
                )

                print(
                    "FFmpeg found:",
                    ffmpeg_path
                )

                return

        except Exception as error:

            print(
                "FFmpeg search error:",
                error
            )


    print(
        "WARNING: FFmpeg was not found."
    )


setup_ffmpeg()


# ==========================================
# IMPORTS
# ==========================================

from flask import (
    Flask,
    render_template,
    request,
    jsonify
)

import whisper

from scam_detector import analyze_transcript

from voice_detector import analyze_voice


# ==========================================
# FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)


ALLOWED_EXTENSIONS = {

    "wav",
    "mp3",
    "m4a",
    "mp4",
    "mpeg",
    "mpga",
    "webm"

}


os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


app.config[
    "UPLOAD_FOLDER"
] = UPLOAD_FOLDER


# ==========================================
# LOAD WHISPER
# ==========================================

print()
print("=" * 55)
print("Loading Whisper speech recognition model...")
print("First startup may take some time.")
print("=" * 55)
print()


# "base" = better accuracy
# "tiny" = faster on slower computers

model = whisper.load_model(
    "base"
)


print()
print("Whisper model loaded successfully!")
print()


# ==========================================
# FILE VALIDATION
# ==========================================

def allowed_file(filename):

    return (

        "."

        in filename

        and

        filename.rsplit(
            ".",
            1
        )[1].lower()

        in ALLOWED_EXTENSIONS

    )


# ==========================================
# FINAL RISK CALCULATION
# ==========================================

def calculate_final_risk(
    scam_score,
    voice_score,
    voice_result
):

    # Scam language is currently the main
    # reliable component.

    scam_weight = 0.70

    voice_weight = 0.30


    final_score = int(

        (
            scam_score
            *
            scam_weight
        )

        +

        (
            voice_score
            *
            voice_weight
        )

    )


    final_score = min(
        max(
            final_score,
            0
        ),
        100
    )


    if final_score >= 65:

        risk_level = "HIGH"

        message = (

            "HIGH RISK: Strong scam indicators "
            "were detected. Do not share OTPs, "
            "passwords, bank information, or "
            "send money."

        )


    elif final_score >= 35:

        risk_level = "MEDIUM"

        message = (

            "CAUTION: Suspicious indicators were "
            "detected. Verify the caller independently "
            "before taking action."

        )


    else:

        risk_level = "LOW"

        message = (

            "LOW RISK: No strong scam indicators "
            "were detected. Continue to remain cautious."

        )


    return {

        "final_score":
            final_score,

        "risk_level":
            risk_level,

        "message":
            message

    }


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================
# AUDIO ANALYSIS API
# ==========================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    try:

        # ----------------------------------
        # CHECK FILE
        # ----------------------------------

        if "audio" not in request.files:

            return jsonify({

                "error":
                "No audio file was uploaded."

            }), 400


        audio = request.files[
            "audio"
        ]


        if audio.filename == "":

            return jsonify({

                "error":
                "No audio file was selected."

            }), 400


        if not allowed_file(
            audio.filename
        ):

            return jsonify({

                "error":
                "Unsupported audio format. "
                "Use WAV, MP3, M4A, MP4, MPEG, "
                "MPGA or WEBM."

            }), 400


        # ----------------------------------
        # CREATE UNIQUE FILE NAME
        # ----------------------------------

        extension = (

            audio.filename
            .rsplit(
                ".",
                1
            )[1]
            .lower()

        )


        import uuid


        unique_filename = (

            str(
                uuid.uuid4()
            )

            +

            "."

            +

            extension

        )


        file_path = os.path.join(

            app.config[
                "UPLOAD_FOLDER"
            ],

            unique_filename

        )


        # ----------------------------------
        # SAVE AUDIO
        # ----------------------------------

        audio.save(
            file_path
        )


        print()
        print(
            "Audio received:",
            audio.filename
        )


        # ----------------------------------
        # SPEECH TO TEXT
        # ----------------------------------

        print(
            "Converting speech to text..."
        )


        transcription = model.transcribe(

            file_path,

            fp16=False

        )


        transcript = (

            transcription.get(
                "text",
                ""
            )
            .strip()

        )


        print(
            "Transcript:",
            transcript
        )


        # ----------------------------------
        # SCAM LANGUAGE ANALYSIS
        # ----------------------------------

        print(
            "Analyzing scam language..."
        )


        scam_result = analyze_transcript(

            transcript

        )


        # ----------------------------------
        # VOICE ANALYSIS
        # ----------------------------------

        print(
            "Analyzing voice..."
        )


        voice_result = analyze_voice(

            file_path

        )


        # ----------------------------------
        # FINAL RISK
        # ----------------------------------

        final_result = calculate_final_risk(

            scam_result[
                "scam_score"
            ],

            voice_result[
                "fake_probability"
            ],

            voice_result[
                "voice_result"
            ]

        )


        # ----------------------------------
        # DELETE TEMPORARY AUDIO
        # ----------------------------------

        try:

            os.remove(
                file_path
            )

        except Exception:

            pass


        # ----------------------------------
        # RETURN RESULT
        # ----------------------------------

        return jsonify({

            "success":
                True,

            "transcript":
                transcript,

            "scam_analysis":
                scam_result,

            "voice_analysis":
                voice_result,

            "final_analysis":
                final_result

        })


    except Exception as error:

        print()
        print(
            "=" * 50
        )
        print(
            "ANALYSIS ERROR"
        )
        print(
            error
        )
        print(
            "=" * 50
        )
        print()


        return jsonify({

            "error":

            "Audio analysis failed: "
            +
            str(error)

        }), 500


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    print()
    print("=" * 55)
    print("VOICE SHIELD")
    print("AI Voice & Scam Detection System")
    print("=" * 55)
    print()
    print(
        "Open this in your browser:"
    )
    print()
    print(
        "http://127.0.0.1:5000"
    )
    print()
    print(
        "Press CTRL+C to stop the server."
    )
    print()


    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )

