import os
import numpy as np


# ==========================================
# VOICE DETECTOR
# ==========================================
#
# This module currently provides a baseline
# audio analysis system.
#
# Later, your Core ML teammates can replace
# this function with the trained ASVspoof /
# pretrained-audio-model classifier.
#
# IMPORTANT:
# This is NOT claiming that acoustic heuristics
# can reliably prove an AI-generated voice.
# The real trained classifier should replace
# this baseline before production use.
# ==========================================


def analyze_voice(audio_path):

    """
    Analyze an audio file and return a standard
    result format expected by app.py.

    Returns:
        {
            "voice_result": "NORMAL" / "SUSPICIOUS",
            "fake_probability": 0-100,
            "confidence": 0-100,
            "details": [...]
        }
    """

    # --------------------------------------
    # CHECK FILE
    # --------------------------------------

    if not os.path.exists(audio_path):

        return {

            "voice_result":
                "UNKNOWN",

            "fake_probability":
                0,

            "confidence":
                0,

            "details":
                [
                    "Audio file was not found."
                ]

        }


    try:

        # ----------------------------------
        # LOAD AUDIO
        # ----------------------------------

        import librosa


        audio, sample_rate = librosa.load(

            audio_path,

            sr=16000,

            mono=True

        )


        # ----------------------------------
        # BASIC AUDIO VALIDATION
        # ----------------------------------

        if len(audio) == 0:

            return {

                "voice_result":
                    "UNKNOWN",

                "fake_probability":
                    0,

                "confidence":
                    0,

                "details":
                    [
                        "The audio file contains no usable audio."
                    ]

            }


        # ----------------------------------
        # NORMALIZE
        # ----------------------------------

        audio = audio.astype(
            np.float32
        )


        max_value = np.max(
            np.abs(audio)
        )


        if max_value > 0:

            audio = (
                audio
                /
                max_value
            )


        # ----------------------------------
        # RMS ENERGY
        # ----------------------------------

        rms = float(

            np.sqrt(

                np.mean(
                    audio ** 2
                )

            )

        )


        # ----------------------------------
        # ZERO CROSSING RATE
        # ----------------------------------

        zero_crossings = np.mean(

            np.abs(
                np.diff(
                    np.sign(audio)
                )
            )

            >

            0

        )


        # ----------------------------------
        # SPECTRAL FEATURES
        # ----------------------------------

        spectral_centroid = librosa.feature.spectral_centroid(

            y=audio,

            sr=sample_rate

        )[0]


        centroid_mean = float(

            np.mean(
                spectral_centroid
            )

        )


        spectral_bandwidth = librosa.feature.spectral_bandwidth(

            y=audio,

            sr=sample_rate

        )[0]


        bandwidth_mean = float(

            np.mean(
                spectral_bandwidth
            )

        )


        # ----------------------------------
        # DETERMINE BASIC AUDIO QUALITY
        # ----------------------------------

        details = []


        if rms < 0.005:

            details.append(
                "Very low audio energy detected."
            )


        elif rms > 0.35:

            details.append(
                "High recording energy detected."
            )


        else:

            details.append(
                "Audio energy appears normal."
            )


        if zero_crossings < 0.01:

            details.append(
                "Low zero-crossing activity."
            )

        elif zero_crossings > 0.25:

            details.append(
                "High zero-crossing activity."
            )

        else:

            details.append(
                "Normal zero-crossing activity."
            )


        # ----------------------------------
        # BASELINE SUSPICION SCORE
        # ----------------------------------
        #
        # This is intentionally conservative.
        #
        # We do NOT claim that these features
        # can accurately identify deepfakes.
        #
        # The actual ML classifier will replace
        # this section.
        # ----------------------------------

        suspicion = 0


        # Very unusual silence/energy

        if rms < 0.003:

            suspicion += 15


        # Extremely high spectral centroid

        if centroid_mean > 5000:

            suspicion += 10


        # Very narrow spectral bandwidth

        if bandwidth_mean < 1000:

            suspicion += 10


        # ----------------------------------
        # LIMIT SCORE
        # ----------------------------------

        suspicion = min(

            max(
                suspicion,
                0
            ),

            100

        )


        # ----------------------------------
        # RESULT
        # ----------------------------------

        if suspicion >= 35:

            voice_result = "SUSPICIOUS"

        else:

            voice_result = "NORMAL"


        # ----------------------------------
        # CONFIDENCE
        # ----------------------------------

        #
        # Baseline confidence is deliberately
        # low because this is not a trained
        # anti-spoofing model.
        #

        confidence = 35


        details.append(

            "Baseline acoustic analysis only. "
            "A trained anti-spoofing model is "
            "required for reliable AI-voice detection."

        )


        return {

            "voice_result":
                voice_result,

            "fake_probability":
                suspicion,

            "confidence":
                confidence,

            "details":
                details

        }


    except ImportError:

        return {

            "voice_result":
                "UNKNOWN",

            "fake_probability":
                0,

            "confidence":
                0,

            "details":
                [
                    "librosa is not installed."
                ]

        }


    except Exception as error:

        return {

            "voice_result":
                "UNKNOWN",

            "fake_probability":
                0,

            "confidence":
                0,

            "details":
                [
                    "Voice analysis error: "
                    +
                    str(error)
                ]

        }


# ==========================================
# DIRECT TEST
# ==========================================

if __name__ == "__main__":

    print()
    print("=" * 55)
    print("VOICE SHIELD - VOICE DETECTOR")
    print("=" * 55)
    print()

    print(
        "This module is ready."
    )

    print()

    print(
        "Usage:"
    )

    print(
        "analyze_voice('path/to/audio.wav')"
    )

    print()

    print(
        "The baseline detector will later be "
        "replaced by the trained ASVspoof model."
    )

    print()
