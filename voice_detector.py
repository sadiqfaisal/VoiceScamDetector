import os
import sys

import librosa
import numpy as np
import torch
import torch.nn.functional as F


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

AASIST_DIR = os.path.join(
    BASE_DIR,
    "models",
    "aasist"
)

if AASIST_DIR not in sys.path:
    sys.path.insert(0, AASIST_DIR)


try:
    from AASIST import Model
except Exception as error:
    Model = None
    AASIST_IMPORT_ERROR = str(error)


MODEL_PATH = os.path.join(
    AASIST_DIR,
    "AASIST.pth"
)


AASIST_CONFIG = {
    "architecture": "AASIST",
    "nb_samp": 64600,
    "first_conv": 128,
    "filts": [
        70,
        [1, 32],
        [32, 32],
        [32, 64],
        [64, 64]
    ],
    "gat_dims": [
        64,
        32
    ],
    "pool_ratios": [
        0.5,
        0.7,
        0.5,
        0.5
    ],
    "temperatures": [
        2.0,
        2.0,
        100.0,
        100.0
    ]
}


_model = None

DEVICE = (
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)


def get_model():
    global _model

    if _model is not None:
        return _model

    if Model is None:
        raise RuntimeError(
            "AASIST import failed: "
            + AASIST_IMPORT_ERROR
        )

    if not os.path.exists(MODEL_PATH):
        raise RuntimeError(
            "AASIST checkpoint not found: "
            + MODEL_PATH
        )

    print("Loading official AASIST...")
    print("AASIST device:", DEVICE)

    model = Model(AASIST_CONFIG)

    checkpoint = torch.load(
        MODEL_PATH,
        map_location=DEVICE,
        weights_only=False
    )

    if isinstance(checkpoint, dict):

        if "state_dict" in checkpoint:
            state_dict = checkpoint["state_dict"]

        elif "model_state_dict" in checkpoint:
            state_dict = checkpoint["model_state_dict"]

        else:
            state_dict = checkpoint

    else:
        state_dict = checkpoint.state_dict()


    cleaned_state_dict = {}

    for key, value in state_dict.items():

        if key.startswith("module."):
            key = key[7:]

        cleaned_state_dict[key] = value


    model.load_state_dict(
        cleaned_state_dict,
        strict=True
    )

    model.to(DEVICE)
    model.eval()

    _model = model

    print("AASIST loaded successfully.")

    return _model


def prepare_audio(audio_path):

    if not os.path.exists(audio_path):
        raise FileNotFoundError(
            audio_path
        )

    audio, sample_rate = librosa.load(
        audio_path,
        sr=16000,
        mono=True
    )

    audio = np.asarray(
        audio,
        dtype=np.float32
    )

    if audio.size == 0:
        raise ValueError(
            "Audio contains no usable samples."
        )


    target_length = (
        AASIST_CONFIG["nb_samp"]
    )


    if len(audio) < target_length:

        repeats = int(
            np.ceil(
                target_length / len(audio)
            )
        )

        audio = np.tile(
            audio,
            repeats
        )


    audio = audio[:target_length]

    return audio.astype(
        np.float32
    )


def analyze_voice(audio_path):

    if not os.path.exists(audio_path):

        return {
            "voice_result": "UNKNOWN",
            "fake_probability": 0,
            "human_probability": 0,
            "confidence": 0,
            "aasist_score": None,
            "analysis_type": "ERROR",
            "details": [
                "Audio file was not found."
            ]
        }


    try:

        audio = prepare_audio(
            audio_path
        )

        model = get_model()


        waveform = torch.from_numpy(
            audio
        ).unsqueeze(0).to(DEVICE)


        with torch.no_grad():

            hidden, logits = model(
                waveform
            )


            probabilities = F.softmax(
                logits,
                dim=-1
            )


            spoof_score = float(
                probabilities[0, 0].item()
            )


            bona_fide_score = float(
                probabilities[0, 1].item()
            )


            bona_fide_logit = float(
                logits[0, 1].item()
            )


        fake_score = (
            spoof_score * 100.0
        )

        human_score = (
            bona_fide_score * 100.0
        )


        if fake_score >= 70:

            voice_result = (
                "AI / SYNTHETIC VOICE"
            )

        elif fake_score >= 45:

            voice_result = (
                "SUSPICIOUS / UNCERTAIN"
            )

        else:

            voice_result = (
                "LIKELY HUMAN VOICE"
            )


        confidence = (
            abs(fake_score - 50.0)
            * 2.0
        )

        confidence = float(
            np.clip(
                confidence,
                0,
                100
            )
        )


        details = [

            "Official AASIST anti-spoofing model used.",

            "Audio normalized to mono 16 kHz.",

            "AASIST analyzes a 64,600-sample input window.",

            f"Bona-fide model logit: {bona_fide_logit:.4f}",

            f"AI / spoof score: {fake_score:.1f}%",

            f"Human / bona-fide score: {human_score:.1f}%"
        ]


        return {

            "voice_result":
                voice_result,

            "fake_probability":
                round(
                    fake_score,
                    2
                ),

            "human_probability":
                round(
                    human_score,
                    2
                ),

            "confidence":
                round(
                    confidence,
                    2
                ),

            "aasist_score":
                round(
                    bona_fide_logit,
                    6
                ),

            "analysis_type":
                "AASIST",

            "details":
                details
        }


    except Exception as error:

        print(
            "AASIST ERROR:",
            repr(error)
        )

        return {

            "voice_result":
                "UNKNOWN",

            "fake_probability":
                0,

            "human_probability":
                0,

            "confidence":
                0,

            "aasist_score":
                None,

            "analysis_type":
                "ERROR",

            "details": [
                "AI voice analysis failed.",
                str(error)
            ]
        }