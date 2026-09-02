import os

from scam_detector import analyze_transcript
from voice_detector import analyze_voice


def analyze_live_audio(
    audio_path,
    whisper_model
):

    if not os.path.exists(audio_path):
        raise FileNotFoundError(
            audio_path
        )


    transcription = (
        whisper_model.transcribe(
            audio_path,
            fp16=False
        )
    )


    transcript = (
        transcription
        .get("text", "")
        .strip()
    )


    scam_result = (
        analyze_transcript(
            transcript
        )
    )


    voice_result = (
        analyze_voice(
            audio_path
        )
    )


    return {
        "transcript": transcript,
        "scam_analysis": scam_result,
        "voice_analysis": voice_result
    }