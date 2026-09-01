import os
import json
import uuid
import qrcode
from datetime import datetime


REPORT_FOLDER = "reports"

os.makedirs(REPORT_FOLDER, exist_ok=True)


def generate_report(data):

    report_id = "VS-" + datetime.now().strftime("%Y%m%d-%H%M%S")

    report = {
        "report_id": report_id,
        "date_time": datetime.now().strftime("%d-%m-%Y %I:%M:%S %p"),

        "caller_information": {
            "caller_name": data.get("caller_name", "Unknown"),
            "caller_number": data.get("caller_number", "Not available")
        },

        "analysis_mode": data.get(
            "analysis_mode",
            "Audio Upload"
        ),

        "transcript": data.get(
            "transcript",
            ""
        ),

        "risk_score": data.get(
            "risk_score",
            0
        ),

        "risk_level": data.get(
            "risk_level",
            "UNKNOWN"
        ),

        "why_flagged": data.get(
            "why_flagged",
            []
        ),

        "detection_result": data.get(
            "detection_result",
            "Unknown"
        ),

        "recommendation": data.get(
            "recommendation",
            ""
        )
    }


    # Save JSON report

    report_path = os.path.join(
        REPORT_FOLDER,
        report_id + ".json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )


    # Generate QR code

    qr_data = (
        "http://127.0.0.1:5000/report/"
        + report_id
    )

    qr = qrcode.make(qr_data)

    qr_path = os.path.join(
        REPORT_FOLDER,
        report_id + "_qr.png"
    )

    qr.save(qr_path)


    return {
        "report_id": report_id,
        "report": report,
        "qr_code": "/" + qr_path.replace("\\", "/")
    }