import re


SCAM_PATTERNS = {

    # ==============================
    # OTP / SENSITIVE INFORMATION
    # ==============================

    "otp": {
        "weight": 25,
        "category": "Sensitive information",
        "severity": "high"
    },

    "one time password": {
        "weight": 25,
        "category": "Sensitive information",
        "severity": "high"
    },

    "verification code": {
        "weight": 20,
        "category": "Sensitive information",
        "severity": "high"
    },

    "share your code": {
        "weight": 25,
        "category": "Sensitive information",
        "severity": "high"
    },

    "cvv": {
        "weight": 25,
        "category": "Banking information",
        "severity": "high"
    },

    "pin number": {
        "weight": 25,
        "category": "Banking information",
        "severity": "high"
    },


    # ==============================
    # URGENCY
    # ==============================

    "urgent": {
        "weight": 12,
        "category": "Urgency",
        "severity": "medium"
    },

    "immediately": {
        "weight": 12,
        "category": "Urgency",
        "severity": "medium"
    },

    "right now": {
        "weight": 12,
        "category": "Urgency",
        "severity": "medium"
    },

    "act now": {
        "weight": 12,
        "category": "Urgency",
        "severity": "medium"
    },

    "quickly": {
        "weight": 8,
        "category": "Urgency",
        "severity": "low"
    },


    # ==============================
    # MONEY REQUESTS
    # ==============================

    "send money": {
        "weight": 25,
        "category": "Money request",
        "severity": "high"
    },

    "transfer money": {
        "weight": 25,
        "category": "Money request",
        "severity": "high"
    },

    "pay now": {
        "weight": 20,
        "category": "Money request",
        "severity": "high"
    },

    "make a payment": {
        "weight": 18,
        "category": "Money request",
        "severity": "high"
    },

    "bank transfer": {
        "weight": 18,
        "category": "Money request",
        "severity": "high"
    },


    # ==============================
    # ACCOUNT / FEAR TACTICS
    # ==============================

    "account blocked": {
        "weight": 18,
        "category": "Fear tactic",
        "severity": "high"
    },

    "account suspended": {
        "weight": 18,
        "category": "Fear tactic",
        "severity": "high"
    },

    "account locked": {
        "weight": 18,
        "category": "Fear tactic",
        "severity": "high"
    },

    "legal action": {
        "weight": 20,
        "category": "Threat",
        "severity": "high"
    },

    "police case": {
        "weight": 20,
        "category": "Threat",
        "severity": "high"
    },

    "arrest": {
        "weight": 18,
        "category": "Threat",
        "severity": "high"
    },


    # ==============================
    # SECRECY
    # ==============================

    "don't tell anyone": {
        "weight": 30,
        "category": "Secrecy",
        "severity": "high"
    },

    "do not tell anyone": {
        "weight": 30,
        "category": "Secrecy",
        "severity": "high"
    },

    "keep this secret": {
        "weight": 25,
        "category": "Secrecy",
        "severity": "high"
    },


    # ==============================
    # IMPERSONATION
    # ==============================

    "this is your bank": {
        "weight": 12,
        "category": "Impersonation",
        "severity": "medium"
    },

    "bank security department": {
        "weight": 15,
        "category": "Impersonation",
        "severity": "medium"
    },


    # ==============================
    # FAMILY / EMERGENCY SCAMS
    # ==============================

    "i am in trouble": {
        "weight": 12,
        "category": "Emergency pressure",
        "severity": "medium"
    },

    "emergency": {
        "weight": 10,
        "category": "Emergency pressure",
        "severity": "medium"
    },

    "help me": {
        "weight": 8,
        "category": "Emergency pressure",
        "severity": "low"
    },

    "your son": {
        "weight": 8,
        "category": "Family impersonation",
        "severity": "medium"
    },

    "your daughter": {
        "weight": 8,
        "category": "Family impersonation",
        "severity": "medium"
    }
}


# ==========================================
# DETECT SCAM PATTERNS
# ==========================================

def detect_scam_patterns(transcript):

    if not transcript:

        return {
            "score": 0,
            "detected_keywords": [],
            "categories": []
        }


    text = transcript.lower()


    score = 0

    detected_keywords = []

    categories = set()


    # --------------------------------------
    # CHECK INDIVIDUAL SCAM PATTERNS
    # --------------------------------------

    for phrase, information in SCAM_PATTERNS.items():

        pattern = (
            r"\b"
            +
            re.escape(phrase)
            +
            r"\b"
        )


        if re.search(
            pattern,
            text
        ):

            score += information["weight"]


            detected_keywords.append({

                "keyword":
                    phrase,

                "category":
                    information["category"],

                "severity":
                    information["severity"],

                "weight":
                    information["weight"]

            })


            categories.add(
                information["category"]
            )


    # --------------------------------------
    # COMBINATION ANALYSIS
    # --------------------------------------

    has_money_request = any(

        item["category"]
        ==
        "Money request"

        for item in detected_keywords

    )


    has_urgency = any(

        item["category"]
        ==
        "Urgency"

        for item in detected_keywords

    )


    has_sensitive_request = any(

        item["category"]

        in [

            "Sensitive information",

            "Banking information"

        ]

        for item in detected_keywords

    )


    has_threat = any(

        item["category"]
        ==
        "Threat"

        for item in detected_keywords

    )


    has_secrecy = any(

        item["category"]
        ==
        "Secrecy"

        for item in detected_keywords

    )


    # --------------------------------------
    # DANGEROUS COMBINATIONS
    # --------------------------------------

    if (

        has_money_request

        and

        has_urgency

    ):

        score += 15


    if (

        has_money_request

        and

        has_sensitive_request

    ):

        score += 20


    if (

        has_urgency

        and

        has_sensitive_request

    ):

        score += 15


    if (

        has_threat

        and

        has_urgency

    ):

        score += 15


    if (

        has_secrecy

        and

        has_money_request

    ):

        score += 20


    score = min(
        score,
        100
    )


    return {

        "score":
            score,

        "detected_keywords":
            detected_keywords,

        "categories":
            list(categories)

    }


# ==========================================
# MAIN TRANSCRIPT ANALYZER
# ==========================================

def analyze_transcript(transcript):

    detection = detect_scam_patterns(
        transcript
    )


    score = detection["score"]


    # --------------------------------------
    # RISK LEVEL
    # --------------------------------------

    if score >= 70:

        risk_level = "HIGH"

        message = (

            "Multiple strong scam indicators "
            "were detected. Do not share money, "
            "OTPs, passwords, PINs, or banking "
            "information."

        )


    elif score >= 35:

        risk_level = "MEDIUM"

        message = (

            "Suspicious language was detected. "
            "Verify the caller through an "
            "independent method before taking action."

        )


    else:

        risk_level = "LOW"

        message = (

            "No major scam language was detected. "
            "However, automated analysis cannot "
            "guarantee that a call is safe."

        )


    return {

        "transcript":
            transcript,

        "scam_score":
            score,

        "risk_level":
            risk_level,

        "detected_keywords":
            detection["detected_keywords"],

        "categories":
            detection["categories"],

        "message":
            message

    }


# ==========================================
# QUICK TEST
# ==========================================

if __name__ == "__main__":

    test_text = """

    Hello, this is your bank security department.

    Your account has been blocked.

    You must act immediately.

    Please send money to verify your account
    and share your OTP.

    Do not tell anyone about this call.

    """


    result = analyze_transcript(
        test_text
    )


    print()
    print("=" * 50)
    print("VOICE SHIELD SCAM DETECTOR TEST")
    print("=" * 50)

    print()

    print(
        "Risk:",
        result["risk_level"]
    )

    print(
        "Score:",
        result["scam_score"],
        "/ 100"
    )

    print()

    print(
        "Detected indicators:"
    )

    for item in result[
        "detected_keywords"
    ]:

        print(

            "-",

            item["keyword"],

            "|",

            item["category"],

            "| weight:",

            item["weight"]

        )

    print()

    print(
        result["message"]
    )

    print()