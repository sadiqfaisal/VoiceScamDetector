import os
import re
import json
import base64
import uuid
import tempfile
from pathlib import Path

import streamlit as st
import qrcode

from jinja2 import Template

from app import (
    transcribe_audio,
    build_final_analysis,
    allowed_file,
    get_whisper_model,
)
from scam_detector import analyze_transcript
from voice_detector import analyze_voice
from live_analyzer import analyze_live_audio
from report_generator import generate_report
from database import (
    initialize_database,
    save_incident_report,
    get_incident_report,
    get_all_incident_reports,
)


# ============================================================
# STREAMLIT PAGE
# ============================================================

st.set_page_config(
    page_title="VoiceShield | AI Voice Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

initialize_database()


# ============================================================
# STREAMLIT UI CLEANUP
# ============================================================

st.markdown(
    """
    <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}

        [data-testid="stHeader"] {
            display: none !important;
        }

        [data-testid="stToolbar"] {
            display: none !important;
        }

        section.main > div.block-container {
            padding: 0 !important;
            max-width: 100% !important;
        }

        [data-testid="stAppViewContainer"] {
            background: transparent !important;
        }

        [data-testid="stDecoration"] {
            display: none !important;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# TEMPLATE HELPERS
# ============================================================

def extract_body(html):
    match = re.search(
        r"<body[^>]*>(.*?)</body>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if match:
        return match.group(1)

    return html


def extract_inline_css(html):
    styles = re.findall(
        r"<style[^>]*>(.*?)</style>",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )

    return "\n".join(styles)


def clean_template(source):
    source = re.sub(
        r'<link[^>]+href="\{\{\s*url_for\(\'static\'.*?\}\}"[^>]*>',
        "",
        source,
        flags=re.IGNORECASE | re.DOTALL,
    )

    source = re.sub(
        r'<script[^>]*src="\{\{\s*url_for\(\'static\'.*?\}\}"[^>]*>\s*</script>',
        "",
        source,
        flags=re.IGNORECASE | re.DOTALL,
    )

    source = re.sub(
        r'<script[^>]*src="\{\{\s*url_for\(\'static\'.*?\}\}"[^>]*></script>',
        "",
        source,
        flags=re.IGNORECASE | re.DOTALL,
    )

    return source


def render_template_file(filename, context=None):
    path = TEMPLATES_DIR / filename

    source = path.read_text(encoding="utf-8-sig")
    source = clean_template(source)

    template = Template(source)

    rendered = template.render(**(context or {}))

    return extract_body(rendered)


def load_dashboard_html():
    source = (
        TEMPLATES_DIR / "index.html"
    ).read_text(encoding="utf-8-sig")

    source = clean_template(source)

    template = Template(source)

    rendered = template.render()

    return extract_body(rendered)


def load_dashboard_inline_css():
    source = (
        TEMPLATES_DIR / "index.html"
    ).read_text(encoding="utf-8-sig")

    return extract_inline_css(source)


GLOBAL_CSS = (
    STATIC_DIR / "style.css"
).read_text(encoding="utf-8-sig")

INLINE_CSS = load_dashboard_inline_css()


# ============================================================
# PAGE DATA
# ============================================================

def build_home_page():
    return load_dashboard_html()


def build_history_page():
    reports = get_all_incident_reports()

    return render_template_file(
        "history.html",
        {
            "reports": reports
        },
    )


def make_qr_data_uri(qr_path):
    if not qr_path:
        return ""

    path = Path(qr_path)

    if not path.exists():
        return ""

    raw = path.read_bytes()

    encoded = base64.b64encode(raw).decode("ascii")

    return "data:image/png;base64," + encoded


def build_report_page(report):
    html = render_template_file(
        "report.html",
        {
            "report": report
        },
    )

    qr_path = report.get("qr_code_path", "")

    if not qr_path:
        qr_path = report.get("qr_path", "")

    qr_uri = make_qr_data_uri(qr_path)

    if qr_uri:
        html = re.sub(
            r'src="/report/[^"]+/qr"',
            'src="' + qr_uri + '"',
            html,
        )

    return html


# ============================================================
# PUBLIC REPORT URL
# ============================================================

def get_public_base_url():
    try:
        headers = st.context.headers

        host = headers.get("Host")

        if not host:
            return ""

        proto = (
            headers.get("X-Forwarded-Proto")
            or "https"
        )

        return f"{proto}://{host}"

    except Exception:
        return ""


def make_streamlit_report_url(report_id):
    base = get_public_base_url()

    if not base:
        return f"?report={report_id}"

    return (
        base.rstrip("/")
        + "/?report="
        + report_id
    )


# ============================================================
# AUDIO HELPERS
# ============================================================

def decode_audio_payload(filename, encoded):
    if not filename or not encoded:
        raise ValueError("No audio recording received.")

    try:
        raw = base64.b64decode(
            encoded,
            validate=True,
        )
    except Exception as error:
        raise ValueError(
            "The uploaded audio data could not be decoded."
        ) from error

    if not raw:
        raise ValueError(
            "The uploaded audio recording is empty."
        )

    if len(raw) > 25 * 1024 * 1024:
        raise ValueError(
            "Audio file is larger than the 25 MB limit."
        )

    return raw


def save_temp_audio(raw, filename):
    extension = Path(filename).suffix.lower()

    if not extension:
        extension = ".webm"

    safe_name = (
        uuid.uuid4().hex
        + extension
    )

    path = UPLOAD_DIR / safe_name

    path.write_bytes(raw)

    return path


# ============================================================
# ANALYSIS
# ============================================================

def process_uploaded_audio(
    filename,
    encoded,
):
    if not allowed_file(filename):
        raise ValueError(
            "Unsupported audio format. "
            "Use WAV, MP3, M4A, OGG, FLAC or WebM."
        )

    raw = decode_audio_payload(
        filename,
        encoded,
    )

    file_path = save_temp_audio(
        raw,
        filename,
    )

    try:
        transcript = transcribe_audio(
            str(file_path)
        )

        scam_analysis = analyze_transcript(
            transcript
        )

        voice_analysis = analyze_voice(
            str(file_path)
        )

        final_analysis = build_final_analysis(
            scam_analysis,
            voice_analysis,
        )

        return {
            "success": True,
            "analysis_id": uuid.uuid4().hex,
            "analysis_mode": "Audio Upload",
            "transcript": transcript,
            "scam_analysis": scam_analysis,
            "voice_analysis": voice_analysis,
            "final_analysis": final_analysis,
        }

    finally:
        try:
            file_path.unlink(
                missing_ok=True
            )
        except Exception:
            pass


def process_live_audio(encoded):
    raw = decode_audio_payload(
        "live_recording.webm",
        encoded,
    )

    file_path = save_temp_audio(
        raw,
        "live_recording.webm",
    )

    try:
        model = get_whisper_model()

        result = analyze_live_audio(
            str(file_path),
            model,
        )

        final_analysis = build_final_analysis(
            result["scam_analysis"],
            result["voice_analysis"],
        )

        return {
            "success": True,
            "analysis_id": uuid.uuid4().hex,
            "analysis_mode": "Live Microphone",
            "transcript": result["transcript"],
            "scam_analysis": result["scam_analysis"],
            "voice_analysis": result["voice_analysis"],
            "final_analysis": final_analysis,
        }

    finally:
        try:
            file_path.unlink(
                missing_ok=True
            )
        except Exception:
            pass


# ============================================================
# REPORT GENERATION
# ============================================================

def create_report(analysis):
    report_input = {
        "caller_name": analysis.get(
            "caller_name",
            "Unknown",
        ),
        "caller_number": analysis.get(
            "caller_number",
            "Not available",
        ),
        "analysis_mode": analysis.get(
            "analysis_mode",
            "Audio Upload",
        ),
        "transcript": analysis.get(
            "transcript",
            "",
        ),
        "risk_score": analysis.get(
            "final_analysis",
            {},
        ).get(
            "final_score",
            0,
        ),
        "risk_level": analysis.get(
            "final_analysis",
            {},
        ).get(
            "risk_level",
            "UNKNOWN",
        ),
        "why_flagged": analysis.get(
            "final_analysis",
            {},
        ).get(
            "why_flagged",
            [],
        ),
        "detection_result": analysis.get(
            "final_analysis",
            {},
        ).get(
            "detection_result",
            "Unknown",
        ),
        "recommendation": analysis.get(
            "final_analysis",
            {},
        ).get(
            "recommendation",
            "",
        ),
        "scam_analysis": analysis.get(
            "scam_analysis",
            {},
        ),
        "voice_analysis": analysis.get(
            "voice_analysis",
            {},
        ),
    }

    result = generate_report(
        report_input
    )

    report = result["report"]

    # The original Flask application generated
    # its QR code from a Flask /report/... URL.
    # Replace that QR with the real Streamlit URL.
    streamlit_url = make_streamlit_report_url(
        result["report_id"]
    )

    qr = qrcode.make(
        streamlit_url
    )

    qr_path = REPORT_DIR / (
        result["report_id"]
        + "_qr.png"
    )

    qr.save(qr_path)

    result["qr_path"] = str(qr_path)

    save_incident_report(
        report,
        result["report_path"],
        str(qr_path),
    )

    return {
        "success": True,
        "report_id": result["report_id"],
        "report_url": (
            "?report="
            + result["report_id"]
        ),
        "qr_code": str(qr_path),
        "report": report,
    }


# ============================================================
# FRONTEND BRIDGE JAVASCRIPT
# ============================================================

BRIDGE_JS = r"""
export default function(component) {
    const {
        parentElement,
        data,
        setTriggerValue
    } = component;

    const root = parentElement.querySelector("#voiceshield-root");

    if (!root) {
        return;
    }

    const page = data?.page || "home";
    const pageHtml = data?.page_html || "";

    if (
        root.dataset.page !== page ||
        root.dataset.rendered !== "true"
    ) {
        root.innerHTML = pageHtml;
        root.dataset.page = page;
        root.dataset.rendered = "true";
    }

    function setLoading(show) {
        const loading = root.querySelector("#loadingSection");

        if (loading) {
            loading.classList.toggle(
                "hidden",
                !show
            );
        }
    }

    function showError(message) {
        const section = root.querySelector("#errorSection");
        const text = root.querySelector("#errorMessage");

        if (text) {
            text.textContent = message;
        }

        if (section) {
            section.classList.remove("hidden");
        }
    }

    function clearError() {
        const section = root.querySelector("#errorSection");
        const text = root.querySelector("#errorMessage");

        if (section) {
            section.classList.add("hidden");
        }

        if (text) {
            text.textContent = "";
        }
    }

    function displayAnalysisResults(result) {
        const scam = result.scam_analysis || {};
        const voice = result.voice_analysis || {};
        const final = result.final_analysis || {};

        const resultsSection =
            root.querySelector("#resultsSection");

        if (!resultsSection) {
            return;
        }

        resultsSection.classList.remove("hidden");

        const riskLevel =
            final.risk_level || "UNKNOWN";

        const riskBadge =
            root.querySelector("#riskBadge");

        if (riskBadge) {
            riskBadge.textContent = riskLevel;
            riskBadge.className =
                "risk-badge " +
                riskLevel.toLowerCase();
        }

        const riskScore =
            root.querySelector("#riskScore");

        if (riskScore) {
            riskScore.textContent =
                final.final_score ?? 0;
        }

        const riskTitle =
            root.querySelector("#riskTitle");

        if (riskTitle) {
            riskTitle.textContent =
                riskLevel === "CRITICAL"
                    ? "Critical Risk"
                    : riskLevel === "HIGH"
                    ? "High Risk"
                    : riskLevel === "MEDIUM"
                    ? "Medium Risk"
                    : riskLevel === "LOW"
                    ? "Low Risk"
                    : "Unknown Risk";
        }

        const riskMessage =
            root.querySelector("#riskMessage");

        if (riskMessage) {
            riskMessage.textContent =
                final.message ||
                "No risk message available.";
        }

        const transcript =
            root.querySelector("#transcript");

        if (transcript) {
            transcript.textContent =
                result.transcript ||
                "No speech was detected.";
        }

        const scamScore =
            root.querySelector("#scamScore");

        if (scamScore) {
            scamScore.textContent =
                (scam.scam_score ?? 0) + "%";
        }

        const voiceScore =
            root.querySelector("#voiceScore");

        if (voiceScore) {
            voiceScore.textContent =
                (voice.fake_probability ?? 0) + "%";
        }

        const voiceResult =
            root.querySelector("#voiceResult");

        if (voiceResult) {
            voiceResult.textContent =
                voice.voice_result ||
                "UNKNOWN";
        }

        const recommendation =
            root.querySelector("#recommendation");

        if (recommendation) {
            recommendation.textContent =
                final.recommendation ||
                "No recommendation available.";
        }

        const indicators =
            root.querySelector("#indicatorsList");

        if (indicators) {
            indicators.innerHTML = "";

            const keywords =
                scam.detected_keywords || [];

            const categories =
                scam.categories || [];

            if (
                keywords.length === 0 &&
                categories.length === 0
            ) {
                const item =
                    document.createElement("span");

                item.className = "indicator";
                item.textContent =
                    "No major indicators";

                indicators.appendChild(item);
            }

            [
                ...keywords,
                ...categories
            ].forEach((value) => {
                const item =
                    document.createElement("span");

                item.className = "indicator";
                item.textContent = value;

                indicators.appendChild(item);
            });
        }

        const why =
            root.querySelector("#whyFlaggedList");

        if (why) {
            why.innerHTML = "";

            (
                final.why_flagged || []
            ).forEach((reason) => {
                const li =
                    document.createElement("li");

                li.textContent = reason;

                why.appendChild(li);
            });
        }

        resultsSection.scrollIntoView({
            behavior: "smooth"
        });
    }

    function bytesToBase64(buffer) {
        let binary = "";

        const bytes =
            new Uint8Array(buffer);

        const chunkSize = 0x8000;

        for (
            let i = 0;
            i < bytes.length;
            i += chunkSize
        ) {
            binary += String.fromCharCode(
                ...bytes.subarray(
                    i,
                    Math.min(
                        i + chunkSize,
                        bytes.length
                    )
                )
            );
        }

        return btoa(binary);
    }

    function bindNavigation() {
        root.querySelectorAll("a").forEach((link) => {
            if (link.dataset.vsBound === "1") {
                return;
            }

            link.dataset.vsBound = "1";

            const href =
                link.getAttribute("href");

            if (!href) {
                return;
            }

            if (
                href === "/" ||
                href === "/history" ||
                href.startsWith("/report/")
            ) {
                link.addEventListener(
                    "click",
                    (event) => {
                        event.preventDefault();

                        if (
                            href === "/" ||
                            href === "/history"
                        ) {
                            setTriggerValue(
                                "action",
                                {
                                    type:
                                        href === "/"
                                            ? "home"
                                            : "history"
                                }
                            );

                            return;
                        }

                        const match =
                            href.match(
                                /\/report\/(.+)$/
                            );

                        if (match) {
                            setTriggerValue(
                                "action",
                                {
                                    type: "report",
                                    report_id:
                                        match[1]
                                }
                            );
                        }
                    }
                );
            }
        });
    }

    function bindHome() {
        const form =
            root.querySelector("#analysisForm");

        const fileInput =
            root.querySelector("#audioFile");

        const chooseButton =
            root.querySelector(
                "#chooseFileButton"
            );

        const dropZone =
            root.querySelector("#dropZone");

        const selectedFile =
            root.querySelector("#selectedFile");

        let selectedAudioFile = null;

        if (
            !form ||
            !fileInput ||
            !chooseButton
        ) {
            return;
        }

        chooseButton.addEventListener(
            "click",
            () => fileInput.click()
        );

        fileInput.addEventListener(
            "change",
            () => {
                if (fileInput.files.length) {
                    selectedAudioFile =
                        fileInput.files[0];

                    selectedFile.textContent =
                        "Selected: " +
                        selectedAudioFile.name;
                }
            }
        );

        if (dropZone) {
            dropZone.addEventListener(
                "dragover",
                (event) => {
                    event.preventDefault();

                    dropZone.classList.add(
                        "dragover"
                    );
                }
            );

            dropZone.addEventListener(
                "dragleave",
                () => {
                    dropZone.classList.remove(
                        "dragover"
                    );
                }
            );

            dropZone.addEventListener(
                "drop",
                (event) => {
                    event.preventDefault();

                    dropZone.classList.remove(
                        "dragover"
                    );

                    const files =
                        event.dataTransfer.files;

                    if (files.length) {
                        selectedAudioFile =
                            files[0];

                        selectedFile.textContent =
                            "Selected: " +
                            selectedAudioFile.name;
                    }
                }
            );
        }

        form.addEventListener(
            "submit",
            async (event) => {
                event.preventDefault();

                clearError();

                if (!selectedAudioFile) {
                    showError(
                        "Please select an audio recording first."
                    );

                    return;
                }

                const callerName =
                    root.querySelector(
                        "#callerName"
                    )?.value || "";

                const callerNumber =
                    root.querySelector(
                        "#callerNumber"
                    )?.value || "";

                const analyzeButton =
                    root.querySelector(
                        "#analyzeButton"
                    );

                if (analyzeButton) {
                    analyzeButton.disabled = true;
                }

                setLoading(true);

                try {
                    const buffer =
                        await selectedAudioFile.arrayBuffer();

                    const encoded =
                        bytesToBase64(buffer);

                    setTriggerValue(
                        "action",
                        {
                            type: "analyze",
                            filename:
                                selectedAudioFile.name,
                            content_base64:
                                encoded,
                            caller_name:
                                callerName,
                            caller_number:
                                callerNumber
                        }
                    );
                } catch (error) {
                    setLoading(false);

                    showError(
                        error.message ||
                        "Unable to read the audio file."
                    );

                    if (analyzeButton) {
                        analyzeButton.disabled = false;
                    }
                }
            }
        );

        const reportButton =
            root.querySelector(
                "#generateReportButton"
            );

        if (reportButton) {
            reportButton.addEventListener(
                "click",
                () => {
                    setTriggerValue(
                        "action",
                        {
                            type: "generate_report"
                        }
                    );
                }
            );
        }

        bindLiveRecorder();
    }

    function bindLiveRecorder() {
        const startButton =
            root.querySelector(
                "#liveRecordButton"
            );

        const stopButton =
            root.querySelector(
                "#stopRecordButton"
            );

        const timer =
            root.querySelector(
                "#liveTimer"
            );

        const status =
            root.querySelector(
                "#liveStatus"
            );

        if (!startButton || !stopButton) {
            return;
        }

        let recorder = null;
        let stream = null;
        let chunks = [];
        let seconds = 0;
        let interval = null;

        function updateTimer() {
            if (!timer) {
                return;
            }

            const minutes =
                String(
                    Math.floor(seconds / 60)
                ).padStart(2, "0");

            const secs =
                String(
                    seconds % 60
                ).padStart(2, "0");

            timer.textContent =
                minutes + ":" + secs;
        }

        startButton.addEventListener(
            "click",
            async () => {
                try {
                    stream =
                        await navigator.mediaDevices.getUserMedia(
                            { audio: true }
                        );

                    chunks = [];

                    recorder =
                        new MediaRecorder(
                            stream
                        );

                    recorder.ondataavailable =
                        (event) => {
                            if (
                                event.data &&
                                event.data.size > 0
                            ) {
                                chunks.push(
                                    event.data
                                );
                            }
                        };

                    recorder.onstop =
                        async () => {
                            try {
                                const blob =
                                    new Blob(
                                        chunks,
                                        {
                                            type:
                                                "audio/webm"
                                        }
                                    );

                                const buffer =
                                    await blob.arrayBuffer();

                                const encoded =
                                    bytesToBase64(
                                        buffer
                                    );

                                if (status) {
                                    status.textContent =
                                        "Processing live voice...";
                                }

                                setTriggerValue(
                                    "action",
                                    {
                                        type:
                                            "live_analyze",
                                        content_base64:
                                            encoded
                                    }
                                );
                            } catch (error) {
                                if (status) {
                                    status.textContent =
                                        error.message ||
                                        "Live analysis failed.";
                                }
                            }
                        };

                    recorder.start();

                    seconds = 0;
                    updateTimer();

                    clearInterval(interval);

                    interval =
                        setInterval(
                            () => {
                                seconds++;
                                updateTimer();
                            },
                            1000
                        );

                    startButton.disabled = true;
                    stopButton.disabled = false;

                    if (status) {
                        status.textContent =
                            "Recording microphone securely...";
                    }
                } catch (error) {
                    if (status) {
                        status.textContent =
                            "Microphone access was denied or unavailable.";
                    }
                }
            }
        );

        stopButton.addEventListener(
            "click",
            () => {
                if (!recorder) {
                    return;
                }

                recorder.stop();

                if (stream) {
                    stream
                        .getTracks()
                        .forEach(
                            (track) =>
                                track.stop()
                        );
                }

                clearInterval(interval);

                startButton.disabled = false;
                stopButton.disabled = true;
            }
        );
    }

    function restoreAnalysisState() {
        if (
            data?.analysis &&
            page === "home"
        ) {
            displayAnalysisResults(
                data.analysis
            );
        }

        if (
            data?.report_result &&
            page === "home"
        ) {
            const result =
                root.querySelector(
                    "#reportResult"
                );

            const id =
                root.querySelector(
                    "#reportId"
                );

            const link =
                root.querySelector(
                    "#viewReportLink"
                );

            const qr =
                root.querySelector(
                    "#qrCode"
                );

            if (result) {
                result.classList.remove(
                    "hidden"
                );
            }

            if (id) {
                id.textContent =
                    data.report_result.report_id;
            }

            if (link) {
                link.href =
                    data.report_result.report_url;
            }

            if (
                qr &&
                data.report_result.qr_data
            ) {
                qr.src =
                    data.report_result.qr_data;
            }
        }

        if (data?.error) {
            showError(data.error);
        }
    }

    bindNavigation();

    if (page === "home") {
        bindHome();
    }

    restoreAnalysisState();
}
"""


# ============================================================
# SESSION STATE
# ============================================================

if "vs_page" not in st.session_state:
    report_from_url = st.query_params.get(
        "report"
    )

    if report_from_url:
        st.session_state.vs_page = "report"
        st.session_state.vs_report_id = (
            report_from_url
        )
    else:
        st.session_state.vs_page = "home"

if "vs_analysis" not in st.session_state:
    st.session_state.vs_analysis = None

if "vs_report_result" not in st.session_state:
    st.session_state.vs_report_result = None

if "vs_error" not in st.session_state:
    st.session_state.vs_error = None


# ============================================================
# COMPONENT
# ============================================================

component_html = """
<div id="voiceshield-root"></div>
"""

component_css = (
    GLOBAL_CSS
    + "\n"
    + INLINE_CSS
    + """
    body {
        margin: 0 !important;
    }

    #voiceshield-root {
        width: 100%;
        min-height: 100vh;
    }

    .stApp {
        background: transparent !important;
    }
    """
)


voiceshield_component = st.components.v2.component(
    "voiceshield_dashboard",
    html=component_html,
    css=component_css,
    js=BRIDGE_JS,
    isolate_styles=False,
)


# ============================================================
# PYTHON -> FRONTEND DATA
# ============================================================

page = st.session_state.vs_page

if page == "home":
    page_html = build_home_page()

elif page == "history":
    page_html = build_history_page()

elif page == "report":
    report_id = st.session_state.get(
        "vs_report_id"
    )

    report_record = (
        get_incident_report(report_id)
        if report_id
        else None
    )

    if report_record:
        report_path = report_record.get(
            "report_path"
        )

        report = report_record

        if (
            report_path
            and Path(report_path).exists()
        ):
            try:
                report = json.loads(
                    Path(report_path).read_text(
                        encoding="utf-8"
                    )
                )
            except Exception:
                report = report_record

        page_html = build_report_page(
            report
        )
    else:
        page_html = """
        <main class="container">
            <section class="card">
                <h2>Report not found</h2>
                <p>The requested VoiceShield incident report does not exist.</p>
                <a class="primary-button" href="/">New Analysis</a>
            </section>
        </main>
        """

else:
    page_html = build_home_page()


# ============================================================
# REPORT RESULT QR
# ============================================================

report_result_for_frontend = (
    st.session_state.vs_report_result
)

if report_result_for_frontend:
    qr_data = make_qr_data_uri(
        report_result_for_frontend.get(
            "qr_code"
        )
    )

    report_result_for_frontend = {
        **report_result_for_frontend,
        "qr_data": qr_data,
    }


# ============================================================
# MOUNT
# ============================================================

result = voiceshield_component(
    data={
        "page": page,
        "page_html": page_html,
        "analysis": st.session_state.vs_analysis,
        "report_result":
            report_result_for_frontend,
        "error": st.session_state.vs_error,
    },
    on_action_change=lambda: None,
    key="voiceshield_main",
    width="stretch",
    height="content",
)


# ============================================================
# HANDLE FRONTEND EVENTS
# ============================================================

action = getattr(
    result,
    "action",
    None,
)


if action:
    action_type = action.get(
        "type"
    ) if isinstance(action, dict) else action

    # --------------------------------------------------------
    # NAVIGATION
    # --------------------------------------------------------

    if action_type == "home":
        st.session_state.vs_page = "home"
        st.session_state.vs_error = None
        st.query_params.clear()
        st.rerun()

    elif action_type == "history":
        st.session_state.vs_page = "history"
        st.session_state.vs_error = None
        st.query_params.clear()
        st.rerun()

    elif action_type == "report":
        report_id = action.get(
            "report_id"
        )

        st.session_state.vs_page = "report"
        st.session_state.vs_report_id = (
            report_id
        )

        st.query_params["report"] = (
            report_id
        )

        st.rerun()

    # --------------------------------------------------------
    # UPLOAD ANALYSIS
    # --------------------------------------------------------

    elif action_type == "analyze":
        try:
            st.session_state.vs_error = None

            analysis = process_uploaded_audio(
                action.get("filename", ""),
                action.get(
                    "content_base64",
                    "",
                ),
            )

            analysis["caller_name"] = action.get(
                "caller_name",
                "",
            )

            analysis["caller_number"] = action.get(
                "caller_number",
                "",
            )

            st.session_state.vs_analysis = (
                analysis
            )

            st.session_state.vs_report_result = (
                None
            )

        except Exception as error:
            st.session_state.vs_error = str(
                error
            )

        st.rerun()

    # --------------------------------------------------------
    # LIVE ANALYSIS
    # --------------------------------------------------------

    elif action_type == "live_analyze":
        try:
            st.session_state.vs_error = None

            analysis = process_live_audio(
                action.get(
                    "content_base64",
                    "",
                )
            )

            analysis["caller_name"] = ""
            analysis["caller_number"] = ""

            st.session_state.vs_analysis = (
                analysis
            )

            st.session_state.vs_report_result = (
                None
            )

        except Exception as error:
            st.session_state.vs_error = str(
                error
            )

        st.rerun()

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    elif action_type == "generate_report":
        try:
            if not st.session_state.vs_analysis:
                raise ValueError(
                    "Please complete an audio analysis before generating a report."
                )

            st.session_state.vs_error = None

            report_result = create_report(
                st.session_state.vs_analysis
            )

            st.session_state.vs_report_result = (
                report_result
            )

        except Exception as error:
            st.session_state.vs_error = str(
                error
            )

        st.rerun()
