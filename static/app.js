let selectedAudioFile = null;
let lastAnalysis = null;

let mediaRecorder = null;
let liveStream = null;
let liveChunks = [];
let liveTimerInterval = null;
let liveSeconds = 0;


const analysisForm =
    document.getElementById("analysisForm");

const dropZone =
    document.getElementById("dropZone");

const audioFile =
    document.getElementById("audioFile");

const chooseFileButton =
    document.getElementById("chooseFileButton");

const selectedFile =
    document.getElementById("selectedFile");

const analyzeButton =
    document.getElementById("analyzeButton");

const loadingSection =
    document.getElementById("loadingSection");

const errorSection =
    document.getElementById("errorSection");

const errorMessage =
    document.getElementById("errorMessage");

const resultsSection =
    document.getElementById("resultsSection");


function showLoading(show) {
    if (!loadingSection) return;

    loadingSection.classList.toggle(
        "hidden",
        !show
    );
}


function showError(message) {
    if (!errorSection) return;

    errorMessage.textContent = message;

    errorSection.classList.remove(
        "hidden"
    );
}


function clearError() {
    if (!errorSection) return;

    errorSection.classList.add(
        "hidden"
    );

    errorMessage.textContent = "";
}


function selectFile(file) {
    if (!file) return;

    selectedAudioFile = file;

    selectedFile.textContent =
        "Selected: " + file.name;
}


if (chooseFileButton) {
    chooseFileButton.addEventListener(
        "click",
        function () {
            audioFile.click();
        }
    );
}


if (audioFile) {
    audioFile.addEventListener(
        "change",
        function () {
            if (this.files.length > 0) {
                selectFile(
                    this.files[0]
                );
            }
        }
    );
}


if (dropZone) {
    dropZone.addEventListener(
        "dragover",
        function (event) {
            event.preventDefault();

            dropZone.classList.add(
                "dragover"
            );
        }
    );

    dropZone.addEventListener(
        "dragleave",
        function () {
            dropZone.classList.remove(
                "dragover"
            );
        }
    );

    dropZone.addEventListener(
        "drop",
        function (event) {
            event.preventDefault();

            dropZone.classList.remove(
                "dragover"
            );

            const files =
                event.dataTransfer.files;

            if (files.length > 0) {
                selectFile(
                    files[0]
                );
            }
        }
    );
}


function displayAnalysisResults(data) {
    lastAnalysis = data;

    const scam =
        data.scam_analysis || {};

    const voice =
        data.voice_analysis || {};

    const final =
        data.final_analysis || {};


    resultsSection.classList.remove(
        "hidden"
    );


    const riskBadge =
        document.getElementById(
            "riskBadge"
        );

    const riskLevel =
        final.risk_level ||
        "UNKNOWN";


    riskBadge.textContent =
        riskLevel;


    riskBadge.className =
        "risk-badge " +
        riskLevel.toLowerCase();


    document.getElementById(
        "riskScore"
    ).textContent =
        final.final_score ??
        0;


    document.getElementById(
        "riskTitle"
    ).textContent =
        riskLevel === "CRITICAL"
            ? "Critical Risk"
            : riskLevel === "HIGH"
            ? "High Risk"
            : riskLevel === "MEDIUM"
            ? "Medium Risk"
            : riskLevel === "LOW"
            ? "Low Risk"
            : "Unknown Risk";


    document.getElementById(
        "riskMessage"
    ).textContent =
        final.message ||
        "No risk message available.";


    document.getElementById(
        "transcript"
    ).textContent =
        data.transcript ||
        "No speech was detected.";


    document.getElementById(
        "scamScore"
    ).textContent =
        (scam.scam_score ?? 0) +
        "%";


    document.getElementById(
        "voiceScore"
    ).textContent =
        (voice.fake_probability ?? 0) +
        "%";


    document.getElementById(
        "voiceResult"
    ).textContent =
        voice.voice_result ||
        "UNKNOWN";


    document.getElementById(
        "recommendation"
    ).textContent =
        final.recommendation ||
        "No recommendation available.";


    const indicatorsList =
        document.getElementById(
            "indicatorsList"
        );

    indicatorsList.innerHTML = "";


    const keywords =
        scam.detected_keywords || [];

    const categories =
        scam.categories || [];


    if (
        keywords.length === 0 &&
        categories.length === 0
    ) {
        indicatorsList.innerHTML =
            '<span class="indicator">No major indicators</span>';
    }


    keywords.forEach(
        function (keyword) {
            const element =
                document.createElement(
                    "span"
                );

            element.className =
                "indicator";

            element.textContent =
                keyword;

            indicatorsList.appendChild(
                element
            );
        }
    );


    categories.forEach(
        function (category) {
            const element =
                document.createElement(
                    "span"
                );

            element.className =
                "indicator";

            element.textContent =
                category;

            indicatorsList.appendChild(
                element
            );
        }
    );


    const whyList =
        document.getElementById(
            "whyFlaggedList"
        );

    whyList.innerHTML = "";


    const reasons =
        final.why_flagged || [];


    reasons.forEach(
        function (reason) {
            const li =
                document.createElement(
                    "li"
                );

            li.textContent =
                reason;

            whyList.appendChild(
                li
            );
        }
    );


    resultsSection.scrollIntoView({
        behavior: "smooth"
    });
}


if (analysisForm) {
    analysisForm.addEventListener(
        "submit",
        async function (event) {
            event.preventDefault();

            clearError();

            if (!selectedAudioFile) {
                showError(
                    "Please select an audio recording first."
                );
                return;
            }


            const formData =
                new FormData();

            formData.append(
                "audio",
                selectedAudioFile
            );


            analyzeButton.disabled =
                true;

            showLoading(true);


            try {
                const response =
                    await fetch(
                        "/analyze",
                        {
                            method: "POST",
                            body: formData
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok ||
                    !data.success) {
                    throw new Error(
                        data.error ||
                        "Analysis failed."
                    );
                }


                displayAnalysisResults(
                    data
                );

            } catch (error) {
                showError(
                    error.message
                );
            } finally {
                analyzeButton.disabled =
                    false;

                showLoading(false);
            }
        }
    );
}


function updateTimer() {
    const timer =
        document.getElementById(
            "liveTimer"
        );

    if (!timer) return;

    const minutes =
        String(
            Math.floor(
                liveSeconds / 60
            )
        ).padStart(2, "0");

    const seconds =
        String(
            liveSeconds % 60
        ).padStart(2, "0");

    timer.textContent =
        minutes + ":" + seconds;
}


function startTimer() {
    liveSeconds = 0;

    updateTimer();

    clearInterval(
        liveTimerInterval
    );

    liveTimerInterval =
        setInterval(
            function () {
                liveSeconds++;

                updateTimer();
            },
            1000
        );
}


function stopTimer() {
    clearInterval(
        liveTimerInterval
    );

    liveTimerInterval = null;
}


async function analyzeLiveRecording() {
    const status =
        document.getElementById(
            "liveStatus"
        );

    try {
        const blob =
            new Blob(
                liveChunks,
                {
                    type:
                        "audio/webm"
                }
            );


        if (blob.size === 0) {
            throw new Error(
                "The microphone recording was empty."
            );
        }


        status.textContent =
            "Processing live voice...";


        showLoading(true);


        const formData =
            new FormData();

        formData.append(
            "audio",
            blob,
            "live_recording.webm"
        );


        const response =
            await fetch(
                "/analyze-live",
                {
                    method: "POST",
                    body: formData
                }
            );


        const data =
            await response.json();


        if (!response.ok ||
            !data.success) {
            throw new Error(
                data.error ||
                "Live analysis failed."
            );
        }


        displayAnalysisResults(
            data
        );


        status.textContent =
            "✅ Live voice analysis complete.";

    } catch (error) {
        status.textContent =
            "❌ " + error.message;

        showError(
            error.message
        );

    } finally {
        showLoading(false);
    }
}


const liveRecordButton =
    document.getElementById(
        "liveRecordButton"
    );

const stopRecordButton =
    document.getElementById(
        "stopRecordButton"
    );


if (
    liveRecordButton &&
    stopRecordButton
) {
    liveRecordButton.addEventListener(
        "click",
        async function () {
            try {
                if (
                    !navigator.mediaDevices ||
                    !navigator.mediaDevices.getUserMedia
                ) {
                    throw new Error(
                        "Your browser does not support microphone access."
                    );
                }


                liveStream =
                    await navigator.mediaDevices.getUserMedia(
                        {
                            audio: true
                        }
                    );


                liveChunks = [];


                let mimeType =
                    "audio/webm;codecs=opus";


                if (
                    !MediaRecorder.isTypeSupported(
                        mimeType
                    )
                ) {
                    mimeType =
                        "audio/webm";
                }


                mediaRecorder =
                    new MediaRecorder(
                        liveStream,
                        {
                            mimeType
                        }
                    );


                mediaRecorder.addEventListener(
                    "dataavailable",
                    function (event) {
                        if (
                            event.data &&
                            event.data.size > 0
                        ) {
                            liveChunks.push(
                                event.data
                            );
                        }
                    }
                );


                mediaRecorder.addEventListener(
                    "stop",
                    analyzeLiveRecording
                );


                mediaRecorder.start();


                liveRecordButton.disabled =
                    true;

                stopRecordButton.disabled =
                    false;


                document.getElementById(
                    "liveStatus"
                ).textContent =
                    "🔴 Recording... Speak normally.";


                startTimer();

            } catch (error) {
                showError(
                    error.message
                );
            }
        }
    );


    stopRecordButton.addEventListener(
        "click",
        function () {
            if (
                mediaRecorder &&
                mediaRecorder.state !==
                    "inactive"
            ) {
                mediaRecorder.stop();
            }


            if (liveStream) {
                liveStream
                    .getTracks()
                    .forEach(
                        function (track) {
                            track.stop();
                        }
                    );
            }


            stopTimer();


            liveRecordButton.disabled =
                false;

            stopRecordButton.disabled =
                true;


            document.getElementById(
                "liveStatus"
            ).textContent =
                "Processing recording...";
        }
    );
}


const generateReportButton =
    document.getElementById(
        "generateReportButton"
    );


if (generateReportButton) {
    generateReportButton.addEventListener(
        "click",
        async function () {
            if (!lastAnalysis) {
                showError(
                    "Analyze an audio recording before generating a report."
                );

                return;
            }


            generateReportButton.disabled =
                true;


            try {
                const scam =
                    lastAnalysis.scam_analysis ||
                    {};

                const voice =
                    lastAnalysis.voice_analysis ||
                    {};

                const final =
                    lastAnalysis.final_analysis ||
                    {};


                const payload = {
                    caller_name:
                        document.getElementById(
                            "callerName"
                        ).value ||
                        "Unknown",

                    caller_number:
                        document.getElementById(
                            "callerNumber"
                        ).value ||
                        "Not available",

                    analysis_mode:
                        lastAnalysis.analysis_mode ||
                        "Audio Upload",

                    transcript:
                        lastAnalysis.transcript ||
                        "",

                    risk_score:
                        final.final_score ||
                        0,

                    risk_level:
                        final.risk_level ||
                        "UNKNOWN",

                    why_flagged:
                        final.why_flagged ||
                        [],

                    detection_result:
                        final.detection_result ||
                        "Unknown",

                    recommendation:
                        final.recommendation ||
                        "",

                    scam_analysis:
                        scam,

                    voice_analysis:
                        voice
                };


                const response =
                    await fetch(
                        "/generate-report",
                        {
                            method: "POST",
                            headers: {
                                "Content-Type":
                                    "application/json"
                            },
                            body:
                                JSON.stringify(
                                    payload
                                )
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok ||
                    !data.success) {
                    throw new Error(
                        data.error ||
                        "Report generation failed."
                    );
                }


                document.getElementById(
                    "reportId"
                ).textContent =
                    data.report_id;


                const reportLink =
                    document.getElementById(
                        "viewReportLink"
                    );


                reportLink.href =
                    data.report_url;


                document.getElementById(
                    "qrCode"
                ).src =
                    data.qr_code;


                document.getElementById(
                    "reportResult"
                ).classList.remove(
                    "hidden"
                );


                generateReportButton.textContent =
                    "✅ Report Generated";

            } catch (error) {
                showError(
                    error.message
                );

                generateReportButton.disabled =
                    false;
            }
        }
    );
}