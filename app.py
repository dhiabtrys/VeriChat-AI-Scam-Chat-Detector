from flask import Flask, render_template, request, send_file
import pickle
import re
import os
import uuid

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER


app = Flask(__name__)

# Maximum upload size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


# =========================================================
# LOAD AI MODEL
# =========================================================

try:
    model = pickle.load(open("scam_model.pkl", "rb"))
    vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
except Exception as e:
    print("Error loading model:", e)
    model = None
    vectorizer = None


# =========================================================
# TEXT CLEANING
# =========================================================

def clean_text(text):
    text = text.lower()
    text = re.sub(r"[^a-zA-Z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# =========================================================
# WHATSAPP MESSAGE VALIDATION
# =========================================================

def is_whatsapp_message(line):

    # Format:
    # [8/25/26, 10:30:15 PM] Ali: Hello

    pattern1 = r"^\[\d{1,2}/\d{1,2}/\d{2,4},\s*\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?\]\s*.*?:\s*.*"

    # Format:
    # 25/8/2026, 10:30 - Ali: Hello

    pattern2 = r"^\d{1,2}/\d{1,2}/\d{2,4},\s*\d{1,2}:\d{2}\s*-\s*.*?:\s*.*"

    return bool(
        re.match(pattern1, line) or
        re.match(pattern2, line)
    )


# =========================================================
# EXTRACT MESSAGE CONTENT
# =========================================================

def extract_message(line):

    # Format:
    # [8/25/26, 10:30:15 PM] Ali: Hello

    match1 = re.match(
        r"^\[\d{1,2}/\d{1,2}/\d{2,4},\s*\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?\]\s*.*?:\s*(.*)",
        line
    )

    if match1:
        return match1.group(1).strip()

    # Format:
    # 25/8/2026, 10:30 - Ali: Hello

    match2 = re.match(
        r"^\d{1,2}/\d{1,2}/\d{2,4},\s*\d{1,2}:\d{2}\s*-\s*.*?:\s*(.*)",
        line
    )

    if match2:
        return match2.group(1).strip()

    return None


# =========================================================
# AI PREDICTION
# =========================================================

def predict_message(message):

    if model is None or vectorizer is None:
        return "Error"

    cleaned = clean_text(message)

    data = vectorizer.transform([cleaned])

    prediction = model.predict(data)[0]

    if prediction == 1:
        return "Scam"

    return "Legitimate"


# =========================================================
# SCAM PROBABILITY
# =========================================================

def predict_probability(message):

    if model is None or vectorizer is None:
        return 0.0

    cleaned = clean_text(message)

    data = vectorizer.transform([cleaned])

    probabilities = model.predict_proba(data)

    # Class 1 = Scam
    scam_probability = probabilities[0][1]

    return float(scam_probability)


# =========================================================
# GENERATE PDF REPORT
# =========================================================

def generate_pdf(
    total_messages,
    scam_count,
    legitimate_count,
    risk_score,
    risk_level,
    results
):

    os.makedirs("reports", exist_ok=True)

    report_id = str(uuid.uuid4())

    file_path = os.path.join(
        "reports",
        f"report_{report_id}.pdf"
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    normal_style = styles["BodyText"]

    document = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    content = []

    # Title
    content.append(
        Paragraph(
            "VeriChat AI - Scam Chat Analysis Report",
            title_style
        )
    )

    content.append(Spacer(1, 20))

    # Summary
    content.append(
        Paragraph(
            "<b>Analysis Summary</b>",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    summary_data = [
        ["Total Messages", str(total_messages)],
        ["Scam Messages", str(scam_count)],
        ["Legitimate Messages", str(legitimate_count)],
        ["Scam Risk Score", f"{risk_score:.2f}%"],
        ["Risk Level", risk_level]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[200, 200]
    )

    summary_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 8)
        ])
    )

    content.append(summary_table)

    content.append(Spacer(1, 20))

    # Message Analysis
    content.append(
        Paragraph(
            "<b>Message Analysis</b>",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    for index, item in enumerate(results, start=1):

        prediction = item["prediction"]

        if prediction == "Scam":
            status = "SCAM"
        else:
            status = "LEGITIMATE"

        probability = item["probability"] * 100

        message = item["message"]

        content.append(
            Paragraph(
                f"<b>Message {index}</b>",
                styles["Heading3"]
            )
        )

        content.append(
            Paragraph(
                f"<b>Status:</b> {status}",
                normal_style
            )
        )

        content.append(
            Paragraph(
                f"<b>Scam Probability:</b> {probability:.2f}%",
                normal_style
            )
        )

        content.append(
            Paragraph(
                f"<b>Message:</b> {message}",
                normal_style
            )
        )

        content.append(Spacer(1, 10))

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "<b>Disclaimer:</b> The prediction provided by VeriChat AI "
            "is an AI-based assessment and should not be treated as "
            "definitive proof that a message is a scam.",
            normal_style
        )
    )

    document.build(content)

    return report_id


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# PREDICT / ANALYZE CHAT
# =========================================================

@app.route("/predict", methods=["POST"])
def predict():

    # -----------------------------------------------------
    # CHECK CONSENT
    # -----------------------------------------------------

    consent = request.form.get("consentCheckbox")

    if consent != "on":

        return render_template(
            "index.html",
            error="Please agree to the privacy notice before uploading your chat."
        )


    # -----------------------------------------------------
    # CHECK FILE
    # -----------------------------------------------------

    if "file" not in request.files:

        return render_template(
            "index.html",
            error="No file was uploaded."
        )

    file = request.files["file"]


    # -----------------------------------------------------
    # CHECK FILE NAME
    # -----------------------------------------------------

    if file.filename == "":

        return render_template(
            "index.html",
            error="Please select a file."
        )


    # -----------------------------------------------------
    # CHECK FILE EXTENSION
    # -----------------------------------------------------

    if not file.filename.lower().endswith(".txt"):

        return render_template(
            "index.html",
            error="Invalid file type. Please upload a WhatsApp .txt file."
        )


    # -----------------------------------------------------
    # READ FILE
    # -----------------------------------------------------

    try:

        file_content = file.read().decode("utf-8")

    except UnicodeDecodeError:

        return render_template(
            "index.html",
            error="Unable to read the file. Please make sure it is a valid UTF-8 WhatsApp .txt file."
        )


    # -----------------------------------------------------
    # EMPTY FILE CHECK
    # -----------------------------------------------------

    if not file_content.strip():

        return render_template(
            "index.html",
            error="The uploaded file is empty."
        )


    # -----------------------------------------------------
    # FIND VALID WHATSAPP MESSAGES
    # -----------------------------------------------------

    lines = file_content.splitlines()

    messages = []

    for line in lines:

        if is_whatsapp_message(line):

            message = extract_message(line)

            if message:

                messages.append(message)


    # -----------------------------------------------------
    # CHECK WHATSAPP FORMAT
    # -----------------------------------------------------

    if len(messages) < 2:

        return render_template(
            "index.html",
            error="Invalid WhatsApp chat file. Please upload a valid exported WhatsApp chat."
        )


    # =====================================================
    # ANALYSIS
    # =====================================================

    results = []

    scam_count = 0
    legitimate_count = 0

    scam_probabilities = []


    for message in messages:

        prediction = predict_message(message)

        probability = predict_probability(message)

        results.append({
            "message": message,
            "prediction": prediction,
            "probability": probability
        })

        scam_probabilities.append(probability)

        if prediction == "Scam":

            scam_count += 1

        else:

            legitimate_count += 1


    # =====================================================
    # RISK SCORE
    # =====================================================

    if len(scam_probabilities) > 0:

        risk_score = (
            sum(scam_probabilities)
            / len(scam_probabilities)
        ) * 100

    else:

        risk_score = 0


    # =====================================================
    # RISK LEVEL
    # =====================================================

    if risk_score < 40:

        risk_level = "LOW"

    elif risk_score < 70:

        risk_level = "MEDIUM"

    else:

        risk_level = "HIGH"


    # =====================================================
    # GENERATE PDF
    # =====================================================

    report_id = generate_pdf(
        len(messages),
        scam_count,
        legitimate_count,
        risk_score,
        risk_level,
        results
    )


    # =====================================================
    # DISPLAY RESULT
    # =====================================================

    return render_template(
        "result.html",
        total=len(messages),
        scam=scam_count,
        legit=legitimate_count,
        risk=risk_score,
        level=risk_level,
        results=results,
        report_id=report_id
    )


# =========================================================
# DOWNLOAD REPORT
# =========================================================

@app.route("/download-report/<report_id>")
def download_report(report_id):

    file_path = os.path.join(
        "reports",
        f"report_{report_id}.pdf"
    )

    if not os.path.exists(file_path):

        return "Report not found.", 404

    return send_file(
        file_path,
        as_attachment=True
    )


# =========================================================
# FILE TOO LARGE
# =========================================================

@app.errorhandler(413)
def file_too_large(error):

    return render_template(
        "index.html",
        error="File is too large. Maximum file size is 5 MB."
    ), 413


# =========================================================
# INTERNAL SERVER ERROR
# =========================================================

@app.errorhandler(500)
def internal_error(error):

    return render_template(
        "index.html",
        error="An unexpected error occurred. Please try again."
    ), 500


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )