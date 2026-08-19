from flask import Flask, render_template, request, send_file
import pickle
import re
import os
import uuid

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


app = Flask(__name__)


# =========================
# LOAD AI MODEL
# =========================

model = pickle.load(
    open("scam_model.pkl", "rb")
)

vectorizer = pickle.load(
    open("vectorizer.pkl", "rb")
)


# =========================
# TEXT CLEANING
# =========================

def clean_text(text):

    text = text.lower()

    text = re.sub(
        r'[^a-zA-Z]',
        ' ',
        text
    )

    text = re.sub(
        r'\s+',
        ' ',
        text
    )

    return text.strip()


# =========================
# EXTRACT WHATSAPP MESSAGE
# =========================

def extract_message(text):

    pattern = r'\]\s.*?:\s(.*)'

    match = re.search(
        pattern,
        text
    )

    if match:
        return match.group(1)

    return text


# =========================
# PREDICTION
# =========================

def predict_message(msg):

    msg = extract_message(msg)

    msg = clean_text(msg)

    data = vectorizer.transform(
        [msg]
    )

    result = model.predict(
        data
    )

    return result[0]


# =========================
# SCAM PROBABILITY
# =========================

def predict_probability(msg):

    msg = extract_message(msg)

    msg = clean_text(msg)

    data = vectorizer.transform(
        [msg]
    )

    probabilities = model.predict_proba(
        data
    )

    # Class 1 = Scam
    scam_probability = probabilities[0][1]

    return scam_probability


# =========================
# HOME PAGE
# =========================

@app.route('/')
def home():

    return render_template(
        'index.html'
    )


# =========================
# GENERATE PDF
# =========================

def generate_pdf(
    report_id,
    total_count,
    scam_count,
    legit_count,
    risk_score,
    risk_level,
    results
):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    filename = f"{report_id}.pdf"

    filepath = os.path.join(
        "reports",
        filename
    )


    # =========================
    # PDF DOCUMENT
    # =========================

    document = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )


    styles = getSampleStyleSheet()


    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        spaceAfter=20
    )


    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=15,
        spaceAfter=10
    )


    message_style = ParagraphStyle(
        "MessageStyle",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12
    )


    story = []


    # =========================
    # TITLE
    # =========================

    story.append(
        Paragraph(
            "AI SCAM CHAT DETECTION REPORT",
            title_style
        )
    )


    story.append(
        Paragraph(
            "WhatsApp Chat Analysis",
            styles["Normal"]
        )
    )


    story.append(
        Spacer(
            1,
            20
        )
    )


    # =========================
    # ANALYSIS SUMMARY
    # =========================

    story.append(
        Paragraph(
            "Analysis Summary",
            heading_style
        )
    )


    summary_data = [

        ["Total Messages", str(total_count)],

        ["Scam Messages", str(scam_count)],

        ["Legitimate Messages", str(legit_count)],

        ["AI Scam Risk Score", f"{risk_score:.2f}%"],

        ["Risk Level", risk_level]

    ]


    summary_table = Table(
        summary_data,
        colWidths=[
            2.5 * inch,
            2.5 * inch
        ]
    )


    summary_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])
    )


    story.append(
        summary_table
    )


    story.append(
        Spacer(
            1,
            20
        )
    )


    # =========================
    # MESSAGE ANALYSIS
    # =========================

    story.append(
        Paragraph(
            "Message Analysis",
            heading_style
        )
    )


    for index, result in enumerate(
        results,
        start=1
    ):

        status = result["status"]

        message = result["message"]


        # Remove unsupported emoji/symbols
        message = message.encode(
            "ascii",
            "ignore"
        ).decode(
            "ascii"
        )


        story.append(
            Paragraph(
                f"<b>{index}. {status}</b>",
                message_style
            )
        )


        story.append(
            Paragraph(
                message,
                message_style
            )
        )


        story.append(
            Spacer(
                1,
                8
            )
        )


    # =========================
    # BUILD PDF
    # =========================

    document.build(
        story
    )


    return filepath


# =========================
# ANALYZE CHAT
# =========================

@app.route(
    '/predict',
    methods=['POST']
)
def predict():

    # Check uploaded file
    if 'file' not in request.files:

        return "No file uploaded."


    file = request.files['file']


    if file.filename == '':

        return "Please select a file."


    # =========================
    # READ FILE
    # =========================

    chat = file.read().decode(
        'utf-8',
        errors='ignore'
    )


    messages = chat.split("\n")


    # =========================
    # VARIABLES
    # =========================

    results = []

    scam_count = 0

    legit_count = 0

    total_count = 0

    scam_probabilities = []


    # =========================
    # ANALYZE EACH MESSAGE
    # =========================

    for msg in messages:

        msg = msg.strip()


        if msg != "":

            total_count += 1


            # Predict classification
            pred = predict_message(msg)


            # Get scam probability
            scam_probability = predict_probability(
                msg
            )


            scam_probabilities.append(
                scam_probability
            )


            # =========================
            # SCAM
            # =========================

            if pred == 1:

                scam_count += 1

                results.append({

                    "message": msg,

                    "status": "SCAM"

                })


            # =========================
            # LEGITIMATE
            # =========================

            else:

                legit_count += 1

                results.append({

                    "message": msg,

                    "status": "LEGITIMATE"

                })


    # =========================
    # RISK SCORE
    # =========================

    if total_count == 0:

        risk_score = 0

    else:

        risk_score = (

            sum(scam_probabilities)
            / len(scam_probabilities)

        ) * 100


    # =========================
    # RISK LEVEL
    # =========================

    if risk_score < 40:

        risk_level = "LOW"


    elif risk_score < 70:

        risk_level = "MEDIUM"


    else:

        risk_level = "HIGH"


    # =========================
    # CREATE REPORT ID
    # =========================

    report_id = str(
        uuid.uuid4()
    )


    # =========================
    # GENERATE PDF
    # =========================

    generate_pdf(

        report_id,

        total_count,

        scam_count,

        legit_count,

        risk_score,

        risk_level,

        results

    )


    # =========================
    # SHOW RESULT
    # =========================

    return render_template(

        "result.html",

        total=total_count,

        scam=scam_count,

        legit=legit_count,

        risk=risk_score,

        level=risk_level,

        results=results,

        report_id=report_id

    )


# =========================
# DOWNLOAD PDF
# =========================

@app.route(
    '/download-report/<report_id>'
)
def download_report(report_id):

    filepath = os.path.join(
        "reports",
        f"{report_id}.pdf"
    )


    if not os.path.exists(filepath):

        return "Report not found."


    return send_file(

        filepath,

        as_attachment=True,

        download_name="AI_Scam_Chat_Report.pdf",

        mimetype="application/pdf"

    )


# =========================
# RUN SERVER
# =========================

if __name__ == '__main__':

    port = int(
        os.environ.get(
            'PORT',
            5000
        )
    )


    app.run(

        host='0.0.0.0',

        port=port,

        debug=False

    )