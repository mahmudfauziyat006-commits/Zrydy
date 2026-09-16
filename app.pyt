from flask import request

@app.route("/submit-data", methods=["POST"])
def handle_data():
    text_received = request.form.get("user_input")
    print(f"Python successfully processed: {text_received}")
    return f"Python received: {text_received}"
