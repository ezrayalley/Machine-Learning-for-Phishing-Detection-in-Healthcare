from flask import Flask, render_template, request
import pickle
import numpy as np

app = Flask(__name__)

# Load the phishing detection model
model_path = "model/phishing_model.pkl"
with open(model_path, "rb") as file:
    model = pickle.load(file)

@app.route("/")
def home():
    return render_template("index.html", result=None)

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]
    
    # Convert the input into a format the model understands
    features = np.array([len(url)])  # Example feature, update based on your model

    # Make prediction
    prediction = model.predict([features])[0]
    result = "Phishing" if prediction == 1 else "Legitimate"

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
