
# 🛡️ Phishing URL Detector

A Machine Learning-based web application that analyzes URLs and predicts whether they are **Phishing** or **Legitimate**.

The project combines **URL feature engineering, Machine Learning, Flask, HTML, and CSS** to create an end-to-end phishing URL detection system.

Live Demo: [https://phishing-url-detector-x1f4.onrender.com](https://phishing-url-detector-x1f4.onrender.com)

---

## 🚀 Features

- 🔍 Analyze a URL for potential phishing activity
- 🧠 Machine Learning-based classification
- 📊 Extracts 18 custom URL-based features
- 📈 Provides prediction probability
- 🌐 Flask-based web application
- 🎨 Simple and user-friendly web interface
- ⚡ Real-time prediction

---

## 🧠 Machine Learning

The model is trained using URL-based features such as:

- URL Length
- Domain Length
- Domain IP Detection
- Number of Subdomains
- URL Obfuscation
- Number of Obfuscated Characters
- Obfuscation Ratio
- Number of Letters
- Letter Ratio
- Number of Digits
- Digit Ratio
- Number of `=`
- Number of `?`
- Number of `&`
- Other Special Characters
- Special Character Ratio
- HTTPS Detection
- TLD Length

---

## 📊 Model Performance

The model was evaluated using:

- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix
- ROC-AUC

The custom URL-only model achieved approximately **99.7% accuracy** and a **ROC-AUC of approximately 0.998** on the test dataset.

> Note: Performance depends on the dataset and evaluation methodology. Real-world phishing detection may perform differently on previously unseen URLs.

---

## 🏗️ Project Structure

```text
Phishing-URL-Detector/
│
├── app.py
├── phishing_url_model.pkl
├── feature_columns.pkl
├── requirements.txt
├── README.md
│
└── templates/
    └── index.html
