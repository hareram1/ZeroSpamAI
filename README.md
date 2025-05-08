## ZeroSpamAI

A Flask-based web application for detecting spam URLs and messages using a machine learning model. This project allows users to input a URL or message and receive a prediction on whether it is spam or not. It also provides analytics on model performance and feature importance.

---

###  Features

* **Spam URL/Message Prediction**: Classify input as spam or not spam.
* **Machine Learning Model**: Random Forest classifier trained on lexical and domain-based features.
* **Interactive Web Interface**: User-friendly UI built with Flask, HTML, CSS, and JavaScript.
* **Analytics Dashboard**: View feature importance and model performance metrics.
* **PDF Report Generation**: Export prediction results and analytics to PDF.
* **Domain WHOIS Lookup (Optional)**: Fetch domain age and registration details using `python-whois`.

---

###  Project Structure

```
SPAM DETECTION/
├── app.py                   # Main Flask application
├── requirements.txt         # Python dependencies
├── data/                    # Sample datasets (CSV format)
├── models/
│   ├── best_model.pkl       # Pre-trained machine learning model
│   ├── feature_list.txt     # Ordered list of features used by the model
│   ├── feature_order.json   # JSON mapping feature names to column indices
│   └── feature_importance.png  # Visualization of feature importances
├── src/
│   └── phishing_detection.py  # Script for model training and evaluation
├── utils/
│   └── whois_utils.py       # Helper functions for WHOIS domain lookups
├── templates/               # HTML templates
│   ├── index.html           # Home page (prediction form)
│   ├── analytics.html       # Model analytics dashboard
│   └── pdf_template.html    # Layout for PDF report
├── static/
│   └── style.css            # Custom styles
└── Readme.md                # Project documentation
```

---

###  Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/<your-username>/spam-detection.git
   cd spam-detection/SPAM\ DETECTION
   ```

2. **Create a virtual environment (optional but recommended)**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

---

### Usage

1. **Run the Flask app**

   ```bash
   python app.py
   ```

2. **Open your browser** and navigate to `http://127.0.0.1:5000/`.

3. **Enter a URL or message** in the input form and submit to see the prediction result.

4. **View Analytics** via the "Analytics" link in the navigation bar to explore feature importances and model metrics.

5. **Generate PDF Report** by clicking the "Download PDF" button on the analytics page.

---

### Model Training (Optional)

If you wish to retrain the model on your own dataset:

1. **Prepare your dataset** in `data/` folder as a CSV with columns: `text`, `label`.
2. **Adjust feature extraction** and training parameters in `src/phishing_detection.py`.
3. **Run training script**:

   ```bash
   python src/phishing_detection.py
   ```
4. **New model & artifacts** will be saved to the `models/` directory.

---