# Phishing Detection Service

A Django-based web service for detecting phishing URLs using machine learning. This service analyzes URLs based on 89 extracted features and classifies them as legitimate or phishing using a trained Multi-Layer Perceptron (MLP) model.

## Dataset Overview

The dataset contains 89 features extracted from URLs to classify them as 'legitimate' or 'phishing'. The target column is `status` (e.g., 'legitimate' or 'phishing'). These features are computed from a user-provided URL string.

### How to Extract Features from a User Input

In your Django app (e.g., in `views.py`), create an endpoint to accept a URL via POST (e.g., from a form). Then:

1. Validate the URL.
2. Compute features using Python libraries like `requests`, `beautifulsoup4`, `tldextract`, `whois`, `scikit-learn`, etc.
3. For external features (e.g., traffic, rank), use APIs like Google Search Console or third-party services.
4. Feed the computed features into a trained ML model to predict 'legitimate' or 'phishing'.
5. Return the result to the user.

Example steps:

- Parse the URL using `urllib.parse` or `tldextract`.
- Fetch page content with `requests` and parse with `BeautifulSoup`.
- Use `whois` for domain registration details.
- Compute numerical features directly from the URL string.

### Feature Categories

#### 1. Basic URL Structure Features

Derived directly from the URL string.

- `url`: The full URL string (input from user).
- `length_url`: Total characters in the URL (e.g., `len(url)`).
- `length_hostname`: Characters in the hostname/domain (extract via `tldextract`).
- `ip`: 1 if hostname is an IP address (check with `ipaddress` module), else 0.
- `nb_dots`: Number of dots (`.`) in URL (count occurrences).
- `nb_hyphens`: Number of hyphens (`-`) in URL.
- `nb_at`: Number of `@` symbols.
- `nb_qm`: Number of question marks (`?`).
- `nb_and`: Number of `&` symbols.
- `nb_or`: Number of `|` symbols.
- `nb_eq`: Number of `=` symbols.
- `nb_underscore`: Number of underscores (`_`).
- `nb_tilde`: Number of tildes (`~`).
- `nb_percent`: Number of `%` symbols.
- `nb_slash`: Number of slashes (`/`).
- `nb_star`: Number of asterisks (`*`).
- `nb_colon`: Number of colons (`:`).
- `nb_comma`: Number of commas (`,`).
- `nb_semicolumn`: Number of semicolons (`;`).
- `nb_dollar`: Number of `$` symbols.
- `nb_space`: Number of spaces.
- `nb_www`: Number of 'www' substrings.
- `nb_com`: Number of '.com' substrings.
- `nb_dslash`: Number of double slashes (`//`).
- `http_in_path`: 1 if 'http' in path, else 0.
- `https_token`: 1 if 'https' in URL, else 0.
- `ratio_digits_url`: Ratio of digits to total URL length.
- `ratio_digits_host`: Ratio of digits in hostname.
- `punycode`: 1 if URL uses punycode (check encoding).
- `port`: 1 if custom port specified, else 0.
- `tld_in_path`: 1 if TLD in path.
- `tld_in_subdomain`: 1 if TLD in subdomain.
- `abnormal_subdomain`: 1 if subdomain looks abnormal (heuristic check).
- `nb_subdomains`: Number of subdomains (split hostname).
- `prefix_suffix`: 1 if '-' in domain.
- `random_domain`: 1 if domain appears random (entropy check).
- `shortening_service`: 1 if from known shorteners (e.g., bit.ly).
- `path_extension`: 1 if suspicious path extension.
- `nb_redirection`: Number of redirections (from HTTP response).
- `nb_external_redirection`: Number of external redirects.

#### 2. Content and Text-Based Features

Require fetching the page with `requests` and parsing with `BeautifulSoup`.

- `length_words_raw`: Total words in raw HTML.
- `char_repeat`: Ratio of repeated characters.
- `shortest_words_raw`, `shortest_word_host`, `shortest_word_path`: Shortest word lengths.
- `longest_words_raw`, `longest_word_host`, `longest_word_path`: Longest word lengths.
- `avg_words_raw`, `avg_word_host`, `avg_word_path`: Average word lengths.
- `phish_hints`: Number of phishing-related keywords in content.
- `domain_in_brand`: 1 if domain matches known brands.
- `brand_in_subdomain/path`: 1 if brand in subdomain/path.
- `suspecious_tld`: 1 if TLD is suspicious.
- `statistical_report`: Statistical score (e.g., from analysis).
- `nb_hyperlinks`: Total hyperlinks in page.
- `ratio_intHyperlinks`: Ratio of internal links.
- `ratio_extHyperlinks`: Ratio of external links.
- `ratio_nullHyperlinks`: Ratio of null links.
- `nb_extCSS`: Number of external CSS links.
- `ratio_intRedirection`: Ratio of internal redirects.
- `ratio_extRedirection`: Ratio of external redirects.
- `ratio_intErrors`: Ratio of internal errors.
- `ratio_extErrors`: Ratio of external errors.
- `login_form`: 1 if login form present.
- `external_favicon`: 1 if favicon is external.
- `links_in_tags`: Ratio of links in tags.
- `submit_email`: 1 if email submission form.
- `ratio_intMedia`: Ratio of internal media.
- `ratio_extMedia`: Ratio of external media.
- `sfh`: Server form handler (check form action).
- `iframe`: 1 if iframes present.
- `popup_window`: 1 if popup scripts.
- `safe_anchor`: Ratio of safe anchors.
- `onmouseover`: 1 if onmouseover events.
- `right_clic`: 1 if right-click disabled.
- `empty_title`: 1 if page title is empty.
- `domain_in_title`: 1 if domain in title.
- `domain_with_copyright`: 1 if copyright mentions domain.

#### 3. Domain and WHOIS Features

Use `whois` library for registration details.

- `whois_registered_domain`: 1 if domain is registered (check WHOIS).
- `domain_registration_length`: Days since registration.
- `domain_age`: Age of domain in days.

#### 4. External and Ranking Features

Require API calls or external checks (e.g., Google, DNS).

- `web_traffic`: Estimated traffic (from services like Alexa).
- `dns_record`: 1 if DNS record exists.
- `google_index`: 1 if indexed by Google.
- `page_rank`: PageRank score (0-10).

## Model Explanation: Multi-Layer Perceptron (MLP)

This is a Multi-Layer Perceptron (MLP), a type of neural network used for classification tasks. It's designed for binary classification (e.g., yes/no decisions) and is called "ChurnModel" here, but in your phishing detection context, it's likely used to predict if a URL is legitimate or phishing based on the 87 features from your dataset (excluding 'url' and 'status').

### Key Components in Simple Terms

- **Layers**: The model has 3 main layers:

  - **Input Layer**: Takes 87 features (numbers from URL analysis, like length, dots, etc.).
  - **Hidden Layers (2)**:
    - First hidden layer: 300 nodes (neurons) to learn patterns.
    - Second hidden layer: 100 nodes to refine those patterns.
  - **Output Layer**: 1 node that outputs a probability (0 to 1) using Sigmoid—close to 1 means phishing, close to 0 means legitimate.

- **Batch Normalization**: Normalizes data between layers to make training stable and faster (prevents issues like exploding values).

- **Activation Functions**:

  - **ReLU**: Adds non-linearity between layers (helps learn complex patterns; outputs 0 for negative inputs, keeps positives).
  - **Sigmoid**: At output for probabilities (squashes output to 0-1 range).

- **Dropout**: Randomly "drops" 10% of neurons during training to prevent overfitting (stops the model from memorizing training data too well).

- **Structure Flow**:
  1. Input (87 features) → Layer 1 (300 nodes) → BatchNorm → ReLU → Dropout.
  2. → Layer 2 (100 nodes) → BatchNorm → ReLU → Dropout.
  3. → Output Layer (1 node) → Sigmoid → Probability.

### Model Architecture

```
ChurnModel(
  (layer_1): Linear(in_features=87, out_features=300, bias=True)
  (layer_2): Linear(in_features=300, out_features=100, bias=True)
  (layer_out): Linear(in_features=100, out_features=1, bias=True)
  (relu): ReLU()
  (sigmoid): Sigmoid()
  (dropout): Dropout(p=0.1, inplace=False)
  (batchnorm1): BatchNorm1d(300, eps=1e-05, momentum=0.1, affine=True, track_running_stats=True)
  (batchnorm2): BatchNorm1d(100, eps=1e-05, momentum=0.1, affine=True, track_running_stats=True)
)
```

### How It's Used in This Project

- **Training**: Feed preprocessed data (from `DataPreprocessing.ipynb`) into the model. It learns to map features to labels (legitimate/phishing) by adjusting weights.
- **Prediction**: For a new URL from a user, compute the 87 features, input them into the model, and get a probability. If > 0.5, classify as phishing; else, legitimate.
- **Integration**: In Django, load the trained model (e.g., using PyTorch), process user URLs in a view, and return results via API or web page.
- **Why This Model?**: Good for tabular data like yours; handles non-linear relationships in features (e.g., how URL length relates to phishing).

## Installation

1. Clone the repository.
2. Create a Python virtual environment: `python -m venv env`
3. Activate it: `.\env\Scripts\activate` (Windows)
4. Install dependencies: `pip install django djangorestframework requests beautifulsoup4 tldextract python-whois scikit-learn pandas numpy joblib transformers datasets torch`

## Usage

1. Preprocess data using `DataPreprocessing.ipynb`.
2. Train the model (implement in a script).
3. Integrate into Django views to accept URLs and return predictions.

For more details, refer to the code files.

## References

- [Deep Learning PyTorch Binary Classification](https://www.kaggle.com/code/unstructuredrahul/deep-learning-pytorch-binary-classification)
- [Web Page Phishing Detection Dataset](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)
