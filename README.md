# Rainbow-Table-Attack

Interactive rainbow-table attack demo — an educational Streamlit app that demonstrates how unhashed or unsalted password hashes can be reversed using precomputed SHA-1 lookup tables (a tiny, in-memory example for learning purposes).

## Features

- Small in-browser simulation that builds a tiny rainbow table from a sample password list.
- Precompute SHA-1 hashes for demo passwords and perform direct-lookup cracking.
- Simple UI to generate sample hashes, enter a custom hash, and attempt to crack it.
- Educational text and code snippets explaining the theory and mitigation strategies.

## Prerequisites

- Python 3.8+ (3.10+ recommended)
- `pip` to install Python packages

This project uses Streamlit and pandas. You can install them with:

```bash
python -m pip install --upgrade pip
pip install streamlit pandas
```

## Run the demo

From the project root run:

```bash
streamlit run app.py
```

This will open the interactive demo in your browser. Typical workflow:

- Click **Build Table** to generate the demo rainbow table.
- Click a sample password to generate its SHA-1 hash in the input field.
- Click **Crack Hash** to attempt a direct lookup in the precomputed table.

If you enter an incorrect or altered hash the demo will report "Not found in demo table." — this demo uses direct lookup only (no reduction/backtracking) unless you enable it in the code.

## Security & Ethics

This repository is for educational purposes only. Do not use these techniques to attack systems you do not own or have explicit permission to test. To defend against rainbow-table attacks you should:

- Use per-user salts when storing password hashes.
- Use a slow, memory-hard key derivation function (e.g., bcrypt, scrypt, Argon2).
- Enforce strong password policies and enable multi-factor authentication.

## Development notes

- The main app is `app.py` (Streamlit). The demo dictionary is defined inside the file (`DEMO_DICT`).
- If you want a reproducible environment, consider adding a `requirements.txt` containing `streamlit` and `pandas`.

## License

Educational demo — no license provided. Use responsibly.

---
If you want, I can also:

- Add a `requirements.txt` file and pin versions.
- Add a short CONTRIBUTING section or automated tests to validate core functions.
- Add a one-line Dockerfile to run the app in a container.

Tell me which of the above you'd like next.
