import streamlit as st
import hashlib
import time
import pandas as pd

# ==============================================================================
# Core Cryptographic & Attack Logic
# ==============================================================================

DEMO_DICT = [
    'helloworld', 'admin123', 'letmein', 'welcome', 'master', 'sunshine', 'dragon', 'monkey'
]

def hash_password_sha1(password: str) -> str:
    """Hashes a plaintext string using SHA-1 (160-bit / 40 hex chars)."""
    return hashlib.sha1(password.encode('utf-8')).hexdigest()

def reduce_to_word(hash_hex: str, dictionary: list) -> str:
    """Reduction function: maps hash to a dictionary candidate using byte partitioning."""
    n = len(dictionary)
    sum_val = 0
    for i in range(0, len(hash_hex), 2):
        try:
            sum_val += int(hash_hex[i:i + 2], 16)
        except ValueError:
            pass
    return dictionary[sum_val % n]

def build_rainbow_table(dictionary: list) -> list:
    """Builds the in-memory rainbow table mapping plaintext words to SHA-1 endpoints."""
    table = []
    for word in dictionary:
        h = hash_password_sha1(word)
        table.append({
            'Plaintext Word': word,
            'SHA-1 Endpoint Hash': h,
            'Algorithm': 'SHA-1',
            'Bit Length': '160-bit'
        })
    return table

def crack_hash(target_hash: str, rainbow_table: list, dictionary: list) -> dict:
    """Attempts to reverse the target hash using direct endpoint lookup and 1-step reduction."""
    target_clean = target_hash.strip().lower()

    # 1. Direct Endpoint Lookup
    for row in rainbow_table:
        if row['SHA-1 Endpoint Hash'] == target_clean:
            return {
                'found': True,
                'password': row['Plaintext Word'],
                'method': 'Direct Endpoint Match',
                'digest': target_clean
            }

    # 2. 1-Step Reduction Chain Verification
    candidate = reduce_to_word(target_clean, dictionary)
    if hash_password_sha1(candidate) == target_clean:
        return {
            'found': True,
            'password': candidate,
            'method': '1-Step Reduction Chain',
            'digest': target_clean
        }

    return {'found': False, 'digest': target_clean}


# ==============================================================================
# Streamlit Application Configuration & Glassmorphism Theme
# ==============================================================================

st.set_page_config(
    page_title="Rainbow Table Attack — Cybersecurity Suite",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Inject Modern Cybersecurity Glassmorphism CSS
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* --- Root Color Variables --- */
:root {
    --bg-dark: #060913;
    --glass-bg: rgba(15, 23, 42, 0.65);
    --glass-panel: rgba(13, 20, 38, 0.7);
    --glass-border: rgba(255, 255, 255, 0.08);
    --cyan: #06b6d4;
    --blue: #3b82f6;
    --purple: #8b5cf6;
    --emerald: #10b981;
    --rose: #f43f5e;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --text-dim: #64748b;
}

/* Base Body & Layout */
.stApp {
    background-color: var(--bg-dark);
    background-image: radial-gradient(circle at 50% 0%, #111a33 0%, #070b16 55%, #04060c 100%);
    background-attachment: fixed;
    color: var(--text-main);
    font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
}

/* Hide Default Streamlit Header & Clutter */
header[data-testid="stHeader"] {
    background: transparent !important;
}
#MainMenu, footer {
    visibility: hidden;
}

/* Cyber Header Navigation Mimic */
.cyber-nav {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    background: rgba(10, 16, 31, 0.75);
    backdrop-filter: blur(16px);
    border: 1px solid var(--glass-border);
    border-radius: 14px;
    margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
}
.brand-title {
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 800;
    font-size: 1.2rem;
    letter-spacing: -0.3px;
    color: #ffffff;
}
.brand-badge {
    background: linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(139, 92, 246, 0.2));
    border: 1px solid rgba(6, 182, 212, 0.35);
    color: var(--cyan);
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
}

/* Hero Typography */
.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 5px 14px;
    border-radius: 999px;
    background: rgba(6, 182, 212, 0.08);
    border: 1px solid rgba(6, 182, 212, 0.25);
    color: var(--cyan);
    font-size: 0.8rem;
    font-weight: 600;
    margin-bottom: 12px;
}
.pulse-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--cyan);
    box-shadow: 0 0 10px var(--cyan);
}
h1.hero-title {
    font-size: clamp(36px, 5vw, 64px);
    font-weight: 900;
    line-height: 1.08;
    letter-spacing: -1.2px;
    margin: 0 0 14px 0;
    background: linear-gradient(135deg, #ffffff 10%, #60a5fa 45%, #c084fc 80%, #38bdf8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 4px 16px rgba(96, 165, 250, 0.25));
}
p.hero-subtitle {
    color: var(--text-muted);
    font-size: 1.1rem;
    line-height: 1.65;
    max-width: 900px;
    margin-bottom: 24px;
}

/* Glassmorphism Panels & Cards */
.glass-card {
    background: linear-gradient(180deg, rgba(20, 28, 52, 0.6) 0%, rgba(11, 17, 34, 0.8) 100%);
    border: 1px solid var(--glass-border);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
    height: 100%;
    transition: transform 0.2s ease, border-color 0.2s ease;
}
.glass-card:hover {
    border-color: rgba(6, 182, 212, 0.35);
}
.glass-card h3 {
    margin: 0 0 8px 0;
    font-size: 1.2rem;
    font-weight: 700;
    color: #ffffff;
}
.glass-card p {
    color: var(--text-muted);
    font-size: 0.92rem;
    margin: 0;
    line-height: 1.5;
}

/* Section Header & Dividers */
.section-tag {
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--cyan);
}
h2.section-heading {
    font-size: 32px;
    font-weight: 800;
    letter-spacing: -0.6px;
    margin: 4px 0 16px 0;
    background: linear-gradient(135deg, #ffffff 20%, #93c5fd 80%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

/* Visual Chain Diagram */
.chain-container {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    background: rgba(11, 17, 34, 0.85);
    border: 1px solid var(--glass-border);
    border-radius: 14px;
    padding: 18px 22px;
    margin: 16px 0;
    flex-wrap: wrap;
}
.chain-node {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
    padding: 10px 14px;
    text-align: center;
    min-width: 130px;
}
.chain-node.highlight {
    border-color: rgba(6, 182, 212, 0.4);
    background: rgba(6, 182, 212, 0.08);
}
.chain-node.endpoint {
    border-color: rgba(16, 185, 129, 0.4);
    background: rgba(16, 185, 129, 0.08);
}
.chain-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    font-weight: 700;
    color: var(--text-dim);
}
.chain-val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.88rem;
    font-weight: 600;
    color: #ffffff;
}
.chain-arrow {
    color: var(--cyan);
    font-weight: 800;
    font-size: 1.1rem;
}

/* Styled Streamlit Button */
div.stButton > button {
    background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 50%, #7c3aed 100%);
    color: #ffffff !important;
    font-weight: 700 !important;
    border-radius: 12px !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    padding: 10px 20px !important;
    box-shadow: 0 4px 16px rgba(37, 99, 235, 0.35) !important;
    transition: all 0.25s ease !important;
}
div.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 6px 24px rgba(37, 99, 235, 0.5) !important;
    border-color: rgba(6, 182, 212, 0.5) !important;
}

/* Text Input Styling */
div[data-baseweb="input"] {
    background: rgba(10, 16, 31, 0.85) !important;
    border: 1px solid rgba(255, 255, 255, 0.12) !important;
    border-radius: 12px !important;
    color: #ffffff !important;
    font-family: 'JetBrains Mono', monospace !important;
}
div[data-baseweb="input"]:focus-within {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.25) !important;
}

/* Results Card Styling */
.res-card {
    padding: 20px;
    border-radius: 14px;
    margin-top: 16px;
    border: 1px solid var(--glass-border);
}
.res-card.success {
    background: linear-gradient(180deg, rgba(16, 185, 129, 0.12) 0%, rgba(10, 16, 31, 0.9) 100%);
    border-color: rgba(16, 185, 129, 0.4);
    box-shadow: 0 0 24px rgba(16, 185, 129, 0.15);
}
.res-card.danger {
    background: linear-gradient(180deg, rgba(244, 63, 94, 0.12) 0%, rgba(10, 16, 31, 0.9) 100%);
    border-color: rgba(244, 63, 94, 0.4);
    box-shadow: 0 0 24px rgba(244, 63, 94, 0.15);
}

/* Modern Dataframe Wrap */
.dataframe-container {
    border: 1px solid var(--glass-border);
    border-radius: 14px;
    overflow: hidden;
    background: rgba(8, 12, 24, 0.85);
}
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# Session State Management
# ==============================================================================

if 'rainbow_table' not in st.session_state:
    st.session_state.rainbow_table = build_rainbow_table(DEMO_DICT)
if 'target_hash' not in st.session_state:
    st.session_state.target_hash = hash_password_sha1('helloworld')
if 'crack_result' not in st.session_state:
    st.session_state.crack_result = None
if 'selected_sample' not in st.session_state:
    st.session_state.selected_sample = 'helloworld'

def handle_sample_click(word):
    """Callback when a sample password chip is pressed."""
    st.session_state.selected_sample = word
    st.session_state.target_hash = hash_password_sha1(word)
    st.session_state.crack_result = None

def handle_crack():
    """Executes the rainbow lookup and records execution metrics."""
    h = st.session_state.target_hash_input.strip()
    if not h:
        st.session_state.crack_result = {
            'found': False,
            'message': 'Please provide a valid SHA-1 hash.',
            'status': 'empty'
        }
        return

    st.session_state.target_hash = h
    start_time = time.perf_counter()
    res = crack_hash(h, st.session_state.rainbow_table, DEMO_DICT)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
    res['latency_ms'] = elapsed_ms
    st.session_state.crack_result = res


# ==============================================================================
# UI Header & Navigation Bar
# ==============================================================================

st.markdown("""
<div class="cyber-nav">
    <div class="brand-title">
        <span>🔐</span>
        <span>Rainbow Table Attack Suite</span>
        <span class="brand-badge">Streamlit Lab</span>
    </div>
    <div style="font-size: 0.85rem; color: var(--text-muted);">
        Status: <strong style="color: #34d399;">● Online & Interactive</strong>
    </div>
</div>
""", unsafe_allow_html=True)


# ==============================================================================
# Hero Section
# ==============================================================================

st.markdown("""
<div class="hero-badge">
    <span class="pulse-dot"></span>
    <span>Cryptographic Vulnerability Laboratory</span>
</div>
<h1 class="hero-title">Rainbow Table Attack</h1>
<p class="hero-subtitle">
    Explore how precomputed hash lookup tables reverse unsalted password hashes in sub-millisecond time. Understand the cryptographic math, reduction functions, and defensive countermeasures.
</p>
""", unsafe_allow_html=True)

col_hero1, col_hero2, col_hero3 = st.columns(3)
with col_hero1:
    st.markdown("""
    <div class="glass-card">
        <h3>🧩 Theory & Chains</h3>
        <p>Learn how alternating hash and reduction functions condense giant keyspaces into start and end points.</p>
    </div>
    """, unsafe_allow_html=True)
with col_hero2:
    st.markdown("""
    <div class="glass-card">
        <h3>🛠️ Attack Mechanics</h3>
        <p>Step-by-step breakdown of direct endpoint searching, collision handling, and chain reconstruction.</p>
    </div>
    """, unsafe_allow_html=True)
with col_hero3:
    st.markdown("""
    <div class="glass-card">
        <h3>⚡ Real-Time Engine</h3>
        <p>Interactive workbench to generate target SHA-1 digests, execute lookups, and benchmark latency.</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ==============================================================================
# Interactive Simulation Section
# ==============================================================================

st.markdown('<span class="section-tag">Interactive Environment</span>', unsafe_allow_html=True)
st.markdown('<h2 class="section-heading">Live Attack Simulation</h2>', unsafe_allow_html=True)

# Visual Chain Diagram
st.markdown("""
<div class="chain-container">
    <div class="chain-node highlight">
        <div class="chain-label">Start Word (Stored)</div>
        <div class="chain-val">helloworld</div>
    </div>
    <div class="chain-arrow">➔</div>
    <div class="chain-node">
        <div class="chain-label">SHA-1 H(P)</div>
        <div class="chain-val">2aae6c35c9...</div>
    </div>
    <div class="chain-arrow">➔</div>
    <div class="chain-node">
        <div class="chain-label">Reduction R(H)</div>
        <div class="chain-val">admin123</div>
    </div>
    <div class="chain-arrow">➔</div>
    <div class="chain-node endpoint">
        <div class="chain-label">End Hash (Stored)</div>
        <div class="chain-val">2aae6c35...</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Step 1: Precomputed Table Status
st.markdown("#### Step 1: Active In-Memory Rainbow Table")
col_stat1, col_stat2, col_stat3 = st.columns(3)
with col_stat1:
    st.metric(label="Precomputed Records", value=f"{len(st.session_state.rainbow_table)} Endpoints")
with col_stat2:
    st.metric(label="Target Digest", value="SHA-1 (160-bit)")
with col_stat3:
    st.metric(label="Lookup Complexity", value="O(1) / O(k)")

st.markdown("<br>", unsafe_allow_html=True)

# Step 2: Sample Password Chips
st.markdown("#### Step 2: Generate Test Hash from Dictionary")
st.caption("Select a sample credential to instantly generate and load its SHA-1 hash:")

sample_cols = st.columns(len(DEMO_DICT))
for idx, word in enumerate(DEMO_DICT):
    btn_label = f"🔑 {word}"
    if sample_cols[idx].button(btn_label, key=f"chip_{word}"):
        handle_sample_click(word)

st.markdown("<br>", unsafe_allow_html=True)

# Step 3: Crack Query Row
st.markdown("#### Step 3: Query & Crack Target Hash")
col_input, col_action = st.columns([4, 1])
with col_input:
    st.text_input(
        label="Target Hash",
        value=st.session_state.target_hash,
        key="target_hash_input",
        placeholder="Enter 40-character SHA-1 hexadecimal hash…",
        label_visibility="collapsed"
    )
with col_action:
    st.button("🔍 Crack Hash", on_click=handle_crack, use_container_width=True)

# Cracking Results Display
if st.session_state.crack_result:
    res = st.session_state.crack_result
    if res.get('status') == 'empty':
        st.warning("Please enter or select a hash to analyze.")
    elif res.get('found'):
        st.markdown(f"""
        <div class="res-card success">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="color: #34d399; margin: 0;">🔓 Password Hash Compromised!</h3>
                <span class="brand-badge" style="border-color: #34d399; color: #34d399;">Resolved</span>
            </div>
            <p style="color: var(--text-muted); margin-bottom: 12px;">
                Target digest <code>{res['digest']}</code> was reversed successfully.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px;">
                <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 8px;">
                    <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Recovered Plaintext</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.1rem; color: #67e8f9; font-weight: 700;">{res['password']}</div>
                </div>
                <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 8px;">
                    <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Method</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; color: #ffffff;">{res['method']}</div>
                </div>
                <div style="background: rgba(255,255,255,0.03); padding: 8px 12px; border-radius: 8px;">
                    <div style="font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase;">Execution Latency</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; color: #34d399;">{res['latency_ms']} ms</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="res-card danger">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="color: #fb7185; margin: 0;">🔒 Hash Not Found in Table</h3>
                <span class="brand-badge" style="border-color: #fb7185; color: #fb7185;">Search Exhausted</span>
            </div>
            <p style="color: var(--text-muted); margin: 0;">
                Digest <code>{res['digest']}</code> was not found among precomputed endpoints or 1-step reduction paths (Search latency: {res.get('latency_ms', 0)} ms).
            </p>
        </div>
        """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Table Explorer
st.markdown("#### Table Explorer")
df_display = pd.DataFrame(st.session_state.rainbow_table)
st.dataframe(df_display, use_container_width=True, hide_index=True)

st.markdown("<hr style='border: 1px solid var(--glass-border); margin: 40px 0;'>", unsafe_allow_html=True)


# ==============================================================================
# Theory & Concepts Section
# ==============================================================================

st.markdown('<span class="section-tag">Concepts & Mathematics</span>', unsafe_allow_html=True)
st.markdown('<h2 class="section-heading">Rainbow Table Architecture</h2>', unsafe_allow_html=True)

col_th1, col_th2 = st.columns(2)
with col_th1:
    st.markdown("""
    <div class="glass-card">
        <h3>⚡ Time-Memory Tradeoff</h3>
        <p>
            Storing every possible password-hash pair would take petabytes of storage. Conversely, calculating hashes on the fly (brute force) takes years. Rainbow tables find the optimal sweet spot by storing only <strong>chain start</strong> and <strong>chain end</strong> entries.
        </p>
    </div>
    """, unsafe_allow_html=True)
with col_th2:
    st.markdown("""
    <div class="glass-card">
        <h3>🔄 The Role of Reduction R(h)</h3>
        <p>
            Reduction functions map hash digest bytes back into valid password characters. Because reduction is many-to-one, different chains can sometimes merge (collisions), which modern rainbow tables solve via position-dependent reduction functions <code>R_i(h)</code>.
        </p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ==============================================================================
# Python Reference Code Section
# ==============================================================================

st.markdown('<span class="section-tag">Reference Implementation</span>', unsafe_allow_html=True)
st.markdown('<h2 class="section-heading">Core Python Implementation</h2>', unsafe_allow_html=True)

st.code("""
import hashlib

def hash_password_sha1(password: str) -> str:
    \"\"\"Generates a standard 160-bit SHA-1 hexadecimal hash.\"\"\"
    return hashlib.sha1(password.encode('utf-8')).hexdigest()

def reduce_to_word(hash_hex: str, dictionary: list) -> str:
    \"\"\"Reduction: maps 40-character hash into a dictionary plaintext candidate.\"\"\"
    byte_sum = sum(int(hash_hex[i:i+2], 16) for i in range(0, len(hash_hex), 2))
    return dictionary[byte_sum % len(dictionary)]

def crack_hash(target_hash: str, rainbow_table: list, dictionary: list):
    \"\"\"Reverses target hash via direct endpoint and reduction checking.\"\"\"
    target_clean = target_hash.strip().lower()
    
    # 1. Direct Lookup
    for row in rainbow_table:
        if row['SHA-1 Endpoint Hash'] == target_clean:
            return {'found': True, 'password': row['Plaintext Word'], 'method': 'Direct Endpoint'}
            
    # 2. 1-Step Reduction Lookup
    candidate = reduce_to_word(target_clean, dictionary)
    if hash_password_sha1(candidate) == target_clean:
        return {'found': True, 'password': candidate, 'method': 'Reduction Chain'}
        
    return {'found': False}
""", language="python")

st.markdown("<hr style='border: 1px solid var(--glass-border); margin: 40px 0;'>", unsafe_allow_html=True)


# ==============================================================================
# Mitigation & Defense Section
# ==============================================================================

st.markdown('<span class="section-tag">Defensive Cryptography</span>', unsafe_allow_html=True)
st.markdown('<h2 class="section-heading">Mitigation Strategies</h2>', unsafe_allow_html=True)

col_def1, col_def2, col_def3 = st.columns(3)
with col_def1:
    st.markdown("""
    <div class="glass-card" style="border-left: 4px solid var(--emerald);">
        <h3>🧂 Cryptographic Salts</h3>
        <p>Adding a unique, random 128-bit salt to each user password forces attackers to generate a unique table for every single account, destroying table reusability.</p>
    </div>
    """, unsafe_allow_html=True)
with col_def2:
    st.markdown("""
    <div class="glass-card" style="border-left: 4px solid var(--cyan);">
        <h3>⚙️ Memory-Hard KDFs</h3>
        <p>Switching from fast hashes (SHA-1, MD5) to slow, memory-hard algorithms (Argon2id, scrypt, bcrypt) makes precomputation computationally prohibitive.</p>
    </div>
    """, unsafe_allow_html=True)
with col_def3:
    st.markdown("""
    <div class="glass-card" style="border-left: 4px solid var(--purple);">
        <h3>🔑 Multi-Factor Auth</h3>
        <p>FIDO2 security keys and time-based one-time passwords (TOTP) protect user accounts even if credential digests are compromised in a database leak.</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br><br>", unsafe_allow_html=True)

# Footer
st.markdown("""
<div style="text-align: center; color: var(--text-dim); font-size: 0.85rem; padding: 20px 0;">
    © Rainbow Table Attack Educational Suite — Strictly for Educational and Defensive Research.
</div>
""", unsafe_allow_html=True)
