import streamlit as st
import hashlib
import time
import pandas as pd

# --- 1. Core Logic Functions (SHA-1 Hashing and Reduction) ---

# Dictionary for the demo table, matching script.js
DEMO_DICT = [
    'helloworld', 'admin123', 'letmein', 'welcome', 'master', 'sunshine', 'dragon', 'monkey'
]

def hash_password_sha1(password):
    """Hashes a password using SHA-1 (40 hex chars)."""
    return hashlib.sha1(password.encode()).hexdigest()

def reduce_to_word(hash_hex, dictionary):
    """Reduction function: maps hash to a word from the dictionary (matching script.js)."""
    n = len(dictionary)
    sum_val = 0
    # Sum up the integer values of every two hex characters
    for i in range(0, len(hash_hex), 2):
        try:
            sum_val += int(hash_hex[i:i + 2], 16)
        except ValueError:
            pass
    return dictionary[sum_val % n]

def build_rainbow_table(dictionary):
    """Builds the in-memory rainbow table (start word -> SHA-1 hash endpoint)."""
    table = []
    for word in dictionary:
        h = hash_password_sha1(word)
        table.append({'Start Password': word, 'SHA-1 Hash': h})
    return table

def crack_hash(target_hash, rainbow_table, dictionary):
    """Attempts to crack the hash using direct lookup and 1-step reduction."""
    target_hash = target_hash.lower().strip()
    
    # 1. Direct Lookup (Hash is found as an endpoint)
    for row in rainbow_table:
        if row['SHA-1 Hash'] == target_hash:
            return {'found': True, 'password': row['Start Password'], 'method': 'Direct lookup'}

    # No reduction/backtracking: only direct lookup is used for this demo.
    # This ensures that entering an incorrect/unknown hash returns 'not found'.
    return {'found': False}


# --- 2. Streamlit UI Setup and Callbacks ---

st.set_page_config(
    page_title="Rainbow Table Attack Demo",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for high visual fidelity, matching styles.css colors and structure
st.markdown("""
<style>
/* --- Color Variables from styles.css --- */
:root {
    --bg: #0b0f1a;
    --panel: #111827;
    --panel-2: #0f172a;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --accent: #3b82f6;
    --accent-2: #8b5cf6;
    --success: #22c55e;
    --danger: #ef4444;
}

/* --- General Styling --- */
.stApp { background-color: var(--bg); color: var(--text); }

/* --- Headings (Matching color and weight) --- */
h1.hero-title {
    /* Gradient-filled headline for stronger visual impact */
    background: linear-gradient(90deg, #60a5fa 0%, #8b5cf6 50%, #f472b6 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    color: transparent;
    font-size: clamp(48px, 7vw, 96px);
    font-weight: 900;
    letter-spacing: -0.5px;
    line-height: 1.02;
    margin-bottom: 12px;
    text-shadow: 0 6px 18px rgba(59,130,246,0.12), 0 2px 6px rgba(0,0,0,0.6);
    filter: drop-shadow(0 10px 30px rgba(139,92,246,0.06));
}
h2.section-title {
    color: #1e90ff;
    font-size: 44px;
    font-weight: 800;
    margin-top: 40px;
}
.subtitle, .stMarkdown p { color: var(--muted); max-width: 900px; }

/* --- Panel & Card Styling --- */
.stContainer {
    background: var(--panel);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 16px;
}
.card-style {
    background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 16px;
    padding: 26px;
    box-shadow: 0 10px 30px rgba(0,0,0,.35); /* Mimic var(--shadow) */
    height: 100%;
}
.card-style h3 { margin: 0 0 6px; color: #e5e7eb; }
.card-style p { margin: 0; }

/* --- Badge Styling --- */
.badge-style {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: #0b1222;
    border: 1px dashed rgba(255,255,255,.2);
    color: #e2e8f0;
    padding: 10px 14px;
    border-radius: 12px;
    font-size: 14px;
    margin-top: 20px;
    margin-bottom: 20px;
}

/* --- Button Styling (Matching btn, btn.primary, btn.pill, btn.tag) --- */
.stButton>button { border-radius: 12px; }
.stButton>button[kind="primary"] {
    background: linear-gradient(180deg, var(--accent), #2563eb);
    color: #081226;
    font-weight: 700;
    border: none;
}
.pill-btn>button {
    background: linear-gradient(180deg, var(--accent-2), #6d28d9);
    color: white;
    border-radius: 999px;
    padding: 8px 14px;
    font-weight: 700;
    border: none;
}
.tag-btn>button {
    padding: 6px 10px;
    border-radius: 999px;
    background: linear-gradient(180deg, #1f2937,#111827);
    border: 1px solid rgba(255,255,255,.1);
}

/* --- Utility/Text Styles --- */
.list-clean b { color: #60a5fa; }
code, pre { background: #0b1222; border: 1px solid rgba(255,255,255,.08); padding: 2px 6px; border-radius: 6px; }
pre { padding: 14px; overflow: auto; }
</style>
""", unsafe_allow_html=True)


# --- Initialize Session State ---
if 'rainbow_table' not in st.session_state:
    st.session_state.rainbow_table = None
if 'build_status' not in st.session_state:
    st.session_state.build_status = "—"
if 'target_hash' not in st.session_state:
    st.session_state.target_hash = ""
if 'crack_result' not in st.session_state:
    st.session_state.crack_result = None

# --- Callbacks ---
def set_hash(hash_value):
    """Callback to set the target hash in session state."""
    st.session_state.target_hash = hash_value
    st.session_state.crack_result = None # Clear result when hash changes

def build_table_callback():
    """Callback to build the table."""
    with st.spinner('Building…'):
        time.sleep(1) # Simulate computation time
        st.session_state.rainbow_table = build_rainbow_table(DEMO_DICT)
        st.session_state.build_status = f"✓ Rainbow table built with {len(st.session_state.rainbow_table)} precomputed hashes"
        st.session_state.crack_result = None # Clear result

def crack_callback():
    """Callback to handle the cracking process."""
    h = st.session_state.hash_input_field.strip()
    
    if not h:
        st.session_state.crack_result = {'found': False, 'message': 'Please enter or generate a hash first.', 'style': 'info'}
        return
    
    st.session_state.target_hash = h # Update target hash from input field
    
    if st.session_state.rainbow_table is None:
        st.session_state.crack_result = {'found': False, 'message': 'Please build the table first.', 'style': 'error'}
        return
        
    # Show "Working" message briefly
    with st.spinner('Working…'):
        time.sleep(0.5)
        result = crack_hash(
            st.session_state.target_hash, 
            st.session_state.rainbow_table, 
            DEMO_DICT
        )
    
    # Store final result
    if result['found']:
        st.session_state.crack_result = {
            'found': True, 
            'message': f"Password: {result['password']} ({result['method']})",
            'style': 'success'
        }
    else:
        st.session_state.crack_result = {
            'found': False, 
            'message': 'Not found in demo table.',
            'style': 'error'
        }


# --- 3. UI Layout (Sections) ---

# Nav/Brand Mimic
# We use a header and markdown to simulate the sticky brand element
st.markdown('<div class="nav-inner" style="position: sticky; top: 0; z-index: 50; padding: 14px 0; border-bottom: 1px solid rgba(255,255,255,.06); background-color: var(--bg); backdrop-filter: saturate(1.2) blur(8px);"><div class="brand"><span class="lock" style="display: grid; place-items: center; width: 28px; height: 28px; border-radius: 8px; background: var(--panel); border: 1px solid rgba(255,255,255,.08);">🔐</span> Rainbow Table Attack</div></div>', unsafe_allow_html=True)


# ----------------- HOME/HERO SECTION -----------------
st.markdown('<a id="home"></a>', unsafe_allow_html=True)
st.markdown('<div style="padding: 40px 0;">', unsafe_allow_html=True) # Mimic hero padding
st.markdown('<h1 class="hero-title">Rainbow Table Attack</h1>', unsafe_allow_html=True)
st.markdown(
    """
    <p class="subtitle">Learn how rainbow table attacks work and understand password security vulnerabilities. 
    Explore the theory, implementation procedure, an interactive mini-simulation, and simple code examples. 
    For learning &amp; awareness only.</p>
    """, unsafe_allow_html=True
)

# Card Grid (Mimic)
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown(
        """<div class="card-style"><h3>🧩 Theory</h3><p>What rainbow tables are, why they’re effective, and the role of hashing and reduction functions.</p></div>""", 
        unsafe_allow_html=True
    )
with col2:
    st.markdown(
        """<div class="card-style"><h3>🛠️ Procedure</h3><p>Step-by-step overview of creating and using a rainbow table against unsalted hashes.</p></div>""", 
        unsafe_allow_html=True
    )
with col3:
    st.markdown(
        """<div class="card-style"><h3>⚡ Simulation</h3><p>Interactive demo that precomputes a tiny table and attempts to crack a given hash.</p></div>""", 
        unsafe_allow_html=True
    )

# Badge (Mimic)
st.markdown(
    """
    <div class="badge-style">
        💡 <strong>Security Note</strong>: This educational site demonstrates attack concepts. Always use strong, unique passwords and hashing algorithms with salt and key stretching (e.g., bcrypt, scrypt, Argon2).
    </div>
    """, unsafe_allow_html=True
)
st.markdown('</div>', unsafe_allow_html=True) # Close hero padding div
st.markdown('<hr style="border-top: 1px solid rgba(255,255,255,.06); margin: 0;">', unsafe_allow_html=True) # Separator


# ----------------- THEORY SECTION -----------------
st.markdown('<a id="theory"></a>', unsafe_allow_html=True)
st.markdown('<div style="padding: 64px 0;">', unsafe_allow_html=True) # Mimic section padding
st.markdown('<h2 class="section-title">Rainbow Table Theory</h2>', unsafe_allow_html=True)

# Panel 1
with st.container():
    st.subheader("What is a Rainbow Table?")
    st.markdown(
        """
        <p class="subtitle">A precomputed table for cracking password hashes. Instead of hashing every guess, it looks up hashes that were pre-calculated and stored, making password cracking much faster.</p>
        """, unsafe_allow_html=True
    )

# Panel 2
with st.container():
    st.subheader("Key Concepts")
    st.markdown(
        """
        <ul class="list-clean">
          <li><b>Hash:</b> One-way function (e.g., SHA-256, MD5) that converts a password to a fixed hex string.</li>
          <li><b>Reduction:</b> Converts a hash back to a password-like candidate.</li>
          <li><b>Chain:</b> Alternates hash → reduce → hash → reduce… to build lookup tables.</li>
          <li><b>Salt:</b> Random data added before hashing to break rainbow tables.</li>
        </ul>
        """, unsafe_allow_html=True
    )

# Panel 3
with st.container():
    st.subheader("How It Works")
    st.markdown(
        """
        <ol class="muted-list">
          <li>Build chains: password → hash → reduce → hash → reduce…</li>
          <li>Store only chain start and end points (saves memory).</li>
          <li>Given target hash, apply reduction and search the table.</li>
          <li>If match found, backtrack chain to recover original password.</li>
        </ol>
        """, unsafe_allow_html=True
    )

# Panel 4 (Two-Column)
col_why, col_stop = st.columns(2)
with col_why:
    with st.container():
        st.markdown('<strong>Why Effective:</strong>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">Much faster than brute force; trades storage for computation.</p>', unsafe_allow_html=True)
with col_stop:
    with st.container():
        st.markdown('<strong>How to Stop It:</strong>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">Use salts + slow hashes (bcrypt, Argon2, scrypt) and enable MFA/2FA.</p>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True) # Close section padding div
st.markdown('<hr style="border-top: 1px solid rgba(255,255,255,.06); margin: 0;">', unsafe_allow_html=True) # Separator

# ----------------- PROCEDURE SECTION -----------------
st.markdown('<a id="procedure"></a>', unsafe_allow_html=True)
st.markdown('<div style="padding: 64px 0;">', unsafe_allow_html=True) # Mimic section padding
st.markdown('<h2 class="section-title">Implementation Steps</h2>', unsafe_allow_html=True)

# Panel 1
with st.container():
    st.subheader("1. Create Hash Function")
    st.markdown(
        """
        <p class="subtitle">Converts a password to its fixed-length hexadecimal representation using a one-way hashing algorithm.</p>
        <code>password → SHA-256 hash (hex string)</code>
        """, unsafe_allow_html=True
    )

# Panel 2
with st.container():
    st.subheader("2. Create Reduction Function")
    st.markdown(
        """
        <p class="subtitle">Transforms a hash back into a password-like candidate by mapping bytes to a defined charset.</p>
        <code>hex hash → take bytes → map to charset → password candidate</code>
        """, unsafe_allow_html=True
    )

# Panel 3
with st.container():
    st.subheader("3. Build Chains")
    st.markdown(
        """
        <p class="subtitle">Each chain starts from a password, repeatedly applies hashing and reduction functions, and stores only the start and end points for efficiency.</p>
        <code>password → hash → reduce → hash → reduce (repeat n times)</code>
        """, unsafe_allow_html=True
    )

# Panel 4
with st.container():
    st.subheader("4. Crack Hash")
    st.markdown(
        """
        <p class="subtitle">Given a target hash, iteratively reduce and look it up in the rainbow table. If a match is found, regenerate the chain to recover the original password.</p>
        <code>target hash → reduce → lookup → match → recover password</code>
        """, unsafe_allow_html=True
    )

# Panel 5
with st.container():
    st.subheader("Performance")
    st.markdown(
        """
        <p class="subtitle">Rainbow tables drastically reduce cracking time by precomputing hashes, trading off storage space for speed. They are highly optimized compared to brute-force methods.</p>
        <code>Build: O(n × m) | Crack: O(m)</code>
        """, unsafe_allow_html=True
    )

st.markdown('</div>', unsafe_allow_html=True) # Close section padding div
st.markdown('<hr style="border-top: 1px solid rgba(255,255,255,.06); margin: 0;">', unsafe_allow_html=True) # Separator


# ----------------- SIMULATION SECTION -----------------
st.markdown('<a id="simulation"></a>', unsafe_allow_html=True)
st.markdown('<div style="padding: 64px 0;">', unsafe_allow_html=True) # Mimic section padding
st.markdown('<h2 class="section-title">Interactive Simulation</h2>', unsafe_allow_html=True)

# Panel 1: Build Table
with st.container():
    st.subheader("Step 1: Build Rainbow Table")
    st.markdown("<p class='subtitle'>Create a precomputed table that maps password hashes to original passwords.</p>", unsafe_allow_html=True)
    
    st.markdown('<div class="pill-btn">', unsafe_allow_html=True)
    st.button(
        label="Build Table", 
        key="build_btn_key",
        on_click=build_table_callback, 
        disabled=(st.session_state.rainbow_table is not None)
    )
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown(f'<div class="panel status-panel"><span id="build-status" style="color:var(--muted);">{st.session_state.build_status}</span></div>', unsafe_allow_html=True)


# Conditional Panels (Step 2 and 3 require the table to be built)
if st.session_state.rainbow_table is not None:
    
    # Panel 2: Generate Test Hash
    with st.container():
        st.subheader("Step 2: Generate Test Hash")
        st.markdown("<p class='subtitle'>Click a password to generate its hash:</p>", unsafe_allow_html=True)
        
        st.markdown('<div class="sample-wrap">', unsafe_allow_html=True) # Mimic sample-wrap
        col_samples = st.columns(len(DEMO_DICT))
        for i, word in enumerate(DEMO_DICT):
            hash_val = hash_password_sha1(word)
            col_samples[i].button(
                label=word, 
                key=f"sample_btn_{word}", 
                on_click=set_hash, 
                args=(hash_val,),
            )
        st.markdown('</div>', unsafe_allow_html=True)

    # Panel 3: Crack the Password
    with st.container():
        st.subheader("Step 3: Crack the Password")
        st.markdown("<p class='subtitle'>Enter a hash or select from above, then look it up in the rainbow table:</p>", unsafe_allow_html=True)

        col_input, col_crack = st.columns([3, 1])
        with col_input:
            st.text_input(
                label="Target Hash (40 hex characters)", 
                value=st.session_state.target_hash, 
                key="hash_input_field", 
                label_visibility="collapsed",
                placeholder="Enter hash manually (40 hex characters)"
            )
        
        with col_crack:
            st.button(
                label="Crack Hash", 
                key="crack_btn_key_final",
                on_click=crack_callback
            )
        
        # Crack Result Output Panel (Mimic result-panel)
        if st.session_state.crack_result:
            result = st.session_state.crack_result
            
            # Use specific CSS for success/danger output
            if result['style'] == 'success':
                st.markdown(f'<div class="panel result-panel"><strong style="color:var(--success);">{result["message"]}</strong></div>', unsafe_allow_html=True)
            elif result['style'] == 'error':
                st.markdown(f'<div class="panel result-panel"><strong style="color:var(--danger);">{result["message"]}</strong></div>', unsafe_allow_html=True)
            else: # Info/Muted
                 st.markdown(f'<div class="panel result-panel"><strong style="color:var(--muted);">{result["message"]}</strong></div>', unsafe_allow_html=True)


    # Panel 4: Info and Table Preview
    st.markdown('<div class="stContainer" style="border-style:dashed;">', unsafe_allow_html=True)
    st.markdown("💡 **How it works:** A rainbow table is a precomputed database of hashes. Instead of trying millions of passwords, we instantly look up the hash to find the match. Real tables contain billions of hashes for faster password cracking.", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<strong>Table Preview</strong>", unsafe_allow_html=True)
        # Display table within a container to mimic the table-wrap
        df_table = pd.DataFrame(st.session_state.rainbow_table)
        st.markdown('<div class="table-wrap">', unsafe_allow_html=True)
        st.dataframe(df_table, use_container_width=True, height=250)
        st.markdown('</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True) # Close section padding div
st.markdown('<hr style="border-top: 1px solid rgba(255,255,255,.06); margin: 0;">', unsafe_allow_html=True) # Separator


# ----------------- CODE SECTION -----------------
st.markdown('<a id="code"></a>', unsafe_allow_html=True)
st.markdown('<div style="padding: 64px 0;">', unsafe_allow_html=True) # Mimic section padding
st.markdown('<h2 class="section-title">Core Code</h2>', unsafe_allow_html=True)

with st.container():
    st.subheader("Reference Implementation (Python)")
    st.markdown(
        """
        <p class="subtitle">This script builds a small rainbow table with position-dependent reduction, then attempts to crack a target hash. It is for education only.</p>
        """, unsafe_allow_html=True
    )
    st.code(
        """
#Generate Test Hash 

import hashlib

def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


#Crack the Password


def crack_hash(target_hash, rainbow_table):
    for password, hash_value in rainbow_table.items():
        if hash_value == target_hash:
            return password
    return "Not found"
        """, 
        language="python"
    )

st.markdown('</div>', unsafe_allow_html=True) # Close section padding div
st.markdown('<hr style="border-top: 1px solid rgba(255,255,255,.06); margin: 0;">', unsafe_allow_html=True) # Separator


# ----------------- CONCLUSION SECTION -----------------
st.markdown('<a id="conclusion"></a>', unsafe_allow_html=True)
st.markdown('<div style="padding: 64px 0;">', unsafe_allow_html=True) # Mimic section padding
st.markdown('<h2 class="section-title">Conclusion</h2>', unsafe_allow_html=True)

with st.container():
    st.subheader("Summary & Recommendations")
    st.markdown(
        """
        <p class="subtitle">
        Rainbow table attacks demonstrate how easily weak and unsalted password hashes can be reversed using precomputed lookup tables. To protect systems, always store passwords with unique per-user salts and a slow, memory-hard hashing algorithm (for example bcrypt, scrypt, or Argon2). Enforce strong password policies, enable multi-factor authentication, and monitor for suspicious activity — these measures together greatly reduce the risk of hash-based attacks and strengthen overall password security.
        </p>
        """, unsafe_allow_html=True
    )

st.markdown('</div>', unsafe_allow_html=True) # Close section padding div

# Footer
st.markdown('<footer style="padding: 40px 0; color: var(--muted); border-top: 1px solid rgba(255,255,255,.06);">© 2024 Rainbow Table Attack – Educational use only.</footer>', unsafe_allow_html=True)
