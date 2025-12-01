import streamlit as st
import hashlib
import time
import pandas as pd

# --- 1. Core Logic Functions (Adapted from script.js) ---

# Dictionary for the demo table
DEMO_DICT = [
    'helloworld', 'admin123', 'letmein', 'welcome', 'master', 'sunshine', 'dragon', 'monkey'
]

def hash_password_sha1(password):
    """Hashes a password using SHA-1 (used in the simulation for simplicity/speed)."""
    # Matches the original JavaScript implementation's choice of SHA-1
    return hashlib.sha1(password.encode()).hexdigest()

def reduce_to_word(hash_hex, dictionary):
    """Tiny reduction function: maps hash to a word from the dictionary."""
    n = len(dictionary)
    sum_val = 0
    # Process the hash by taking hex pairs and summing their integer values
    for i in range(0, len(hash_hex), 2):
        try:
            sum_val += int(hash_hex[i:i + 2], 16)
        except ValueError:
            pass
    return dictionary[sum_val % n]

def build_rainbow_table(dictionary):
    """Builds the in-memory rainbow table (SHA-1)."""
    table = []
    for word in dictionary:
        h = hash_password_sha1(word)
        table.append({'start': word, 'hash': h})
    return table

def crack_hash(target_hash, rainbow_table, dictionary):
    """Attempts to crack the hash using direct lookup and 1-step reduction."""
    target_hash = target_hash.lower().strip()
    
    # 1. Direct Lookup
    for row in rainbow_table:
        if row['hash'] == target_hash:
            return {'found': True, 'password': row['start'], 'method': 'Direct lookup'}

    # 2. 1-Step Reduction Check
    try:
        # Perform the reduction as the first step of a potential chain
        reduced_word = reduce_to_word(target_hash, dictionary)
        h2 = hash_password_sha1(reduced_word)
        
        # Check if this computed hash (h2) is an endpoint in the table
        for row in rainbow_table:
            if row['hash'] == h2:
                # If h2 matches an endpoint, the original password (row['start']) is the crack
                return {'found': True, 'password': row['start'], 'method': '1-step reduction/Backtracking'}
    except Exception:
        pass
        
    return {'found': False}


# --- 2. Streamlit UI Setup and Callbacks ---

st.set_page_config(
    page_title="Rainbow Table Attack Demo",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for styling the sections (mimicking styles.css)
st.markdown("""
<style>
/* Main body colors */
.stApp {
    background-color: #0b0f1a;
    color: #e5e7eb;
}
/* Title and Section Titles */
.title {
    color: #1e90ff;
    font-size: 3.5rem;
    font-weight: 800;
}
.section-title {
    color: #1e90ff;
    font-size: 2.75rem;
    font-weight: 800;
    margin-top: 40px;
    margin-bottom: 10px;
}
/* Subtitle/Muted text */
.subtitle, .stMarkdown p {
    color: #9ca3af;
    max-width: 900px;
}
/* Card-like panels (using st.container + custom CSS) */
.stContainer {
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 16px;
    background: #111827;
}
/* Card Grid mimic */
.card-style {
    background: linear-gradient(180deg, #111827 0%, #0f172a 100%);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 16px;
    padding: 26px;
    height: 100%;
}
.card-style h3 { color: #60a5fa; }
/* Badge mimic */
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
/* List styling for Key Concepts */
ul { padding-left: 20px; }
ul b { color: #60a5fa; }
</style>
""", unsafe_allow_html=True)


# Initialize session state for the table and status
if 'rainbow_table' not in st.session_state:
    st.session_state.rainbow_table = None
if 'build_status' not in st.session_state:
    st.session_state.build_status = "—"
if 'target_hash' not in st.session_state:
    st.session_state.target_hash = ""


# --- Callbacks for button actions ---

def set_hash(hash_value):
    """Callback to set the target hash in session state."""
    st.session_state.target_hash = hash_value

def build_table_callback():
    """Callback to build the table."""
    with st.spinner('Building table…'):
        time.sleep(1) # Simulate computation time
        st.session_state.rainbow_table = build_rainbow_table(DEMO_DICT)
        st.session_state.build_status = f"✓ Rainbow table built with {len(st.session_state.rainbow_table)} precomputed hashes"

# --- UI Layout ---

# Mimic the Nav/Menu by creating an anchor map (Streamlit has no direct anchor support)
st.markdown("## 🔐 Rainbow Table Attack", unsafe_allow_html=True)
st.divider()

# ----------------- HOME/HERO SECTION -----------------
st.markdown('<a name="home"></a>', unsafe_allow_html=True)
st.markdown('<p class="title">Rainbow Table Attack</p>', unsafe_allow_html=True)
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
    with st.container():
        st.markdown(
            """
            <div class="card-style">
                <h3>🧩 Theory</h3>
                <p>What rainbow tables are, why they’re effective, and the role of hashing and reduction functions.</p>
            </div>
            """, unsafe_allow_html=True
        )
with col2:
    with st.container():
        st.markdown(
            """
            <div class="card-style">
                <h3>🛠️ Procedure</h3>
                <p>Step-by-step overview of creating and using a rainbow table against unsalted hashes.</p>
            </div>
            """, unsafe_allow_html=True
        )
with col3:
    with st.container():
        st.markdown(
            """
            <div class="card-style">
                <h3>⚡ Simulation</h3>
                <p>Interactive demo that precomputes a tiny table and attempts to crack a given hash.</p>
            </div>
            """, unsafe_allow_html=True
        )

# Badge (Mimic)
st.markdown(
    """
    <div class="badge-style">
        💡 <strong>Security Note</strong>: This educational site demonstrates attack concepts. Always use strong, unique passwords and hashing algorithms with salt and key stretching (e.g., bcrypt, scrypt, Argon2).
    </div>
    """, unsafe_allow_html=True
)

st.divider()

# ----------------- THEORY SECTION -----------------
st.markdown('<a name="theory"></a>', unsafe_allow_html=True)
st.markdown('<p class="section-title">Rainbow Table Theory</p>', unsafe_allow_html=True)


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
        st.markdown('<strong class="why">Why Effective:</strong>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">Much faster than brute force; trades storage for computation.</p>', unsafe_allow_html=True)
with col_stop:
    with st.container():
        st.markdown('<strong class="why">How to Stop It:</strong>', unsafe_allow_html=True)
        st.markdown('<p class="subtitle">Use salts + slow hashes (bcrypt, Argon2, scrypt) and enable MFA/2FA.</p>', unsafe_allow_html=True)

st.divider()

# ----------------- PROCEDURE SECTION -----------------
st.markdown('<a name="procedure"></a>', unsafe_allow_html=True)
st.markdown('<p class="section-title">Implementation Steps</p>', unsafe_allow_html=True)

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

st.divider()

# ----------------- SIMULATION SECTION -----------------
st.markdown('<a name="simulation"></a>', unsafe_allow_html=True)
st.markdown('<p class="section-title">Interactive Simulation</p>', unsafe_allow_html=True)

# Panel 1: Build Table
with st.container():
    st.subheader("Step 1: Build Rainbow Table")
    st.markdown("<p class='subtitle'>Create a precomputed table that maps password hashes to original passwords.</p>", unsafe_allow_html=True)
    
    st.button(
        label="Build Table (SHA-1)", 
        key="build_btn",
        on_click=build_table_callback, 
        disabled=(st.session_state.rainbow_table is not None)
    )
    st.info(f"Status: {st.session_state.build_status}")

# Panel 2: Generate Test Hash
if st.session_state.rainbow_table:
    with st.container():
        st.subheader("Step 2: Generate Test Hash")
        st.markdown("<p class='subtitle'>Click a password to generate its hash:</p>", unsafe_allow_html=True)
        
        # Use columns for sample buttons
        col_samples = st.columns(len(DEMO_DICT))
        for i, word in enumerate(DEMO_DICT):
            hash_val = hash_password_sha1(word)
            col_samples[i].button(
                label=word, 
                key=f"sample_btn_{word}", 
                on_on_click=set_hash, 
                args=(hash_val,)
            )

# Panel 3: Crack the Password
with st.container():
    st.subheader("Step 3: Crack the Password")
    st.markdown("<p class='subtitle'>Enter a hash or select from above, then look it up in the rainbow table:</p>", unsafe_allow_html=True)

    col_input, col_crack = st.columns([3, 1])
    with col_input:
        target_hash_input = st.text_input(
            label="Target Hash", 
            value=st.session_state.target_hash, 
            key="hash_input_field", 
            label_visibility="collapsed",
            placeholder="Enter hash manually (40 hex characters)"
        )
    
    with col_crack:
        def crack_callback():
            # Update the session state hash from the input field before cracking
            st.session_state.target_hash = st.session_state.hash_input_field
            
        crack_button = st.button(
            label="Set Hash & Crack", 
            key="crack_btn_2",
            on_click=crack_callback
        )

    # Crack Result
    if crack_button and st.session_state.target_hash and st.session_state.rainbow_table:
        st.markdown("---")
        with st.spinner('Working…'):
            time.sleep(0.5)
            result = crack_hash(
                st.session_state.target_hash, 
                st.session_state.rainbow_table, 
                DEMO_DICT
            )
        
        if result['found']:
            st.success(f"🔓 **Password: {result['password']}** \n\n**Method:** {result['method']}")
        else:
            st.error("❌ **Not found** in demo table.")
            
        st.markdown(f"**Target Hash:** `{st.session_state.target_hash}`")
        st.markdown("---")

# Panel 4: Table Preview
if st.session_state.rainbow_table:
    with st.container():
        st.markdown("💡 **How it works:** A rainbow table is a precomputed database of hashes. Instead of trying millions of passwords, we instantly look up the hash to find the match. Real tables contain billions of hashes for faster password cracking.", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<strong>Table Preview</strong>", unsafe_allow_html=True)
        # Convert to DataFrame for better table rendering
        df_table = pd.DataFrame(st.session_state.rainbow_table)
        st.dataframe(df_table, use_container_width=True)

st.divider()

# ----------------- CODE SECTION -----------------
st.markdown('<a name="code"></a>', unsafe_allow_html=True)
st.markdown('<p class="section-title">Core Code</p>', unsafe_allow_html=True)

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

st.divider()

# ----------------- CONCLUSION SECTION -----------------
st.markdown('<a name="conclusion"></a>', unsafe_allow_html=True)
st.markdown('<p class="section-title">Conclusion</p>', unsafe_allow_html=True)

with st.container():
    st.subheader("Summary & Recommendations")
    st.markdown(
        """
        <p class="subtitle">
        Rainbow table attacks demonstrate how easily weak and unsalted password hashes can be reversed using precomputed lookup tables. To protect systems, always store passwords with unique per-user salts and a slow, memory-hard hashing algorithm (for example **bcrypt**, **scrypt**, or **Argon2**). Enforce strong password policies, enable multi-factor authentication, and monitor for suspicious activity — these measures together greatly reduce the risk of hash-based attacks and strengthen overall password security.
        </p>
        """, unsafe_allow_html=True
    )

# Footer
st.caption("© 2024 Rainbow Table Attack – Educational use only.")
