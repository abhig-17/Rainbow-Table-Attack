import streamlit as st
import hashlib
import time

# --- 1. Core Logic Functions (Adapted from script.js) ---

# Dictionary for the demo table
DEMO_DICT = [
    'helloworld', 'admin123', 'letmein', 'welcome', 'master', 'sunshine', 'dragon', 'monkey'
]

def hash_password_sha256(password):
    """Hashes a password using SHA-256 and returns a hex string."""
    # Use SHA-256 for the main text, SHA-1 for the simulation, matching script.js
    return hashlib.sha256(password.encode()).hexdigest()

def hash_password_sha1(password):
    """Hashes a password using SHA-1 (used in the simulation for simplicity/speed)."""
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
            # Handle potential non-hex characters if the hash length isn't perfectly even, though it should be.
            pass
    return dictionary[sum_val % n]

def build_rainbow_table(dictionary):
    """Builds the in-memory rainbow table (similar to script.js)."""
    table = []
    for word in dictionary:
        # NOTE: Using SHA-1 to match the original JavaScript simulation for consistency.
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

    # 2. 1-Step Reduction (Simplified chain search for the demo)
    try:
        reduced_word = reduce_to_word(target_hash, dictionary)
        # Hash the reduced word
        h2 = hash_password_sha1(reduced_word)
        
        # Check if the reduced hash matches any chain endpoint in the table
        for row in rainbow_table:
            if row['hash'] == h2:
                # If a match is found on the reduced hash, the starting word *is* the crack result 
                # in this simplified demo, but in a real RT, you'd backtrack from the start point.
                # Since the demo table is small, we'll just check if the reduced word is the start word.
                # A more correct approach for a 1-step chain is to hash the previous reduction.
                # For this simplified demo, we stick to the script.js logic:
                return {'found': True, 'password': row['start'], 'method': '1-step reduction (Simplified)'}
    except Exception:
        # General exception handling for reduction errors
        pass
        
    return {'found': False}


# --- 2. Streamlit UI and Callbacks ---

st.set_page_config(
    page_title="Rainbow Table Attack Demo",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for styling (similar to your styles.css)
st.markdown("""
<style>
/* Streamlit main background and text colors */
.stApp {
    background-color: #0b0f1a;
    color: #e5e7eb;
}
/* Title style */
h1 {
    color: #1e90ff;
    font-size: 3.5rem;
    font-weight: 800;
}
/* Section title style */
h2 {
    color: #1e90ff;
    font-size: 2.75rem;
    font-weight: 800;
    padding-top: 20px;
}
/* Subtitle/muted text */
.stMarkdown p {
    color: #9ca3af;
}
/* The main content blocks (panels in your design) */
.block-container {
    padding-top: 1rem;
    padding-bottom: 0rem;
}
.stTabs [data-baseweb="tab-list"] button {
    background-color: #111827;
    color: #e5e7eb;
    border-radius: 10px 10px 0 0;
    padding: 10px 20px;
}
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
    with st.spinner('Building table...'):
        time.sleep(1) # Simulate computation time
        st.session_state.rainbow_table = build_rainbow_table(DEMO_DICT)
        st.session_state.build_status = f"✓ Rainbow table built with {len(st.session_state.rainbow_table)} precomputed hashes."


# --- UI Layout ---

# Header (Hero)
st.title("Rainbow Table Attack")
st.markdown(
    """
    Learn how rainbow table attacks work and understand password security vulnerabilities. 
    Explore the theory, implementation procedure, an interactive mini-simulation, and simple code examples. 
    **For learning & awareness only.**
    """
)
st.divider()


# Tabs for navigation (replacing the top menu)
tab_theory, tab_procedure, tab_simulation, tab_code, tab_conclusion = st.tabs(
    ["🧩 Theory", "🛠️ Procedure", "⚡ Simulation", "💻 Code", "💡 Conclusion"]
)


# --- Theory Section ---
with tab_theory:
    st.header("Rainbow Table Theory")
    st.subheader("What is a Rainbow Table?")
    st.markdown(
        """
        A **precomputed table** for cracking password hashes. Instead of hashing every guess (brute force), 
        it looks up hashes that were pre-calculated and stored, making password cracking much **faster**.
        """
    )
    
    st.subheader("Key Concepts")
    st.markdown(
        """
        * **Hash**: One-way function (e.g., SHA-256, MD5) that converts a password to a fixed hex string.
        * **Reduction**: Converts a hash back to a **password-like candidate**. This is NOT an un-hashing function; it's a way to generate the next word in the chain.
        * **Chain**: Alternates **hash → reduce → hash → reduce…** to build lookup tables.
        * **Salt**: Random data added before hashing to **break rainbow tables**.
        """
    )
    
    st.subheader("How It Works")
    st.markdown(
        """
        1.  Build chains: `password → hash → reduce → hash → reduce…`
        2.  Store only chain **start and end points** (saves memory).
        3.  Given target hash, apply the **reduction function** and search the table.
        4.  If a match is found, backtrack the chain to recover the original password.
        """
    )
    
    col_effective, col_stop = st.columns(2)
    with col_effective:
        st.markdown("**Why Effective:**")
        st.markdown("Much faster than brute force; trades cheap storage space for expensive computation time.")
    with col_stop:
        st.markdown("**How to Stop It:**")
        st.markdown("Use **salts** + slow hashes (**bcrypt**, **Argon2**, **scrypt**) and enable MFA/2FA.")


# --- Procedure Section ---
with tab_procedure:
    st.header("Implementation Steps")
    
    st.subheader("1. Create Hash Function")
    st.markdown(
        """
        Converts a password to its fixed-length hexadecimal representation using a one-way hashing algorithm.
        
        `password → SHA-256 hash (hex string)`
        """
    )
    
    st.subheader("2. Create Reduction Function")
    st.markdown(
        """
        Transforms a hash back into a password-like candidate by mapping bytes to a defined charset or dictionary.
        
        `hex hash → take bytes → map to charset → password candidate`
        """
    )
    
    st.subheader("3. Build Chains")
    st.markdown(
        """
        Each chain starts from a password, repeatedly applies hashing and reduction functions, and stores only the start and end points for efficiency.
        
        `password → hash → reduce → hash → reduce (repeat n times)`
        """
    )
    
    st.subheader("4. Crack Hash")
    st.markdown(
        """
        Given a target hash, iteratively reduce and look it up in the rainbow table. If a match is found, regenerate the chain to recover the original password.
        
        `target hash → reduce → lookup → match → recover password`
        """
    )
    
    st.subheader("Performance")
    st.markdown(
        """
        Rainbow tables drastically reduce cracking time by precomputing hashes, trading off storage space for speed. They are highly optimized compared to brute-force methods.
        
        `Build: O(n × m) | Crack: O(m)`
        """
    )


# --- Simulation Section ---
with tab_simulation:
    st.header("Interactive Simulation")

    # Step 1: Build Table
    st.subheader("Step 1: Build Rainbow Table")
    st.markdown("Create a precomputed table that maps password hashes to original passwords.")
    st.button(
        label="Build Demo Table (SHA-1)", 
        on_click=build_table_callback, 
        disabled=(st.session_state.rainbow_table is not None)
    )
    st.info(st.session_state.build_status)
    
    # Step 2: Generate Test Hash
    if st.session_state.rainbow_table:
        st.subheader("Step 2: Generate Test Hash")
        st.markdown("Click a password to generate its hash:")
        
        col_samples = st.columns(len(DEMO_DICT))
        for i, word in enumerate(DEMO_DICT):
            hash_val = hash_password_sha1(word)
            col_samples[i].button(
                label=word, 
                key=f"sample_btn_{word}", 
                on_click=set_hash, 
                args=(hash_val,)
            )

        # Step 3: Crack Hash
        st.subheader("Step 3: Crack the Password")
        st.markdown("Enter a hash or select from above, then look it up in the rainbow table:")
        
        
        col_input, col_crack = st.columns([3, 1])
        with col_input:
            # Hash input field
            st.text_input(
                label="Target Hash (SHA-1 Hex String)", 
                value=st.session_state.target_hash, 
                key="hash_input_field", 
                label_visibility="collapsed",
                placeholder="Enter hash manually (40 hex characters)"
            )
        
        with col_crack:
            def crack_callback():
                # Set target hash from the input field before cracking
                set_hash(st.session_state.hash_input_field) 
                
            crack_button = st.button(
                label="Crack Hash", 
                key="crack_btn",
                on_click=crack_callback
            )

        # Crack Result
        if crack_button and st.session_state.target_hash and st.session_state.rainbow_table:
            st.markdown("---")
            with st.spinner('Cracking...'):
                time.sleep(0.5)
                result = crack_hash(
                    st.session_state.target_hash, 
                    st.session_state.rainbow_table, 
                    DEMO_DICT
                )
            
            if result['found']:
                st.success(f"🎉 **Password Found!** \n\n**Password:** `{result['password']}` \n\n**Method:** {result['method']}")
            else:
                st.error("❌ **Not found** in the demo table. Try one of the generated hashes.")
                
            st.markdown(f"**Target Hash:** `{st.session_state.target_hash}`")
            st.markdown("---")

        st.subheader("Table Preview")
        st.markdown(
            "💡 **How it works:** A rainbow table is a precomputed database of hashes. "
            "Instead of trying millions of passwords, we instantly look up the hash to find the match. "
            "Real tables contain billions of hashes for faster password cracking."
        )
        st.dataframe(st.session_state.rainbow_table, use_container_width=True)


# --- Code Section ---
with tab_code:
    st.header("Core Code (Python)")
    st.subheader("Reference Implementation")
    st.markdown(
        """
        This script shows the core logic for hashing and a simple lookup-based cracking method. 
        It is for education only.
        """
    )
    st.code(
        """
import hashlib

def hash_password(password):
    # Converts a password to its fixed-length hexadecimal hash string
    return hashlib.sha256(
        password.encode()
    ).hexdigest()

def crack_hash(target_hash, rainbow_table):
    # Simplified lookup against a dictionary-based table
    for password, hash_value in rainbow_table.items():
        if hash_value == target_hash:
            return password
    return "Not found"
        """, 
        language="python"
    )

# --- Conclusion Section ---
with tab_conclusion:
    st.header("Conclusion")
    st.subheader("Summary & Recommendations")
    st.markdown(
        """
        Rainbow table attacks demonstrate how easily weak and **unsalted** password hashes can be reversed 
        using precomputed lookup tables. To protect systems, always store passwords with:
        
        * **Unique per-user salts**.
        * A **slow, memory-hard hashing algorithm** (for example: **bcrypt**, **scrypt**, or **Argon2**).
        
        Additionally, enforce strong password policies, enable **multi-factor authentication (MFA)**, and 
        monitor for suspicious activity — these measures together greatly reduce the risk of hash-based 
        attacks and strengthen overall password security.
        """
    )

st.caption("© 2024 Rainbow Table Attack – Educational use only.")
