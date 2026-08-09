"""Crypto Playground — a Streamlit app to generate, inspect and use crypto material.

Run with:
    streamlit run app.py
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

from crypto_lib import asymmetric, keys, symmetric

st.set_page_config(page_title="Crypto Playground", page_icon="🔐", layout="wide")

# --------------------------------------------------------------------------- #
# Styling
# --------------------------------------------------------------------------- #
st.markdown(
    """
    <style>
      .stCodeBlock, pre { font-size: 0.8rem; }
      .metric-ok    { color: #16a34a; font-weight: 600; }
      .metric-bad   { color: #dc2626; font-weight: 600; }
      .pem-label    { font-size: 0.85rem; color: #64748b; margin-bottom: -8px; }
      div[data-testid="stMetricValue"] { font-size: 1.1rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🔐 Crypto Playground")
st.caption(
    "Generate keys & certificates, inspect them in a readable format, and try "
    "symmetric / asymmetric encryption with different algorithms."
)


def render_dict(d: dict) -> None:
    """Render a dict as a clean two-column table."""
    df = pd.DataFrame({"Field": list(d.keys()), "Value": [str(v) for v in d.values()]})
    st.dataframe(df, hide_index=True, use_container_width=True)


def pem_block(label: str, pem: str, filename: str) -> None:
    st.markdown(f"<div class='pem-label'>{label}</div>", unsafe_allow_html=True)
    st.code(pem, language="text")
    st.download_button(f"⬇ Download {filename}", pem, file_name=filename, key=f"dl_{filename}")


tab_keys, tab_cert, tab_inspect, tab_sym, tab_asym = st.tabs(
    ["🔑 Key Pairs", "📜 Certificate", "🔍 Inspect", "🧩 Symmetric", "🔀 Asymmetric"]
)

# --------------------------------------------------------------------------- #
# Key Pairs
# --------------------------------------------------------------------------- #
with tab_keys:
    st.subheader("Generate a Key Pair")
    col1, col2 = st.columns([1, 2])
    with col1:
        key_type = st.radio("Algorithm", ["RSA", "EC (Elliptic Curve)"], key="kp_type")
        if key_type == "RSA":
            size = st.select_slider("Key size (bits)", keys.RSA_SIZES, value=2048)
            curve = None
        else:
            curve = st.selectbox("Curve", list(keys.EC_CURVES.keys()))
            size = None
        passphrase = st.text_input("Passphrase (optional)", type="password", key="kp_pass")
        gen = st.button("Generate Key Pair", type="primary")

    if gen:
        if key_type == "RSA":
            kp = keys.generate_rsa_keypair(size, passphrase or None)
        else:
            kp = keys.generate_ec_keypair(curve, passphrase or None)
        st.session_state["last_keypair"] = kp

    kp = st.session_state.get("last_keypair")
    if kp:
        with col2:
            st.success(f"Generated {kp.kind} key pair — {kp.detail}")
        c1, c2 = st.columns(2)
        with c1:
            pem_block("Private Key (PKCS#8, PEM)", kp.private_pem, "private_key.pem")
        with c2:
            pem_block("Public Key (SPKI, PEM)", kp.public_pem, "public_key.pem")

# --------------------------------------------------------------------------- #
# Certificate
# --------------------------------------------------------------------------- #
with tab_cert:
    st.subheader("Generate a Self-Signed X.509 Certificate")
    col1, col2 = st.columns(2)
    with col1:
        cn = st.text_input("Common Name (CN)", "example.local")
        org = st.text_input("Organization (O)", "Acme Corp")
        country = st.text_input("Country (C, 2 letters)", "US")
        sans_raw = st.text_input("Subject Alt Names (comma separated)", "example.local, www.example.local")
    with col2:
        valid_days = st.number_input("Validity (days)", 1, 3650, 365)
        cert_key_type = st.radio("Key type", ["RSA", "EC"], horizontal=True, key="cert_key")
        if cert_key_type == "RSA":
            cert_rsa = st.select_slider("RSA size", keys.RSA_SIZES, value=2048, key="cert_rsa")
            cert_curve = "SECP256R1 (P-256)"
        else:
            cert_curve = st.selectbox("Curve", list(keys.EC_CURVES.keys()), key="cert_curve")
            cert_rsa = 2048

    if st.button("Generate Certificate", type="primary"):
        result = keys.generate_self_signed_cert(
            common_name=cn,
            organization=org,
            country=country,
            sans=[s for s in sans_raw.split(",")],
            valid_days=int(valid_days),
            key_type=cert_key_type,
            rsa_size=cert_rsa,
            ec_curve=cert_curve,
        )
        st.session_state["last_cert"] = result

    cert = st.session_state.get("last_cert")
    if cert:
        st.success("Certificate generated.")
        st.markdown("**Certificate details**")
        render_dict(keys.inspect_certificate(cert.cert_pem))
        c1, c2 = st.columns(2)
        with c1:
            pem_block("Certificate (PEM)", cert.cert_pem, "cert.pem")
        with c2:
            pem_block("Private Key (PEM)", cert.private_pem, "cert_key.pem")

# --------------------------------------------------------------------------- #
# Inspect
# --------------------------------------------------------------------------- #
with tab_inspect:
    st.subheader("Inspect & Review PEM Material")
    kind = st.selectbox("What are you pasting?", ["Certificate", "Private Key", "Public Key"])
    pem_input = st.text_area("Paste PEM here", height=220, placeholder="-----BEGIN ...-----")
    insp_pass = ""
    if kind == "Private Key":
        insp_pass = st.text_input("Passphrase (if encrypted)", type="password", key="insp_pass")

    if st.button("Inspect", type="primary"):
        try:
            if kind == "Certificate":
                info = keys.inspect_certificate(pem_input)
                status = info.get("Status", "")
                if status == "VALID":
                    st.markdown(f"<span class='metric-ok'>✔ {status}</span>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<span class='metric-bad'>✗ {status}</span>", unsafe_allow_html=True)
            elif kind == "Private Key":
                info = keys.inspect_private_key(pem_input, insp_pass or None)
            else:
                info = keys.inspect_public_key(pem_input)
            render_dict(info)
        except Exception as e:  # noqa: BLE001
            st.error(f"Could not parse: {e}")

# --------------------------------------------------------------------------- #
# Symmetric
# --------------------------------------------------------------------------- #
with tab_sym:
    st.subheader("Symmetric Encryption")
    st.caption(
        "Same secret (a password) encrypts and decrypts. A 256-bit key is derived "
        "from your password via PBKDF2-HMAC-SHA256 (200k iterations)."
    )
    algo = st.selectbox("Algorithm", symmetric.SYMMETRIC_ALGOS)
    password = st.text_input("Password / shared secret", "correct horse battery staple", key="sym_pw")

    enc_col, dec_col = st.columns(2)
    with enc_col:
        st.markdown("#### Encrypt")
        plaintext = st.text_area("Plaintext", "Attack at dawn 🌅", key="sym_pt")
        if st.button("Encrypt", key="sym_enc"):
            try:
                res = symmetric.encrypt(algo, password, plaintext)
                st.session_state["sym_res"] = (algo, res)
            except Exception as e:  # noqa: BLE001
                st.error(str(e))
        if "sym_res" in st.session_state:
            used_algo, res = st.session_state["sym_res"]
            st.text("Ciphertext (base64)")
            st.code(res.ciphertext_b64, language="text")
            if res.fields:
                st.text("Parameters (needed to decrypt)")
                render_dict(res.fields)

    with dec_col:
        st.markdown("#### Decrypt")
        ct_in = st.text_area("Ciphertext (base64)", key="sym_ct")
        params_help = "Enter hex params as key=value per line (salt=..., nonce=..., iv=...)"
        params_in = st.text_area("Parameters", key="sym_params", help=params_help, height=100)
        if st.button("Decrypt", key="sym_dec"):
            try:
                fields = {}
                for line in params_in.strip().splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        fields[k.strip()] = v.strip()
                out = symmetric.decrypt(algo, password, ct_in.strip(), fields)
                st.success("Decrypted:")
                st.code(out, language="text")
            except Exception as e:  # noqa: BLE001
                st.error(f"Decryption failed: {e}")

# --------------------------------------------------------------------------- #
# Asymmetric
# --------------------------------------------------------------------------- #
with tab_asym:
    st.subheader("Asymmetric Encryption & Signatures")
    mode = st.radio(
        "Demo",
        ["RSA-OAEP Encryption", "Sign / Verify (RSA-PSS or ECDSA)", "ECDH Key Agreement"],
        key="asym_mode",
    )

    if mode == "RSA-OAEP Encryption":
        st.caption("Public key encrypts; only the matching private key can decrypt.")
        pub_pem = st.text_area("RSA Public Key (PEM)", height=160, key="rsa_pub")
        priv_pem = st.text_area("RSA Private Key (PEM)", height=160, key="rsa_priv")
        priv_pass = st.text_input("Private key passphrase (optional)", type="password", key="rsa_priv_pass")
        msg = st.text_input("Message", "Top secret 🤫", key="rsa_msg")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Encrypt with public key"):
                try:
                    ct = asymmetric.rsa_encrypt(pub_pem, msg)
                    st.session_state["rsa_ct"] = ct
                except Exception as e:  # noqa: BLE001
                    st.error(str(e))
            if "rsa_ct" in st.session_state:
                st.code(st.session_state["rsa_ct"], language="text")
        with c2:
            ct_in = st.text_area("Ciphertext (base64)", value=st.session_state.get("rsa_ct", ""), key="rsa_ct_in")
            if st.button("Decrypt with private key"):
                try:
                    pt = asymmetric.rsa_decrypt(priv_pem, ct_in.strip(), priv_pass or None)
                    st.success("Decrypted:")
                    st.code(pt, language="text")
                except Exception as e:  # noqa: BLE001
                    st.error(str(e))

    elif mode == "Sign / Verify (RSA-PSS or ECDSA)":
        st.caption("Private key signs; anyone with the public key can verify. Works with RSA or EC keys.")
        priv_pem = st.text_area("Signer Private Key (PEM)", height=160, key="sig_priv")
        priv_pass = st.text_input("Passphrase (optional)", type="password", key="sig_pass")
        pub_pem = st.text_area("Verifier Public Key (PEM)", height=160, key="sig_pub")
        msg = st.text_input("Message", "I authorize this transaction.", key="sig_msg")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Sign"):
                try:
                    sig = asymmetric.sign(priv_pem, msg, priv_pass or None)
                    st.session_state["sig_val"] = sig
                except Exception as e:  # noqa: BLE001
                    st.error(str(e))
            if "sig_val" in st.session_state:
                st.text("Signature (base64)")
                st.code(st.session_state["sig_val"], language="text")
        with c2:
            sig_in = st.text_area("Signature (base64)", value=st.session_state.get("sig_val", ""), key="sig_in")
            if st.button("Verify"):
                try:
                    ok = asymmetric.verify(pub_pem, msg, sig_in.strip())
                    if ok:
                        st.markdown("<span class='metric-ok'>✔ Signature VALID</span>", unsafe_allow_html=True)
                    else:
                        st.markdown("<span class='metric-bad'>✗ Signature INVALID</span>", unsafe_allow_html=True)
                except Exception as e:  # noqa: BLE001
                    st.error(str(e))

    else:  # ECDH
        st.caption(
            "Two parties (Alice & Bob) each generate an EC key pair and derive the "
            "*same* shared secret without ever transmitting it."
        )
        curve = st.selectbox("Curve", ["SECP256R1"], key="ecdh_curve")
        if st.button("Run ECDH demo", type="primary"):
            res = asymmetric.ecdh_demo(curve)
            render_dict(
                {
                    "Curve": res["curve"],
                    "Alice raw secret": res["alice_raw_secret"][:32] + "…",
                    "Bob raw secret": res["bob_raw_secret"][:32] + "…",
                    "Alice derived key (HKDF)": res["alice_derived_key"],
                    "Bob derived key (HKDF)": res["bob_derived_key"],
                }
            )
            if res["match"]:
                st.markdown(
                    "<span class='metric-ok'>✔ Both parties derived the SAME key</span>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown("<span class='metric-bad'>✗ Keys differ</span>", unsafe_allow_html=True)

st.divider()
st.caption("⚠️ For learning/demo only. Do not use generated material for production secrets.")
