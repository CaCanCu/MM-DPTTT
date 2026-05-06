import streamlit as st
import hashlib
import hmac
import random
import time

# ==========================================
# 1. THAM SỐ ĐƯỜNG CONG (secp256k1)
# ==========================================
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
A = 0
B = 7
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

# ==========================================
# 2. TOÁN HỌC NỀN TẢNG
# ==========================================
def inv_mod(k, p):
    return pow(k, -1, p)

def add_points(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        m = (3 * x1**2 + A) * inv_mod(2 * y1, P) % P
    else:
        m = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (m**2 - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    res = None
    temp = point
    while k:
        if k & 1: res = add_points(res, temp)
        temp = add_points(temp, temp)
        k >>= 1
    return res

def hash_msg(msg):
    h = hashlib.sha256(msg.encode('utf-8')).hexdigest()
    return int(h, 16)

# ==========================================
# 3. NGHIỆP VỤ ECDSA & TẤN CÔNG
# ==========================================
def sign_ecdsa(msg, d, k):
    z = hash_msg(msg)
    P1 = scalar_mult(k, G)
    r = P1[0] % N
    s = (inv_mod(k, N) * (z + r * d)) % N
    return z, r, s

def verify_ecdsa(msg, r, s, Q):
    if not (0 < r < N and 0 < s < N): return False
    z = hash_msg(msg)
    w = inv_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    p_check = add_points(scalar_mult(u1, G), scalar_mult(u2, Q))
    return p_check is not None and (p_check[0] % N) == r

def hack_k_reuse(z1, z2, r, s1, s2):
    k_hacked = ((z1 - z2) * inv_mod((s1 - s2) % N, N)) % N
    d_hacked = (inv_mod(r, N) * (s1 * k_hacked - z1)) % N
    return k_hacked, d_hacked

def hack_leaked_k(z, r, s, k_leaked):
    # d = r^-1 * (sk - z) mod n
    d_hacked = (inv_mod(r, N) * (s * k_leaked - z)) % N
    return d_hacked

# ==========================================
# 4. GIAO DIỆN WEB STREAMLIT
# ==========================================
st.set_page_config(page_title="ECDSA Simulator Pro", layout="wide")
st.title("Hệ thống Phân tích An toàn Chữ ký số ECDSA")

#if 'alice_d' not in st.session_state:
    #st.session_state.alice_d = random.randint(1, N - 1)
#alice_Q = scalar_mult(st.session_state.alice_d, G)

# --- ĐOẠN CODE MỚI THÊM VÀO ---
st.sidebar.markdown("---")
st.sidebar.subheader("Tùy chỉnh Khóa bí mật")
# Tạo ô nhập liệu cho d (dùng text_input để hỗ trợ số cực lớn)
user_input_d = st.sidebar.text_input("Nhập giá trị d của bạn:", value="12345")

try:
    # Chuyển đổi chuỗi người dùng nhập thành số nguyên
    custom_d = int(user_input_d)
    
    # Kiểm tra điều kiện bắt buộc của ECDSA: 0 < d < N
    if 0 < custom_d < N:
        st.session_state.alice_d = custom_d
    else:
        st.sidebar.error(f"Lỗi: d phải lớn hơn 0 và nhỏ hơn N!")
        st.session_state.alice_d = 12345 # Giá trị mặc định nếu nhập sai
except ValueError:
    st.sidebar.error("Lỗi: Vui lòng chỉ nhập số nguyên!")
    st.session_state.alice_d = 12345

# Tính toán Khóa công khai Q dựa trên d bạn vừa nhập
alice_Q = scalar_mult(st.session_state.alice_d, G)
# ------------------------------

st.sidebar.header(" Cấu hình")
mode = st.sidebar.radio("Chọn kịch bản thực nghiệm:", 
                        ["1. Mô phỏng ECDSA chuẩn", 
                         "2. Lỗ hổng Tái sử dụng k", 
                         "3. Tấn công khi Lộ k (Weak k)",
                         "4. Giải pháp An toàn (RFC 6979)"])

st.sidebar.markdown("---")
st.sidebar.write("**Khóa công khai (Q = dG):**")
st.sidebar.code(f"{hex(alice_Q[0])[:20]}...")

# ---------------------------------------------------------
# KỊCH BẢN 1: ECDSA CHUẨN
# ---------------------------------------------------------
if mode == "1. Mô phỏng ECDSA chuẩn":
    st.subheader("Kịch bản 1: Hoạt động ECDSA tiêu chuẩn")
    st.info("Trong kịch bản này, mỗi thông điệp được ký với một số ngẫu nhiên k khác nhau.")
    
    msg = st.text_input("Nhập thông điệp cần ký:", "Giao dịch hợp lệ 100k VND")
    if st.button("Thực hiện Ký và Xác minh"):
        k = random.randint(1, N - 1)
        z, r, s = sign_ecdsa(msg, st.session_state.alice_d, k)
        
        col_a, col_b = st.columns(2)
        with col_a:
            st.write("**Bước 1: Ký số**")
            st.write(f"k ngẫu nhiên: `{hex(k)[:15]}...`")
            st.write(f"Chữ ký (r, s):")
            st.code(f"r: {r}\ns: {s}")
        
        with col_b:
            st.write("**Bước 2: Xác minh**")
            is_valid = verify_ecdsa(msg, r, s, alice_Q)
            if is_valid:
                st.success("Xác minh thành công! Chữ ký hợp lệ.")
            else:
                st.error("Xác minh thất bại!")

# ---------------------------------------------------------
# KỊCH BẢN 2: TÁI SỬ DỤNG K
# ---------------------------------------------------------
elif mode == "2. Lỗ hổng Tái sử dụng k":
    st.subheader("Kịch bản 2: Lỗ hổng Tái sử dụng k (Nonce Reuse)")
    st.warning("Hacker bắt được 2 giao dịch có cùng giá trị r.")
    
    col_a, col_b = st.columns(2)
    with col_a:
        msg1 = st.text_input("Thông điệp 1:", "Anh gửi Chanh 100k VND")
        msg2 = st.text_input("Thông điệp 2:", "Anh gửi Danh 200k VND")
        bad_k = 998877665544 # Dùng chung k
        
        if st.button("Ký 2 giao dịch với cùng k"):
            z1, r1, s1 = sign_ecdsa(msg1, st.session_state.alice_d, bad_k)
            z2, r2, s2 = sign_ecdsa(msg2, st.session_state.alice_d, bad_k)
            st.session_state.reuse_data = (z1, z2, r1, s1, s2)
            st.write(f"Giá trị r dùng chung: `{r1}`")

    with col_b:
        if 'reuse_data' in st.session_state:
            st.write("**Hacker thực thi:**")
            if st.button("Khôi phục Khóa bí mật"):
                z1, z2, r, s1, s2 = st.session_state.reuse_data
                k_h, d_h = hack_k_reuse(z1, z2, r, s1, s2)
                st.latex(r"k = (z_1 - z_2)(s_1 - s_2)^{-1} \pmod n")
                st.success(f"Tìm lại được k: `{k_h}`")
                st.success(f"Tìm lại được d: `{d_h}`")
                if d_h == st.session_state.alice_d:
                    st.balloons()

# ---------------------------------------------------------
# KỊCH BẢN 3: LỘ K HOẶC K YẾU
# ---------------------------------------------------------
elif mode == "3. Tấn công khi Lộ k (Weak k)":
    st.subheader("Kịch bản 3: Tấn công khi lộ k (Nonce Exposure)")
    st.markdown("""
    Nếu giá trị $k$ bị lộ (do bộ sinh số ngẫu nhiên yếu hoặc bị rò rỉ bộ nhớ), 
    Khóa bí mật $d$ sẽ bị tính toán ra ngay lập tức chỉ với **1 thông điệp duy nhất**.
    """)
    
    msg = st.text_input("Thông điệp ký:", "Giao dịch bí mật")
    weak_k = st.number_input("Giả sử k bị lộ là:", value=12345)
    
    if st.button("Mô phỏng lộ k"):
        z, r, s = sign_ecdsa(msg, st.session_state.alice_d, weak_k)
        st.write(f"Chữ ký công khai: r=`{hex(r)[:10]}...`, s=`{hex(s)[:10]}...`")
        
        st.divider()
        st.write("**Hacker tính toán:**")
        st.latex(r"d \equiv r^{-1}(s \cdot k - z) \pmod n")
        d_hacked = hack_leaked_k(z, r, s, weak_k)
        
        st.warning(f"Khóa bí mật bị hacker chiếm đoạt: {d_hacked}")
        if d_hacked == st.session_state.alice_d:
            st.error("TẤN CÔNG THÀNH CÔNG!")

# ---------------------------------------------------------
# KỊCH BẢN 4: RFC 6979
# ---------------------------------------------------------
elif mode == "4. Giải pháp An toàn (RFC 6979)":
    st.subheader("Kịch bản 4: Chữ ký số tất định (RFC 6979)")
    st.info("Giá trị k được sinh ra từ HMAC(d, z), đảm bảo k luôn duy nhất và bí mật.")
    
    msg = st.text_input("Nhập nội dung:", "Dữ liệu an toàn")
    if st.button("Ký với RFC 6979"):
        z = hash_msg(msg)
        # Mô phỏng sinh k rfc6979
        k_rfc = int(hmac.new(st.session_state.alice_d.to_bytes(32,'big'), 
                             z.to_bytes(32,'big'), hashlib.sha256).hexdigest(), 16) % N
        
        _, r, s = sign_ecdsa(msg, st.session_state.alice_d, k_rfc)
        st.success(f"k được tạo ra một cách an toàn: `{hex(k_rfc)[:20]}...`")
        st.write(f"Chữ ký r: `{r}`")
        st.write("Vì k thay đổi theo mã băm của mỗi thông điệp, hacker không thể áp dụng các kịch bản tấn công trên.")
