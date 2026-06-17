import streamlit as st  # Giao diện Web UI
import hashlib          # Băm mật mã (SHA-256)
import hmac             # Tạo mã xác thực thông điệp (RFC 6979)
import random           # Sinh số ngẫu nhiên môi trường (PRNG)
import time             # Thư viện xử lý thời gian (đo thời gian Brute-force)


# 1. THAM SỐ ĐƯỜNG CONG (secp256k1)

# P là số nguyên tố xác định kích thước của trường hữu hạn (Prime field)
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
# N là bậc của Điểm cơ sở G (tổng số điểm tạo thành Nhóm Abel)
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
# A và B là hằng số của phương trình đường cong y^2 = x^3 + Ax + B mod P
A = 0
B = 7
# G là Điểm cơ sở (Generator point), chứa tọa độ (x, y) công khai
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

# 2. TOÁN HỌC NỀN TẢNG

def inv_mod(k, p):
    # Dùng hàm pow() của lớp C bên dưới Python để tìm nghịch đảo modulo.
    # pow(k, -1, p) tương đương với việc giải k*x ≡ 1 (mod p) bằng thuật toán Euclid mở rộng.
    return pow(k, -1, p)

def add_points(p1, p2):
    # Phép cộng hai điểm trên đường cong Elliptic
    if p1 is None: return p2  # Nếu p1 là Điểm vô cực (None), kết quả là p2
    if p2 is None: return p1  # Nếu p2 là Điểm vô cực (None), kết quả là p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    # Nếu x giống nhau nhưng y đối nghịch nhau -> Điểm vô cực (None)
    if x1 == x2 and y1 != y2: return None
    
    # Tính hệ số góc m của đường thẳng
    if x1 == x2:
        # Trường hợp P1 trùng P2 -> Đây là phép NHÂN ĐÔI ĐIỂM (Point Doubling).
        # Đạo hàm của đường cong (kẻ tiếp tuyến): m = (3*x1^2 + A) / (2*y1) mod P
        m = (3 * x1**2 + A) * inv_mod(2 * y1, P) % P
    else:
        # Trường hợp P1 khác P2 -> Đây là phép CỘNG ĐIỂM BÌNH THƯỜNG (Point Addition).
        # Hệ số góc cát tuyến: m = (y2 - y1) / (x2 - x1) mod P
        m = (y2 - y1) * inv_mod(x2 - x1, P) % P
        
    # Tính tọa độ điểm thứ 3 (giao điểm) rồi lấy đối xứng qua trục hoành
    x3 = (m**2 - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    # Phép nhân vô hướng k*P áp dụng thuật toán Double-and-Add (độ phức tạp O(log k))
    res = None
    temp = point
    while k:
        # Kiểm tra bit cuối cùng. Nếu là 1, cộng dồn điểm temp vào biến kết quả (Add)
        if k & 1: res = add_points(res, temp)
        # Bất chấp bit là gì, luôn nhân đôi điểm temp cho vòng lặp tiếp theo (Double)
        temp = add_points(temp, temp)
        # Dịch phải 1 bit (tương đương k = k // 2) để duyệt bit tiếp theo
        k >>= 1
    return res

def hash_msg(msg):
    # Băm thông điệp nguyên bản (string) thành chuỗi băm SHA-256 (hex)
    h = hashlib.sha256(msg.encode('utf-8')).hexdigest()
    # Chuyển chuỗi hex thành số nguyên lớn cơ số 16 để tính toán đại số
    return int(h, 16)

# 3. NGHIỆP VỤ ECDSA & TẤN CÔNG

def sign_ecdsa(msg, d, k):
    # Bước 1: Băm thông điệp lấy z
    z = hash_msg(msg)
    # Bước 2: Sinh điểm P1 = k*G
    P1 = scalar_mult(k, G)
    # Bước 3: Hoành độ r = P1.x mod N
    r = P1[0] % N
    # Bước 4: Chữ ký s = k^-1 * (z + r*d) mod N
    s = (inv_mod(k, N) * (z + r * d)) % N
    return z, r, s

def verify_ecdsa(msg, r, s, Q):
    # Kiểm tra tính hợp lệ cơ bản: r và s phải nằm trong khoảng (0, N)
    if not (0 < r < N and 0 < s < N): return False
    
    z = hash_msg(msg)
    # Tính w = s^-1 mod N
    w = inv_mod(s, N)
    # Tính hệ số u1 = z*w mod N
    u1 = (z * w) % N
    # Tính hệ số u2 = r*w mod N
    u2 = (r * w) % N
    
    # Phục hồi điểm p_check = (u1*G) + (u2*Q)
    p_check = add_points(scalar_mult(u1, G), scalar_mult(u2, Q))
    
    # Xác minh thành công nếu p_check không phải vô cực và hoành độ khớp với r
    return p_check is not None and (p_check[0] % N) == r

def hack_k_reuse(z1, z2, r, s1, s2):
    # Giải thuật tấn công lặp Nonce (O(1))
    # Tính k = (z1 - z2) * (s1 - s2)^-1 mod N
    k_hacked = ((z1 - z2) * inv_mod((s1 - s2) % N, N)) % N
    # Tính d = r^-1 * (s1*k - z1) mod N
    d_hacked = (inv_mod(r, N) * (s1 * k_hacked - z1)) % N
    return k_hacked, d_hacked

def hack_leaked_k(z, r, s, k_leaked):
    # Giải thuật tấn công lộ Nonce (O(1))
    # Tính d = r^-1 * (s*k - z) mod N
    d_hacked = (inv_mod(r, N) * (s * k_leaked - z)) % N
    return d_hacked
     
# 4. GIAO DIỆN WEB STREAMLIT

st.set_page_config(page_title="ECDSA Simulator Pro", layout="wide")
st.title("Hệ thống Phân tích An toàn Chữ ký số ECDSA")

if 'alice_d' not in st.session_state:
    st.session_state.alice_d = random.randint(1, N - 1)

# st.sidebar.markdown("---")
# st.sidebar.subheader("Tùy chỉnh Khóa bí mật")
# # Tạo ô nhập liệu cho d 
# user_input_d = st.sidebar.text_input("Nhập giá trị d của bạn:", value="2023169324")

# try:
#     # Chuyển đổi chuỗi người dùng nhập thành số nguyên
#     custom_d = int(user_input_d)
    
#     # Kiểm tra điều kiện bắt buộc của ECDSA: 0 < d < N
#     if 0 < custom_d < N:
#         st.session_state.alice_d = custom_d
#     else:
#         st.sidebar.error(f"Lỗi: d phải lớn hơn 0 và nhỏ hơn N!")
#         st.session_state.alice_d = 2023169324 # Giá trị mặc định nếu nhập sai
# except ValueError:
#     st.sidebar.error("Lỗi: Vui lòng chỉ nhập số nguyên!")
#     st.session_state.alice_d = 2023169324

# Tính toán Khóa công khai Q dựa trên d bạn vừa nhập
alice_Q = scalar_mult(st.session_state.alice_d, G)

st.sidebar.header(" Cấu hình")
mode = st.sidebar.radio("Chọn kịch bản thực nghiệm:", 
                        ["1. Mô phỏng ECDSA chuẩn", 
                         "2. Tấn công khi Lộ k", 
                         "3. Lỗ hổng Tái sử dụng k",
                         "4. Sinh d yếu (Weak PRNG)",
                         "5. Giải pháp An toàn (RFC 6979)"])

st.sidebar.markdown("---")
st.sidebar.write("**Khóa công khai (Q = dG):**")
st.sidebar.code(f"{hex(alice_Q[0])[:20]}...")

# KỊCH BẢN 1: ECDSA CHUẨN

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

# KỊCH BẢN 2: LỘ K

elif mode == "2. Tấn công khi Lộ k":
    st.subheader("Kịch bản 2: Tấn công khi lộ k")
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

# KỊCH BẢN 3: TÁI SỬ DỤNG K

elif mode == "3. Lỗ hổng Tái sử dụng k":
    st.subheader("Kịch bản 3: Lỗ hổng Tái sử dụng k (Nonce Reuse)")
    st.warning("Hacker bắt được 2 giao dịch có cùng giá trị r.")
    
    col_a, col_b = st.columns(2)
    with col_a:
        msg1 = st.text_input("Thông điệp 1:", "Anh gửi Chanh 100k VND")
        msg2 = st.text_input("Thông điệp 2:", "Anh gửi Danh 200k VND")
        bad_k = 123456789
        
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

# KỊCH BẢN 4: KHÓA BÍ MẬT YẾU (WEAK PRNG)

elif mode == "4. Sinh d yếu (Weak PRNG)":
    st.subheader("Kịch bản 4: Tấn công vét cạn do sinh khóa yếu")
    st.info("Mô phỏng việc phần mềm ví sử dụng bộ sinh số giả ngẫu nhiên yếu kém (lấy một mã PIN 4 số làm mầm/seed) để tạo Khóa bí mật.")
    
    col_a, col_b = st.columns(2)
    with col_a:
        st.write("**Nạn nhân tạo ví:**")
        user_pin = st.number_input("Nhập mã PIN 4 số (1000 - 9999) làm mầm sinh khóa:", min_value=1000, max_value=9999, value=2026)
        if st.button("Tạo ví với Weak PRNG"):
            # Dùng PIN làm hạt giống (seed) để sinh khóa
            random.seed(user_pin)
            d_weak = random.randint(1, N - 1)
            Q_weak = scalar_mult(d_weak, G)
            
            # Reset lại seed hệ thống để không ảnh hưởng các chức năng khác
            random.seed()
            
            st.session_state.weak_wallet = (d_weak, Q_weak)
            st.success("Tạo ví thành công!")
            st.write(f"Khóa công khai Q (công bố):")
            st.code(f"x: {hex(Q_weak[0])[:20]}...\ny: {hex(Q_weak[1])[:20]}...")
            st.write("Khóa bí mật d: `Đã được giữ kín, chỉ lưu trên máy`")
    
    with col_b:
        st.write("**Hacker tấn công (Brute-force):**")
        st.write("Hacker quét toàn bộ không gian hạt giống từ 1000 đến 9999 để tính ngược ra d.")
        
        if 'weak_wallet' in st.session_state:
            target_Q = st.session_state.weak_wallet[1]
            if st.button("Bắt đầu Vét cạn (Brute-force)"):
                progress_text = "Đang quét các khả năng..."
                my_bar = st.progress(0, text=progress_text)
                
                start_time = time.time()
                found = False
                
                # Hacker thử tất cả các hạt giống (seed) có thể
                for guess in range(1000, 10000):
                    # Cập nhật thanh tiến trình (chỉ cập nhật mỗi 500 bước để UI không giật)
                    if guess % 500 == 0:
                        my_bar.progress((guess - 1000) / 9000, text=f"Đang thử PIN: {guess}")
                        
                    random.seed(guess)
                    d_guess = random.randint(1, N - 1)
                    Q_guess = scalar_mult(d_guess, G)
                    
                    # Nếu Khóa công khai sinh ra khớp với mục tiêu -> Đã tìm ra seed!
                    if Q_guess and Q_guess[0] == target_Q[0]:
                        found = True
                        random.seed() # Reset seed
                        my_bar.progress(1.0, text="Hoàn thành!")
                        end_time = time.time()
                        
                        st.success(f"TẤN CÔNG THÀNH CÔNG! Mất {round(end_time - start_time, 2)} giây.")
                        st.warning(f"Đoán trúng mầm sinh số (seed): `{guess}`")
                        st.error(f"Khôi phục được Khóa bí mật d: `{d_guess}`")
                        
                        # So sánh với khóa thực tế nạn nhân đang giấu
                        if d_guess == st.session_state.weak_wallet[0]:
                            st.balloons()
                        break
                
                if not found:
                    random.seed()
                    st.error("Không tìm thấy! Không gian mẫu có thể lớn hơn dự kiến.")

# KỊCH BẢN 5: RFC 6979

elif mode == "5. Giải pháp An toàn (RFC 6979)":
    st.subheader("Kịch bản 5: Chữ ký số tất định (RFC 6979)")
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



