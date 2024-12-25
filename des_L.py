import binascii

# 定义最佳线性逼近式
best_linear_approximations = {
    1: {(16, 15): -18},
    2: {(34, 11): -16, (34, 15): 16},
    3: {(34, 15): 16},
    4: {(34, 15): -16, (40, 15): -16, (43, 9): -16},
    5: {(16, 15): -20},
    6: {(16, 7): -14},
    7: {(59, 4): -18},
    8: {(16, 15): -16}
}


# 构建线性近似表
def build_LAT(best_linear_approximations):
    LAT = {i: {} for i in range(1, 9)}  # 初始化LAT字典，包含8个S盒
    for S, approximations in best_linear_approximations.items():
        for (alpha, beta), NS in approximations.items():
            LAT[S].setdefault(alpha, {})[beta] = NS
    return LAT


# 打印线性近似表
def print_LAT(LAT):
    for S, approximations in LAT.items():
        print(f"S盒{S}的线性近似表:")
        for alpha, betas in approximations.items():
            for beta, NS in betas.items():
                print(f"\tα={bin(alpha)[2:].zfill(6)}, β={bin(beta)[2:].zfill(4)}, NS={NS}")
        print()


# 获取并打印线性近似表
LAT = build_LAT(best_linear_approximations)
print_LAT(LAT)


# 将十六进制字符串转换为字节串
def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)


# 假设我们有足够的已知明文-密文对
known_plaintexts_hex = [
    'aaaec75c9fa73091', 'c691a8ad944303c2', 'c09c6b1e91cf8cb4', 'd46b4860bcc80f44', '8b9d130791b7e0dd',
    '9f1515d7b66927fd', '829716b707b58618', 'd3fe23dd8a0f53b1', 'b7182f897e057271', '532540e593021f72'
]
known_ciphertexts_hex = [
    '966e0ce6fccb9f35', 'dae61fab659da46f', 'fd62cd090a62b115', 'eefd576e63c539cf', '3f80417c1ef81936',
    '4756f4ccde6803c0', '59a6476ddd33ba1c', '54d7889640f33f31', '73f830d1ac4f3ce5', '4e62334cf483cd4e'
]

# 将十六进制字符串转换为字节串
known_plaintexts = [hex_to_bytes(pt) for pt in known_plaintexts_hex]
known_ciphertexts = [hex_to_bytes(ct) for ct in known_ciphertexts_hex]


# 定义一个函数来计算给定密钥候选的得分
def calculate_key_score(key, LAT, known_pt, known_ct):
    score = 0
    for pt, ct in zip(known_pt, known_ct):
        for S, approximations in LAT.items():  # 遍历每个S盒
            for alpha, betas in approximations.items():
                for beta, NS in betas.items():
                    # 提取与当前S盒相关的比特
                    pt_bits = (int.from_bytes(pt, 'big') >> (56 - (S - 1) * 6)) & 0x3F  # 取出S盒输入的6比特
                    ct_bits = (int.from_bytes(ct, 'big') >> (64 - (S - 1) * 4 - 4)) & 0xF  # 取出S盒输出的4比特

                    # 计算线性逼近方程的左侧和右侧
                    left_side = (pt_bits & alpha) ^ (ct_bits & beta)
                    right_side = (key >> (56 - (S - 1) * 6)) & 0x3F  # 只考虑当前S盒相关的密钥部分

                    # 如果左侧和右侧的异或结果与NS值的符号相同，则增加得分
                    if (left_side == 0 and NS < 0) or (left_side != 0 and NS > 0):
                        score += abs(NS)  # 使用偏差值的绝对值作为权重
                    else:
                        score -= abs(NS)
    return score


# 对的密钥候选进行评分
def find_best_key_reduced(LAT, known_pt, known_ct):
    best_key = 0
    best_score = -float('inf')
    for key in range(2 ** 16):  # 只遍历前16位密钥
        score = calculate_key_score(key << 40, LAT, known_pt, known_ct)  # 假设其余40位为0
        if score > best_score:
            best_score = score
            best_key = key
    return best_key, best_score


# 获取并打印最佳密钥候选
best_key, best_score = find_best_key_reduced(LAT, known_plaintexts, known_ciphertexts)
print(f"最佳密钥候选的前16位: {best_key:016b}, 得分: {best_score}")