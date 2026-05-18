"""
import requests
import re

DEESEEK_API_URL = "http://localhost:11434/api/generate"

# TC Kimlik no regex
tc_regex = r"\b[1-9][0-9]{9}[02468]\b"

def is_valid_tc(tc: str) -> bool:
    if not tc.isdigit() or len(tc) != 11 or tc[0] == '0':
        return False

    digits = [int(c) for c in tc]
    odd_sum = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    even_sum = digits[1] + digits[3] + digits[5] + digits[7]
    if digits[9] != ((odd_sum * 7 - even_sum) % 10):
        return False

    if digits[10] != (sum(digits[:10]) % 10):
        return False

    return True

def should_block_message(text: str) -> bool:
    candidates = re.findall(tc_regex, text)
    valid_tcs = [tc for tc in candidates if is_valid_tc(tc)]
    return len(valid_tcs) >= 3

def contains_other_pii(text):
    email = re.search(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", text)
    phone = re.search(r"\b05\d{9}\b", text)
    return any([email, phone])

def query_deepseek(prompt):
    payload = {
        "model": "deepseek-r1:1.5b",
        "prompt": prompt,
        "stream": False
    }
    response = requests.post(DEESEEK_API_URL, json=payload)
    data = response.json()
    return data.get("response", "[Cevap alınamadı]")

def main():
    while True:
        text = input("Mesajınızı yazın (çıkmak için 'exit'): ")
        if text.lower() == 'exit':
            print("Çıkılıyor...")
            break

        if should_block_message(text):
            print("❌ [ENGELLENDİ] Mesaj 3 veya daha fazla geçerli TC içeriyor.")
            continue

        if contains_other_pii(text):
            print("❌ [ENGELLENDİ] Mesaj kişisel veri içeriyor (e-posta yada telefon), gönderilmedi.")
            continue

        print("✅ [DeepSeek cevaplıyor...]")
        cevap = query_deepseek(text)
        print(cevap)

if __name__ == "__main__":
    main()
"""

"""
# 2. mastercardlı

import requests
import re

DEESEEK_API_URL = "http://localhost:11434/api/generate"

# Regex'ler
tc_regex = r"\b[1-9][0-9]{9}[02468]\b"
mastercard_regex = r"\b(?:5[1-5][0-9]{14}|2(2[2-9][0-9]{12}|[3-6][0-9]{13}|7[01][0-9]{12}|720[0-9]{12}))\b"
visa_regex = r"\b4[0-9]{12}(?:[0-9]{3})?\b"

# TC Kimlik doğrulama
def is_valid_tc(tc: str) -> bool:
    if not tc.isdigit() or len(tc) != 11 or tc[0] == '0':
        return False
    digits = [int(c) for c in tc]
    odd_sum = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    even_sum = digits[1] + digits[3] + digits[5] + digits[7]
    if digits[9] != ((odd_sum * 7 - even_sum) % 10):
        return False
    if digits[10] != (sum(digits[:10]) % 10):
        return False
    return True

# Luhn algoritması
def is_valid_luhn(number: str) -> bool:
    digits = [int(d) for d in number[::-1]]
    for i in range(1, len(digits), 2):
        doubled = digits[i] * 2
        digits[i] = doubled - 9 if doubled > 9 else doubled
    return sum(digits) % 10 == 0

# Veri kontrolü ve nedenleri
def get_block_reasons(text: str):
    reasons = []

    # TC kontrolü
    tc_candidates = re.findall(tc_regex, text)
    valid_tcs = [tc for tc in tc_candidates if is_valid_tc(tc)]
    if len(valid_tcs) >= 3:
        reasons.append(f"{len(valid_tcs)} geçerli TC Kimlik Numarası")

    # Mastercard kontrolü
    mc_candidates = re.findall(mastercard_regex, text)
    valid_mcs = [mc for mc in mc_candidates if is_valid_luhn(mc)]
    if valid_mcs:
        reasons.append(f"{len(valid_mcs)} geçerli Mastercard numarası")

    # Visa kontrolü
    visa_candidates = re.findall(visa_regex, text)
    valid_visas = [v for v in visa_candidates if is_valid_luhn(v)]
    if valid_visas:
        reasons.append(f"{len(valid_visas)} geçerli Visa kartı numarası")

    # E-posta/telefon kontrolü
    email = re.search(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", text)
    phone = re.search(r"\b05\d{9}\b", text)
    if email:
        reasons.append("e-posta adresi")
    if phone:
        reasons.append("telefon numarası")

    return reasons

# DeepSeek'e gönderim
def query_deepseek(prompt):
    payload = {
        "model": "deepseek-r1:1.5b",
        "prompt": prompt,
        "stream": False
    }
    response = requests.post(DEESEEK_API_URL, json=payload)
    data = response.json()
    return data.get("response", "[Cevap alınamadı]")

# CLI
def main():
    while True:
        text = input("Mesajınızı yazın (çıkmak için 'exit'): ")
        if text.lower() == 'exit':
            print("Çıkılıyor...")
            break

        reasons = get_block_reasons(text)
        if reasons:
            print("❌ [ENGELLENDİ] Mesaj aşağıdaki nedenlerle engellendi:")
            for reason in reasons:
                print(f" - {reason}")
            continue

        print("✅ [DeepSeek cevaplıyor...]")
        cevap = query_deepseek(text)
        print(cevap)

if __name__ == "__main__":
    main()
"""

##3. loglu

import requests
import re
from datetime import datetime

DEESEEK_API_URL = "http://localhost:11434/api/generate"

# Regex'ler
tc_regex = r"\b[1-9][0-9]{9}[02468]\b"
mastercard_regex = r"(5[1-5][0-9]{14}|2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7[01][0-9]{12}|720[0-9]{12}))"
visa_regex = r"\b4[0-9]{12}(?:[0-9]{3})?\b"

# TC Kimlik doğrulama
def is_valid_tc(tc: str) -> bool:
    if not tc.isdigit() or len(tc) != 11 or tc[0] == '0':
        return False
    digits = [int(c) for c in tc]
    odd_sum = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    even_sum = digits[1] + digits[3] + digits[5] + digits[7]
    if digits[9] != ((odd_sum * 7 - even_sum) % 10):
        return False
    if digits[10] != (sum(digits[:10]) % 10):
        return False
    return True

# Luhn algoritması (kredi kartı için)
def is_valid_luhn(number: str) -> bool:
    digits = [int(d) for d in number[::-1]]
    for i in range(1, len(digits), 2):
        doubled = digits[i] * 2
        digits[i] = doubled - 9 if doubled > 9 else doubled
    return sum(digits) % 10 == 0

# Engelleme nedenlerini ve bulunan değerleri döndürür
def get_block_reasons(text: str):
    reasons = []

    # TC kontrolü
    tc_candidates = re.findall(tc_regex, text)
    valid_tcs = [tc for tc in tc_candidates if is_valid_tc(tc)]
    if len(valid_tcs) >= 3:
        reasons.append(f"{len(valid_tcs)} geçerli TC Kimlik Numarası: {', '.join(valid_tcs)}")

    # Mastercard kontrolü
    mc_candidates = re.findall(mastercard_regex, text)
    valid_mcs = [mc for mc in mc_candidates if is_valid_luhn(mc)]
    if valid_mcs:
        reasons.append(f"{len(valid_mcs)} geçerli Mastercard numarası: {', '.join(valid_mcs)}")

    # Visa kontrolü
    visa_candidates = re.findall(visa_regex, text)
    valid_visas = [v for v in visa_candidates if is_valid_luhn(v)]
    if valid_visas:
        reasons.append(f"{len(valid_visas)} geçerli Visa kartı numarası: {', '.join(valid_visas)}")

    # E-posta/telefon kontrolü
    email = re.search(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", text)
    phone = re.search(r"\b05\d{9}\b", text)
    if email:
        reasons.append("e-posta adresi")
    if phone:
        reasons.append("telefon numarası")

    return reasons, valid_tcs, valid_mcs, valid_visas

# DeepSeek API çağrısı
def query_deepseek(prompt):
    payload = {
        "model": "deepseek-r1:1.5b",
        "prompt": prompt,
        "stream": False
    }
    response = requests.post(DEESEEK_API_URL, json=payload)
    data = response.json()
    return data.get("response", "[Cevap alınamadı]")

# Log yazma (kronolojik ters, en son en üstte)
def write_log(text, reasons):
    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [BLOKLANDI] {text} | Nedenler: {', '.join(reasons)}\n"
    log_file = "blocked_messages.log"

    # Mevcut logu oku
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            old_logs = f.read()
    except FileNotFoundError:
        old_logs = ""

    # Yeni logu en üste yaz
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(log_entry + old_logs)

def main():
    while True:
        text = input("Mesajınızı yazın (çıkmak için 'exit'): ")
        if text.lower() == 'exit':
            print("Çıkılıyor...")
            break

        reasons, valid_tcs, valid_mcs, valid_visas = get_block_reasons(text)
        if reasons:
            print("❌ [ENGELLENDİ] Mesaj aşağıdaki nedenlerle engellendi:")
            for reason in reasons:
                print(f" - {reason}")

            # Loga sadece PII detaylarını yaz (kullanıcıya göstermeden)
            pii_details = []
            if valid_tcs:
                pii_details.append(f"TC Kimlik Numaraları: {', '.join(valid_tcs)}")
            if valid_mcs:
                pii_details.append(f"Mastercard Numara(lar): {', '.join(valid_mcs)}")
            if valid_visas:
                pii_details.append(f"Visa Kart(lar): {', '.join(valid_visas)}")

            write_log(text, pii_details)
            continue

        print("✅ [DeepSeek cevaplıyor...]")
        cevap = query_deepseek(text)
        print(cevap)

if __name__ == "__main__":
    main()
