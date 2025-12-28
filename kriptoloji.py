import sys
import math
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QTextEdit, QPushButton,
    QComboBox, QRadioButton, QGroupBox, QMessageBox
)
from PyQt5.QtCore import Qt
import numpy as np

# --- 1. Sabitler ve Alfabe Tanımlamaları ---

# Python'daki tüm metinler için UTF-8 standartını kullanıyoruz.
# Türk Alfabesi (29 harf) ve İngiliz Alfabesi (26 harf) tanımlanmıştır.
TR_ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"  # 29 Harf
EN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"   # 26 Harf

class CipherEngine:
    """
    Tüm şifreleme ve deşifreleme mantığını içeren detaylı sınıf.
    Her adım, kullanıcının anlayabileceği şekilde bir çıktı dizisine eklenir.
    Hill şifrelemesi için tam sayı tabanlı modüler matris tersi hesaplama eklenmiştir.
    """
    def __init__(self):
        self.output_steps = []
        self.alphabet = ""
        self.m = 0

    def _get_char_to_num(self, char):
        return self.alphabet.find(char)

    def _get_num_to_char(self, num):
        # Modüler aritmetik kuralı: num % self.m her zaman 0 ile m-1 arasında olmalı.
        return self.alphabet[num % self.m]

    def _clean_text(self, text):
        """Metni işlemek için temizle ve büyük harfe çevir."""
        # Seçili alfabedeki karakterleri korur.
        cleaned = "".join(c.upper() for c in text if c.upper() in self.alphabet)
        return cleaned

    def _extended_gcd(self, a, b):
        """Genişletilmiş Öklid Algoritması ile modüler tersini bulur."""
        s0, s1 = 1, 0
        t0, t1 = 0, 1
        while b != 0:
            q = a // b
            a, b = b, a % b
            s0, s1 = s1, s0 - q * s1
            t0, t1 = t1, t0 - q * t1
        return a, s0, t0

    def _mod_inverse(self, a, m):
        """a'nın m modundaki tersini (a^-1) bulur."""
        g, x, y = self._extended_gcd(a, m)
        if g != 1:
            return None
        # x % m, negatif x değerleri için modüler tersi doğru döndürür.
        return x % m

    # --- Hill Şifrelemesi için Gerekli Tam Sayı Modüler Matris İşlemleri ---
    
    def _mod_det(self, matrix):
        """Matrixin determinantını mod M içinde hesaplar (Rekürsif)."""
        n = matrix.shape[0]
        if n == 1:
            return matrix[0, 0] % self.m
        
        det = 0
        # İlk satır üzerinden kofaktör açılımı
        for c in range(n):
            # Alt matrisi (minör) oluştur
            sub_matrix = np.delete(np.delete(matrix, 0, axis=0), c, axis=1)
            # Kofaktör işareti: (-1)^(0+c)
            sign = 1 if c % 2 == 0 else -1
            
            # Rekürsif çağrı ile determinantı hesapla ve mod M içinde tut
            term = (sign * matrix[0, c] * self._mod_det(sub_matrix))
            det = (det + term)
            
        # Python'da negatif sonuçları mod M içinde tutmak için
        return det % self.m
    
    def _get_cofactor_matrix(self, matrix):
        """Matrisin Adjugate (Eşlenik) matrisini mod M içinde hesaplar."""
        n = matrix.shape[0]
        adjugate_matrix = np.zeros((n, n), dtype=int)
        
        for r in range(n):
            for c in range(n):
                # Alt matrisi (minör) oluştur: r. satır ve c. sütun silinir
                minor_matrix = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
                
                # Kofaktör (Minör Determinantı * (-1)^(r+c))
                minor_det = self._mod_det(minor_matrix)
                # Kofaktör işareti: (-1)^(r+c)
                sign = 1 if (r + c) % 2 == 0 else -1
                
                cofactor = minor_det * sign
                
                # Adjugate matrisi, kofaktör matrisinin transpozudur: Adj[c, r] = Cofactor[r, c]
                adjugate_matrix[c, r] = cofactor % self.m

        # Negatif elemanları mod M içinde tutmak için son bir mod alma
        return adjugate_matrix % self.m


    def hill_cipher(self, key_text, text, encrypt, selected_alphabet):
        self.alphabet = TR_ALPHABET if selected_alphabet == "TR" else EN_ALPHABET
        self.m = len(self.alphabet)
        self.output_steps.append(f"--- HILL ŞİFRELEME ANALİZİ ---")
        self.output_steps.append(f"Kullanılan Alfabe: {self.alphabet} (Boyut M = {self.m})")
        
        cleaned_text = self._clean_text(text)

        # 1. Anahtar Matrisini Oluşturma
        try:
            # Anahtar metni (key_text) boşluklarla ayrılmış sayı dizisi olarak beklenir
            key_matrix_list = [int(n.strip()) for n in key_text.split() if n.strip()]
        except ValueError:
            self.output_steps.append("KRİTİK HATA: Hill Şifresi anahtarı yalnızca tam sayılar içermelidir (Örn: 6 24 1 13).")
            return None
            
        key_len = len(key_matrix_list)
        n = int(np.sqrt(key_len))

        if n * n != key_len or key_len == 0:
            self.output_steps.append(f"HATA: Anahtar eleman sayısı ({key_len}) bir tam kare olmalıdır (Örn: 4, 9, 16). Geçersiz eleman sayısı. Giriş: {key_text}")
            return None

        self.output_steps.append(f"Kullanılan Matris Boyutu (n): {n}x{n}. Metin blokları {n} harften oluşacaktır.")

        # Anahtar matrisi oluşturma
        key_matrix = np.array(key_matrix_list).reshape(n, n)
        self.output_steps.append(f"1. Anahtar Matrisi (K) (Girdiğiniz Sayılardan Oluşturuldu):\n{key_matrix}")

        # 2. KRİTİK ANAHTAR GEÇERLİLİK KONTROLÜ
        
        # Determinantı tam sayı modüler aritmetik ile hesapla
        det = self._mod_det(key_matrix)
        self.output_steps.append(f"2. Determinant (det(K)) Hesaplama: det(K) = {det} (mod {self.m}) (Tam Sayı Aritmetiğiyle)")

        if det == 0:
            self.output_steps.append("KRİTİK HATA: Determinant 0. Matris tekil olduğu için (K^-1) mevcut değil. Bu anahtar matrisi KULLANILAMAZ.")
            return None

        # Modüler tersin varlığını kontrol et
        det_inv = self._mod_inverse(det, self.m)
        if det_inv is None:
            g = math.gcd(det, self.m)
            self.output_steps.append(f"KRİTİK HATA: det(K)={det} ve modül M={self.m} aralarında asal değil (EBOB={g}). Modüler ters mevcut değil. Bu anahtar matrisi KULLANILAMAZ.")
            return None
        
        self.output_steps.append(f"3. Anahtar Geçerliliği Kontrolü: det(K)={det} (mod {self.m}) ve modüler tersi {det_inv} bulundu. Anahtar matrisi GEÇERLİDİR.")

        # 4. Metin bloğu tamamlama (padding)
        if len(cleaned_text) % n != 0:
            padding_needed = n - (len(cleaned_text) % n)
            # Seçilen alfabeye uygun tamamlama karakteri
            padding_char = 'Z' if self.alphabet == EN_ALPHABET else 'X' 
            cleaned_text += padding_char * padding_needed
            self.output_steps.append(f"4. Metin Bloğu Tamamlama: Metin boyutu ({len(cleaned_text) - padding_needed}) {n}'e tam bölünmediği için, sonuna {padding_needed} adet '{padding_char}' eklenerek metin boyutu {len(cleaned_text)}'e tamamlandı.")

        text_blocks = [cleaned_text[i:i + n] for i in range(0, len(cleaned_text), n)]
        result_text = ""
        target_matrix = key_matrix

        if not encrypt:
            # DÜZELTME: Deşifreleme için ters matris (K^-1) tam sayı modüler aritmetik ile hesaplanması
            self.output_steps.append(f"\n5. Deşifreleme İçin Ters Matris (K^-1) Hesaplama (Tam Sayı Aritmetiğiyle):")
            
            # Adjugate (Eşlenik) matrisini tam sayı modüler aritmetik ile hesapla
            adjugate_matrix = self._get_cofactor_matrix(key_matrix)
            self.output_steps.append(f"   - Adjugate Matrisi (Adj(K)) (mod {self.m}):\n{adjugate_matrix}")
            
            # Ters Matris: K^-1 = det_inv * Adj(K) mod M
            # Bu, Hill şifrelemesi için güvenilir, tam sayı tabanlı ters matris hesaplama yöntemidir.
            inv_matrix = (adjugate_matrix * det_inv) % self.m
            target_matrix = inv_matrix
            self.output_steps.append(f"K^-1 = {det_inv} * Adj(K) (mod {self.m}):\n{target_matrix}")


        self.output_steps.append(f"\n6. Blok İşlemleri:")
        for block in text_blocks:
            # Metin bloğunu sayı dizisine çevir
            num_vector = np.array([self._get_char_to_num(c) for c in block])

            # Matris çarpımı (K * P) veya (K^-1 * C)
            result_vector = np.dot(target_matrix, num_vector)
            
            # Modulo M işlemi
            final_vector = result_vector % self.m

            # Sayı dizisini harf dizisine çevir
            result_block = "".join([self._get_num_to_char(n) for n in final_vector])
            result_text += result_block

            num_str = [str(n) for n in num_vector]
            res_str = [str(r) for r in result_vector]
            fin_str = [str(f) for f in final_vector]

            self.output_steps.append(f"\nBlok: '{block}' ({' '.join(num_str)})")
            # Matrisin ve vektörün numpy array formatını string'e çevirerek daha okunabilir hale getir
            mat_str = "[\n" + "\n".join([f"  {row.tolist()}" for row in target_matrix]) + "\n]"
            self.output_steps.append(f"Matris Çarpımı:\n{mat_str} x {num_vector.tolist()} =\n{result_vector.tolist()}")
            self.output_steps.append(f"Modulo {self.m} İşlemi: ({' '.join(res_str)}) mod {self.m} = ({' '.join(fin_str)})")
            self.output_steps.append(f"Sonuç Blok: {result_block}")

        return result_text

    def affine_cipher(self, key_text, text, encrypt, selected_alphabet):
        self.alphabet = TR_ALPHABET if selected_alphabet == "TR" else EN_ALPHABET
        self.m = len(self.alphabet)
        self.output_steps.append(f"--- AFFINE ŞİFRELEME ANALİZİ ---")
        self.output_steps.append(f"Kullanılan Alfabe: {self.alphabet} (Boyut M = {self.m})")

        cleaned_text = self._clean_text(text)
        if not cleaned_text:
            self.output_steps.append("HATA: Şifrelenecek/Deşifrelenecek metin alfabede geçerli karakter içermiyor.")
            return None

        # Anahtarı A ve B olarak ayrıştırma
        try:
            # Anahtar metni "A B" veya "A,B" formatında beklenir
            parts = [p.strip() for p in key_text.replace(',', ' ').split()]
            if len(parts) != 2:
                 self.output_steps.append(f"HATA: Affine şifresi için anahtar 'A B' veya 'A,B' formatında iki sayı olmalıdır. Girilen: {key_text}")
                 return None

            a = int(parts[0])
            b = int(parts[1])
        except ValueError:
            self.output_steps.append(f"HATA: Anahtar (A ve B) sayı olmalıdır. Girilen: {key_text}")
            return None

        self.output_steps.append(f"1. Kullanılan Anahtarlar: A = {a}, B = {b}")

        # A'nın M ile aralarında asal olma kontrolü (A < M olmalı)
        if math.gcd(a, self.m) != 1:
            self.output_steps.append(f"HATA: Anahtar A ({a}) ve modül M ({self.m}) aralarında asal değil (EBOB={math.gcd(a, self.m)}). Affine şifrelemesi için A'nın tersi mevcut olmalıdır. Lütfen başka bir A değeri seçin.")
            return None
        self.output_steps.append(f"2. A ve M Arasında Asal Kontrolü: EBOB({a}, {self.m}) = 1. Anahtar geçerlidir.")

        result_text = ""
        cipher_val = 0 # Loop dışında tanımlandı
        
        if encrypt:
            # Şifreleme: C = (A * P + B) mod M
            self.output_steps.append(f"3. Şifreleme Formülü: C = ({a} * P + {b}) mod {self.m}")
        else:
            # Deşifreleme: P = A^-1 * (C - B) mod M
            a_inv = self._mod_inverse(a, self.m)
            self.output_steps.append(f"3. Deşifreleme İçin A^-1: {a}^-1 = {a_inv} (mod {self.m})")
            self.output_steps.append(f"4. Deşifreleme Formülü: P = {a_inv} * (C - {b}) mod {self.m}")

        self.output_steps.append(f"\n5. Karakter İşlemleri:")
        for char in cleaned_text:
            P_or_C = self._get_char_to_num(char)
            step_output = f"Karakter '{char}' Sayısal Değer: {P_or_C}. "

            if encrypt:
                # C = (A * P + B) mod M
                cipher_val = (a * P_or_C + b) % self.m
                step_output += f"C = ({a} * {P_or_C} + {b}) mod {self.m} = {cipher_val}"
            else:
                # Deşifreleme
                a_inv = self._mod_inverse(a, self.m)
                # Modüler aritmetik kurallarına göre (P_or_C - b) ifadesinin negatif olması durumunu ele al
                dec_term = (P_or_C - b) % self.m
                dec_val = (a_inv * dec_term) % self.m
                step_output += f"C - B = {P_or_C} - {b} = {P_or_C - b}. Modulo {self.m} Karşılığı: {dec_term}. P = {a_inv} * {dec_term} mod {self.m} = {dec_val}"
                cipher_val = dec_val # Ortak değişkene atama

            result_char = self._get_num_to_char(cipher_val)
            result_text += result_char
            step_output += f". Sonuç Karakter: {result_char}"
            self.output_steps.append(step_output)

        return result_text

    def _keyword_to_numeric_key(self, keyword):
        """
        Anahtar kelimeyi alfabedeki sırasına göre sayısal bir anahtar dizisine çevirir.
        """
        key = keyword.upper()
        
        # Metinde alfabede olmayan karakter varsa temizle
        key = self._clean_text(key)
        
        if not key:
             # Hata mesajı Transpozisyon metodunda daha kapsamlı veriliyor.
             return [], ""
             
        # 1. Her karakterin (alfabedeki pozisyonu, orijinal indeksi) çiftini oluştur
        sort_list = [(self._get_char_to_num(c), i) for i, c in enumerate(key)]
        
        # 2. Alfabetik pozisyona göre sırala (pozisyonlar aynıysa orijinal sırayı koru)
        sorted_list = sorted(sort_list)
        
        # 3. Sıralanmış listedeki pozisyonlarına göre (1'den başlayarak) rankları oluştur
        rank_map = {}
        for rank, item in enumerate(sorted_list):
            original_index = item[1]
            # Rank 1-tabanlıdır
            rank_map[original_index] = rank + 1
            
        # 4. Anahtar kelimenin orijinal sırasına göre rankları listele
        key_sequence = [rank_map[i] for i in range(len(key))]
        
        return key_sequence, key


    def transposition_cipher(self, key_text, text, encrypt, selected_alphabet):
            self.alphabet = TR_ALPHABET if selected_alphabet == "TR" else EN_ALPHABET
            self.m = len(self.alphabet)
            self.output_steps.append(f"--- DÜZENSİZ KOLON TRANPOZİSYON ANALİZİ ---")
            
            cleaned_text = self._clean_text(text)
            key_order, key_word = self._keyword_to_numeric_key(key_text)
            key_len = len(key_order)

            if not cleaned_text or not key_word:
                return None

            total_len = len(cleaned_text)
            num_rows = math.ceil(total_len / key_len)
            remainder = total_len % key_len # Son satırda kaç harf olduğu
            
            self.output_steps.append(f"1. Anahtar: {key_word} (Boyut: {key_len})")
            self.output_steps.append(f"2. Metin Uzunluğu: {total_len}. Satır Sayısı: {num_rows}")
            self.output_steps.append(f"3. Bilgi: Dolgu (Padding) yapılmadan işlem yapılıyor.")

            # Matris oluşturma (Eksik hücreleri boş bırakacağız)
            matrix = [['' for _ in range(key_len)] for _ in range(num_rows)]

            if encrypt:
                # --- ŞİFRELEME ---
                # 1. Metni satır satır yerleştir
                k = 0
                for i in range(num_rows):
                    for j in range(key_len):
                        if k < total_len:
                            matrix[i][j] = cleaned_text[k]
                            k += 1
                
                # 2. Sütunları anahtar sırasına göre oku
                result_text = ""
                for order in range(1, key_len + 1):
                    col_idx = key_order.index(order)
                    col_chars = ""
                    for i in range(num_rows):
                        if matrix[i][col_idx] != '':
                            col_chars += matrix[i][col_idx]
                    result_text += col_chars
                    self.output_steps.append(f"Sütun {col_idx+1} okundu: {col_chars}")

            else:
                # --- DEŞİFRELEME (En kritik kısım) ---
                # Hangi sütunun kaç karakter uzunluğunda olduğunu belirle
                # Normalde her sütun 'total_len // key_len' kadardır. 
                # Ancak ilk 'remainder' kadar sütun 1 karakter daha uzundur.
                col_lengths = {}
                for j in range(key_len):
                    # j. sütun, matrisin fiziksel sütunudur
                    length = total_len // key_len
                    if j < remainder or remainder == 0: 
                        # Eğer remainder 0 ise tüm sütunlar tamdır
                        if remainder != 0 and j < remainder:
                            length += 1
                        elif remainder == 0:
                            length = total_len // key_len
                    col_lengths[j] = length

                # Şifreli metni parçalara ayırıp sütunlara (anahtar sırasına göre) yerleştir
                k = 0
                # Sütunları alfabetik sıraya göre (1, 2, 3...) doldurmamız lazım
                for order in range(1, key_len + 1):
                    col_idx = key_order.index(order)
                    current_col_len = col_lengths[col_idx]
                    
                    # Şifreli metinden o sütuna ait parçayı al
                    for i in range(current_col_len):
                        if k < total_len:
                            matrix[i][col_idx] = cleaned_text[k]
                            k += 1
                
                # Matrisi satır satır oku
                result_text = ""
                for i in range(num_rows):
                    for j in range(key_len):
                        if matrix[i][j] != '':
                            result_text += matrix[i][j]

            return result_text

class CipherApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kriptografi Analiz ve Simülasyon Uygulaması (v1.2.0 - Hill Fix)") #
        self.setGeometry(100, 100, 1000, 750)
        self.engine = CipherEngine()
        self._setup_ui()

    def _setup_ui(self):
        """Kullanıcı arayüzü bileşenlerini titizlikle yerleştirir."""
        central_widget = QWidget()
        main_layout = QHBoxLayout(central_widget)

        # --- SOL PANEL: Kontroller ve Girişler (QVBoxLayout) ---
        control_panel = QWidget()
        control_layout = QVBoxLayout(control_panel)
        control_layout.setAlignment(Qt.AlignTop)

        # 1. Alfabe Seçimi
        alphabet_group = QGroupBox("1. Alfabe Seçimi (M)")
        alphabet_layout = QHBoxLayout()
        self.tr_radio = QRadioButton("Türkçe (M=29)")
        self.en_radio = QRadioButton("İngilizce (M=26)")
        self.tr_radio.setChecked(True)
        alphabet_layout.addWidget(self.tr_radio)
        alphabet_layout.addWidget(self.en_radio)
        alphabet_group.setLayout(alphabet_layout)
        control_layout.addWidget(alphabet_group)

        # 2. Şifreleme Yöntemi Seçimi
        cipher_group = QGroupBox("2. Şifreleme Yöntemi")
        cipher_layout = QVBoxLayout()
        self.cipher_combo = QComboBox()
        self.cipher_combo.addItems(["Affine Şifrelemesi", "Hill Şifrelemesi", "Transpozisyon Şifrelemesi"])
        self.cipher_combo.currentIndexChanged.connect(self._update_key_placeholder)
        cipher_layout.addWidget(self.cipher_combo)
        cipher_group.setLayout(cipher_layout)
        control_layout.addWidget(cipher_group)

        # 3. Anahtar Girişi
        key_group = QGroupBox("3. Anahtar Metin/Değerler")
        key_layout = QVBoxLayout()
        self.key_input = QLineEdit()
        self._update_key_placeholder()
        key_layout.addWidget(self.key_input)
        key_group.setLayout(key_layout)
        control_layout.addWidget(key_group)

        # 4. Metin Girişi
        text_group = QGroupBox("4. Şifrelenecek/Deşifrelenecek Metin")
        text_layout = QVBoxLayout()
        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText("İşlenecek metni buraya girin...")
        text_layout.addWidget(self.text_input)
        text_group.setLayout(text_layout)
        control_layout.addWidget(text_group)

        # 5. İşlem Tipi Seçimi
        operation_group = QGroupBox("5. İşlem Tipi")
        operation_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton("Şifrele")
        self.decrypt_radio = QRadioButton("Deşifrele")
        self.encrypt_radio.setChecked(True)
        operation_layout.addWidget(self.encrypt_radio)
        operation_layout.addWidget(self.decrypt_radio)
        operation_group.setLayout(operation_layout)
        control_layout.addWidget(operation_group)

        # 6. İşlem Başlatma Butonu
        self.process_button = QPushButton("6. İŞLEMİ BAŞLAT ve ADIMLARI GÖSTER")
        self.process_button.setStyleSheet("font-size: 14pt; padding: 10px; background-color: #4CAF50; color: white; border-radius: 8px;")
        self.process_button.clicked.connect(self.process_cipher)
        control_layout.addWidget(self.process_button)

        control_layout.addStretch(1) # Boşluk ekle

        # Sol paneli ana düzeneğe ekle
        main_layout.addWidget(control_panel, 1)

        # --- SAĞ PANEL: Sonuçlar ve Detaylı Adımlar (QVBoxLayout) ---
        result_panel = QWidget()
        result_layout = QVBoxLayout(result_panel)

        # Başlık
        result_title = QLabel("7. İŞLEM SONUCU VE DETAYLI ADIM ANALİZİ")
        result_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #333;")
        result_layout.addWidget(result_title)

        # Sonuç Metni Alanı
        result_label = QLabel("Nihai Sonuç:")
        result_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        result_layout.addWidget(result_label)

        self.result_output = QLineEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setStyleSheet("font-size: 14pt; font-weight: bold; padding: 10px; background-color: #EFEFEF; border: 2px solid #CCC; border-radius: 6px; color: black;")
        result_layout.addWidget(self.result_output)


        # Adım Analizi Alanı
        steps_label = QLabel("Detaylı İşlem Adımları:")
        steps_label.setStyleSheet("font-weight: bold; margin-top: 15px;")
        result_layout.addWidget(steps_label)

        self.steps_output = QTextEdit()
        self.steps_output.setReadOnly(True)
        self.steps_output.setStyleSheet("font-family: monospace; font-size: 10pt; background-color: #F8F8F8; color: #333333; border: 1px solid #AAA; padding: 10px; border-radius: 4px;")
        result_layout.addWidget(self.steps_output, 1)

        # Sağ paneli ana düzeneğe ekle
        main_layout.addWidget(result_panel, 2)

        self.setCentralWidget(central_widget)

    def _update_key_placeholder(self):
        """Seçilen şifreye göre anahtar giriş alanını günceller."""
        cipher = self.cipher_combo.currentText()
        if cipher == "Hill Şifrelemesi":
            
            placeholder = "Matris elemanlarını boşlukla ayırarak girin (tam kare adet olmalı). Örn: 6 24 1 13 (2x2) veya 17 17 5 21 18 21 2 2 19 (3x3)"
        elif cipher == "Affine Şifrelemesi":
            placeholder = "A ve B değerleri aralarında boşluk veya virgül ile. Örn: 5 8"
        elif cipher == "Transpozisyon Şifrelemesi":
            placeholder = "Sütunların sırasını belirleyecek kelime/isim. Örn: ANAHTAR"
        else:
            placeholder = "Lütfen bir şifreleme yöntemi seçin."
        self.key_input.setPlaceholderText(placeholder)

    def process_cipher(self):
        """Ana işlemi tetikler ve sonuçları arayüze aktarır."""
        cipher_name = self.cipher_combo.currentText()
        key_text = self.key_input.text()
        text = self.text_input.text()
        encrypt = self.encrypt_radio.isChecked()
        selected_alphabet = "TR" if self.tr_radio.isChecked() else "EN"

        # Giriş Kontrolleri
        if not key_text or not text:
            QMessageBox.critical(self, "Giriş Hatası", "Anahtar metin ve şifrelenecek/deşifrelenecek metin boş bırakılamaz.")
            return

        # 1. Giriş Özeti Oluşturma
        initial_steps = [
            "==================================================================",
            f"SEÇİLEN KRİPTO SİSTEMİ: {cipher_name}",
            f"ALFABE VE MODÜL (M): {'Türkçe (M=29)' if selected_alphabet == 'TR' else 'İngilizce (M=26)'}",
            f"İŞLEM TİPİ: {'Şifreleme' if encrypt else 'Deşifreleme'}",
            f"ANAHTAR GİRDİSİ: {key_text}",
            f"İŞLENECEK METİN: {text}",
            "=================================================================="
        ]
        self.engine.output_steps = initial_steps

        # 2. İşlem Yürütme
        try:
            if cipher_name == "Hill Şifrelemesi":
                result = self.engine.hill_cipher(key_text, text, encrypt, selected_alphabet)
            elif cipher_name == "Affine Şifrelemesi":
                result = self.engine.affine_cipher(key_text, text, encrypt, selected_alphabet)
            elif cipher_name == "Transpozisyon Şifrelemesi":
                result = self.engine.transposition_cipher(key_text, text, encrypt, selected_alphabet)
            else:
                result = None
                self.engine.output_steps.append("HATA: Geçersiz şifreleme yöntemi seçildi.")

            # 3. Çıktıları Arayüze Aktarma
            if result is not None:
                self.result_output.setText(result)
                steps_text = "\n".join(self.engine.output_steps)
                self.steps_output.setText(steps_text)
            else:
                # İşlemde hata oluştuysa (örneğin anahtar geçersizse)
                self.result_output.setText("HATA: İşlem Başarısız. Adım Analizi Bölümünü İnceleyin.")
                self.steps_output.setText("\n".join(self.engine.output_steps))

        except Exception as e:
            # Genel Hata Yönetimi
            error_msg = f"KRİTİK HATA: Uygulama kodunda beklenmedik bir hata oluştu: {type(e).__name__}: {str(e)}. Lütfen kullandığınız anahtar ve metni kontrol edin ve hatayı bana bildirin."
            QMessageBox.critical(self, "Kritik Hata", error_msg)
            self.steps_output.setText(error_msg)
            self.result_output.setText("KRİTİK HATA")

if __name__ == '__main__':
    # QT Uygulamasını Başlatma (Linux ve Windows için standart başlangıç)
    app = QApplication(sys.argv)
    window = CipherApp()
    window.show()
    sys.exit(app.exec_())
