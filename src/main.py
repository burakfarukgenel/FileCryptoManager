import os
from utils import generate_pgp_keys, calculate_file_hashes, encrypt_file_pgp, decrypt_file_pgp, verify_passphrase

def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 2 defa dirname ile src'den çıkıyoruz

    # Anahtarların kaydedileceği klasörü oluştur
    keys_dir = os.path.join(project_root, "keys")
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
    # Anahtarların kaydedileceği yollar
    private_key_path = os.path.join(keys_dir, "private_key.pgp")
    public_key_path = os.path.join(keys_dir, "public_key.pgp")

    # Eğer anahtarlar varsa, kullanıcıdan mevcut passphrase'i iste
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("Mevcut anahtarlar kullanılıyor.")
        current_passphrase = input("Lütfen Private Key parolanızı girin: ")

        # Mevcut passphrase'in doğruluğunu kontrol et
        if not verify_passphrase(private_key_path, current_passphrase):
            print("❌ Hata: Yanlış parola girdiniz. Program sonlandırılıyor.")
            return

        new_passphrase = input("Yeni bir parola belirlemek istiyor musunuz? (E/H): ").strip().lower()

        if new_passphrase == "e":
            # Yeni passphrase iste ve anahtarları yeniden oluştur
            passphrase = input("Lütfen yeni Private Key parolanızı girin: ")
            print("Yeni PGP anahtarları oluşturuluyor...")
            if not generate_pgp_keys(private_key_path, public_key_path, passphrase):
                print("Anahtar oluşturma işlemi başarısız. Program sonlandırılıyor.")
                return
        else:
            # Mevcut passphrase'i kullan
            passphrase = current_passphrase
    else:
        # Anahtarlar yoksa, yeni anahtarlar oluştur
        print("PGP anahtarları bulunamadı. Yeni anahtarlar oluşturuluyor...")
        passphrase = input("Lütfen Private Key için bir parola belirleyin: ")
        if not generate_pgp_keys(private_key_path, public_key_path, passphrase):
            print("Anahtar oluşturma işlemi başarısız. Program sonlandırılıyor.")
            return

    # Kullanıcıdan dosya yolunu al
    file_path = input("Lütfen dosya yolunu girin: ")

    # Dosyanın hash'lerini hesapla (1MB'lık parçalara bölerek)
    print("Dosyanın hash'leri hesaplanıyor...")
    original_md5, original_sha256, original_sha512 = calculate_file_hashes(file_path)

    # Dosyayı PGP ile şifrele
    encrypted_file_path = file_path + ".pgp"
    print("Dosya PGP ile şifreleniyor...")
    if not encrypt_file_pgp(file_path, public_key_path, encrypted_file_path):
        print("Şifreleme işlemi başarısız. Program sonlandırılıyor.")
        return

    # Şifrelenmiş dosyanın şifresini çöz
    decrypted_file_path = file_path + ".decrypted"
    print("Şifrelenmiş dosyanın şifresi çözülüyor...")
    if not decrypt_file_pgp(encrypted_file_path, private_key_path, decrypted_file_path, passphrase):
        print("Şifre çözme işlemi başarısız. Program sonlandırılıyor.")
        return

    # Şifresi çözülen dosyanın hash'lerini hesapla ve doğrula
    print("Şifresi çözülen dosyanın hash'leri hesaplanıyor...")
    decrypted_md5, decrypted_sha256, decrypted_sha512 = calculate_file_hashes(decrypted_file_path)

    if decrypted_md5 == original_md5:
        print("✅ Şifresi çözülen dosyanın hash'i orijinal dosya ile eşleşiyor.")
    else:
        print("❌ Uyarı: Şifresi çözülen dosyanın hash'i orijinal dosya ile eşleşmiyor!")

if __name__ == "__main__":
    main()