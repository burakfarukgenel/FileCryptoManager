
import hashlib
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

def generate_pgp_keys(private_key_path, public_key_path, passphrase):
    """
    PGP anahtarlarını oluşturur ve belirtilen dosya yollarına kaydeder.
    """
    try:
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        uid = pgpy.PGPUID.new("FileCryptoManager User", email="filecrypto@example.com")

        key.add_uid(uid,
                    usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP,
                                 CompressionAlgorithm.Uncompressed])

        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

        with open(private_key_path, "wb") as private_key_file:
            private_key_file.write(str(key).encode("utf-8"))

        with open(public_key_path, "wb") as public_key_file:
            public_key_file.write(str(key.pubkey).encode("utf-8"))

        print(f"✅ Private Key ve Public Key oluşturuldu ve kaydedildi.")
        print(f"Private Key: {private_key_path}")
        print(f"Public Key: {public_key_path}")
        return True
    except Exception as e:
        print(f"❌ Hata: Anahtarlar oluşturulurken bir sorun oluştu: {e}")
        return False

def calculate_file_hashes(file_path, chunk_size=1024 * 1024):
    """
    Dosyayı belirtilen boyutta parçalara böler ve her parçanın hash'ini hesaplar.
    Ayrıca tüm dosyanın hash'ini de hesaplar.
    """
    full_hash_md5 = hashlib.md5()
    full_hash_sha256 = hashlib.sha256()
    full_hash_sha512 = hashlib.sha512()

    for i, chunk in enumerate(read_file_in_chunks(file_path, chunk_size)):
        print(f"Parça {i + 1} MD5: {calculate_md5(chunk)}")
        print(f"Parça {i + 1} SHA-256: {calculate_sha256(chunk)}")
        print(f"Parça {i + 1} SHA-512: {calculate_sha512(chunk)}")

        full_hash_md5.update(chunk)
        full_hash_sha256.update(chunk)
        full_hash_sha512.update(chunk)

    print(f"Tüm Dosya MD5: {full_hash_md5.hexdigest()}")
    print(f"Tüm Dosya SHA-256: {full_hash_sha256.hexdigest()}")
    print(f"Tüm Dosya SHA-512: {full_hash_sha512.hexdigest()}")

    return full_hash_md5.hexdigest(), full_hash_sha256.hexdigest(), full_hash_sha512.hexdigest()

def encrypt_file_pgp(file_path, public_key_path, output_path):
    """
    Dosyayı PGP ile şifreler.
    """
    try:
        public_key, _ = pgpy.PGPKey.from_file(public_key_path)
        if not public_key.is_public:
            raise ValueError("Belirtilen dosya bir Public Key değil.")

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = public_key.encrypt(
            pgpy.PGPMessage.new(file_data),
            cipher=SymmetricKeyAlgorithm.AES256,
            compression=CompressionAlgorithm.ZIP
        )

        with open(output_path, "wb") as encrypted_file:
            encrypted_file.write(str(encrypted_data).encode("utf-8"))

        print(f"✅ Dosya başarıyla şifrelendi: {output_path}")
        return True
    except Exception as e:
        print(f"❌ Şifreleme hatası: {e}")
        return False

def decrypt_file_pgp(encrypted_file_path, private_key_path, output_path, passphrase):
    """
    Dosyanın şifresini PGP ile çözer.
    """
    try:
        private_key, _ = pgpy.PGPKey.from_file(private_key_path)

        if private_key.is_protected:
            with private_key.unlock(passphrase):
                with open(encrypted_file_path, "rb") as encrypted_file:
                    encrypted_data = encrypted_file.read()

                encrypted_message = pgpy.PGPMessage.from_blob(encrypted_data)
                decrypted_data = private_key.decrypt(encrypted_message)

                with open(output_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data.message)

                print(f"✅ Dosyanın şifresi başarıyla çözüldü: {output_path}")
                return True
        else:
            with open(encrypted_file_path, "rb") as encrypted_file:
                encrypted_data = encrypted_file.read()

            encrypted_message = pgpy.PGPMessage.from_blob(encrypted_data)
            decrypted_data = private_key.decrypt(encrypted_message)

            with open(output_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data.message)

            print(f"✅ Dosyanın şifresi başarıyla çözüldü: {output_path}")
            return True

    except Exception as e:
        print(f"❌ Şifre çözme hatası: {e}")
        return False

def verify_passphrase(private_key_path, passphrase):
    """
    Private Key'in passphrase'ini doğrular.
    """
    try:
        private_key, _ = pgpy.PGPKey.from_file(private_key_path)

        if private_key.is_protected:
            with private_key.unlock(passphrase):
                # Eğer buraya kadar gelirse, passphrase doğrudur
                return True
        else:
            # Eğer Private Key korunmuyorsa, passphrase doğru kabul edilir
            return True
    except Exception as e:
        # Eğer hata alınırsa, passphrase yanlıştır
        return False

def read_file_in_chunks(file_path, chunk_size=1024 * 1024):
    """
    Dosyayı belirtilen boyutta parçalara bölerek okur.
    """
    with open(file_path, "rb") as file:
        while chunk := file.read(chunk_size):
            yield chunk

def calculate_md5(data):
    return hashlib.md5(data).hexdigest()

def calculate_sha256(data):
    return hashlib.sha256(data).hexdigest()

def calculate_sha512(data):
    return hashlib.sha512(data).hexdigest()