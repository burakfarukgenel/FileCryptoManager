# FileCryptoManager

Bu proje, büyük dosyaları parçalara bölerek hash değerlerini hesaplar, PGP ile şifreler ve güvenli bir şekilde saklar veya iletir.

## 1. Dosyanın Parçalara Bölünüp Hash Değerlerinin Alınması

İlk olarak, büyük bir dosya küçük parçalara bölünür ve her bir parça için hash değerleri hesaplanır.

### Neden bölüyoruz?

- **Veri bütünlüğü** kontrolü yapmak daha verimli hale gelir.
- Bozulma durumunda hangi parçanın bozulduğunu kolayca tespit edilebilir.
- Büyük dosyanın tümünü tekrar okumaya gerek kalmadan küçük parçalar halinde işlem yapılabilir.

### Ne yapılıyor?

- Dosyanın her bir parçası için **MD5**, **SHA-256** ve **SHA-512** hash değerleri hesaplanır.
- Bu hash değerleri, parçaların bütünlüğünü korumak için saklanır.
- Ekstra olarak, tüm dosyanın hash değeri de hesaplanır.

Eğer biri dosyanın içeriğini değiştirirse, hash değeri farklı çıkacak ve dosyanın bozulduğu anlaşılacaktır.

---

## 2. Dosyanın PGP ile Şifrelenmesi

Bu aşamada dosya, içeriklerinin güvenliğini sağlamak için şifrelenir.

### Ne yapılıyor?

- **Public Key (Açık Anahtar)** kullanılarak dosya şifrelenir.
- **Private Key (Özel Anahtar)** ile şifre çözülebilir şekilde saklanır.

### Neden PGP kullanıyoruz?

- **Asimetrik şifreleme** sayesinde güvenli bir şekilde dosya iletimi yapılabilir.
- Public key ile şifreleme yapılır, bu nedenle yalnızca private key sahibi dosyayı açabilir.

---

## 3. Şifrelenmiş Dosyanın Açılması

Şifrelenmiş dosyayı geri açabilmek için private key kullanılır.

- **Private Key** ile PGP şifreleme çözülür.
- Açılan dosyanın hash değerleri tekrar hesaplanarak orijinal hash'lerle karşılaştırılır.
  - Eğer hash değerleri tutuyorsa, dosya bozulmadan açılmıştır.
  - Farklıysa, şifre çözme sırasında veya dosya taşınırken bir hata olmuş olabilir.

---

## Uygulamanın Genel Amacı ve Kullanım Alanları

Bu işlem güvenli veri saklama ve iletim için yapılır.

### Amaçlar:

- ✅ **Veri Bütünlüğünü Sağlamak** → Hash değerleri sayesinde verinin değişip değişmediğini anlayabiliriz.
- ✅ **Güvenli Şifreleme** → PGP ile dosya güvenli bir şekilde şifrelenmiş olur.
- ✅ **Yetkilendirme** → Sadece private key’e sahip kişiler dosyayı açabilir, böylece yetkisiz erişim engellenir.
- ✅ **Veri Aktarımı** → Dosyayı güvenli şekilde birine gönderebilir, şifreleyip karşı tarafa verebilirsiniz. Onlar da private key ile açabilir.

Bu yöntemi kritik veri saklama, hassas dosya transferi, yedekleme ve siber güvenlik uygulamalarında kullanabilirsiniz.

---

## Kurulum ve Kullanım

### Kurulum

1. Projeyi klonlayın:
   ```bash
   git clone https://github.com/burakfarukgenel/FileCryptoManager.git
