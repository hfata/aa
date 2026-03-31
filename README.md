# micro-AES File Demo

Bu repository, orijinal `µAES` kütüphanesi üzerine kurulmuş, dosya tabanlı şifreleme ve chunk tabanlı `GCM` / `XTS` denemeleri için sadeleştirilmiş bir çalışma alanıdır.

Bu sürümde odak nokta:

- `input/demo_hex.txt` içindeki hex veriyi okuyup etkin AES modlarıyla şifrelemek
- Sonucu `outputs/` klasörüne yazmak
- Aynı çıktıyı tekrar okuyup çözmek
- İstenirse `GCM` ve `XTS` için makro kontrollü chunk akışlarını ayrı modül üzerinden göstermek

Bu repo artık test-vector odaklı orijinal `main.c` örneği değildir. `main.c`, doğrudan dosya giriş/çıkış akışına göre sadeleştirilmiştir.

## İçerik

- `micro_aes.c`
- `micro_aes.h`
- `micro_fpe.h`
- `main.c`
- `chunk.c`
- `chunk.h`
- `input/demo_hex.txt`
- `outputs/`
- `bin/`

`chunk.c` dosyası makrolara bağlı olarak `GCM` için `8`, `16` veya `32`, `XTS` için `16` veya `32` byte chunk ile çalışır.

## Kısa Özet

Programın çalışma modeli:

- Giriş dosyası `input/demo_hex.txt`
- Bu dosya `hex text` olarak yorumlanır
- Hex karakterler gerçek byte dizisine çevrilir
- Etkin modlar için şifreleme yapılır
- Çıktılar `outputs/` klasörüne yazılır
- Aynı çıktı tekrar okunur
- Decrypt yapılır
- Decrypt sonucu tekrar `hex` olarak yazılır

Örnek giriş:

```txt
00 11 22 33 44 55 66 77
88 99 aa bb cc dd ee ff
00 11 22 33 44 55 66 77
88 99 aa bb cc dd ee ff
```

## Önemli Not

Bu proje şu anda `raw binary file` değil, `hex text file` şifreliyor.

Yani:

- `00 11 22 33` gibi veri doğru çalışır
- `merhaba` gibi normal text mevcut akışta doğru yorumlanmaz

Sebep:

- dosya önce text olarak okunur
- sonra sadece hex karakterleri bayta çevrilir

## Dizin Yapısı

- `input/`
  Buraya giriş dosyaları konur.

- `outputs/`
  Program çıktıları buraya yazılır.

- `bin/`
  Derlenmiş executable burada tutulur.

Bu klasörlerin mevcut olduğu varsayılır. Kod bunları otomatik oluşturmaz.

## Derleme

Windows PowerShell + `gcc` ile örnek derleme:

```powershell
gcc -g *.c -o .\bin\main.exe
```

Çalıştırma:

```powershell
.\bin\main.exe
```

Alternatif:

```powershell
cd .\bin
.\main.exe
```

Program hem proje kökünden hem `bin` klasöründen çalışacak şekilde yazılmıştır.

## Giriş Dosyası

Varsayılan giriş dosyası:

```txt
input/demo_hex.txt
```

Program bu dosyayı iki olası yoldan arar:

- `./input/demo_hex.txt`
- `../input/demo_hex.txt`

Bu sayede exe'yi `bin` altından da çalıştırabilirsin.

## Çıkış Dosyaları

Çıkış adları AES bit uzunluğunu da içerir.

Örnek:

- `aes_256_ecb_encrypted.hex`
- `aes_256_ecb_decrypted.hex`
- `aes_256_gcm_encrypted.hex`
- `aes_256_gcm_decrypted.hex`

Chunk demo açıksa ayrıca seçilen chunk boyuna göre:

- `aes_256_gcm_chunk8_encrypted.txt`
- `aes_256_gcm_chunk8_decrypted.hex`
- `aes_256_gcm_chunk16_encrypted.txt`
- `aes_256_gcm_chunk16_decrypted.hex`
- `aes_256_gcm_chunk32_encrypted.txt`
- `aes_256_gcm_chunk32_decrypted.hex`
- `aes_256_xts_chunk16_encrypted.txt`
- `aes_256_xts_chunk16_decrypted.hex`
- `aes_256_xts_chunk32_encrypted.txt`
- `aes_256_xts_chunk32_decrypted.hex`

Not:

- `encrypted.hex`, `decrypted.hex` ve `chunk*.txt` dosyaları debug ve inceleme amaçlı `hex text` formatındadır
- CAN veya başka binary taşıma katmanına bunların string hali değil, gerçek byte karşılığı gönderilmelidir

## Etkin Modlar

Etkin modlar `micro_aes.h` içindeki makrolara bağlıdır.

Şu anda örnek akışta tipik olarak şu dosyalar üretilir:

- `ECB`
- `CBC`
- `CFB`
- `OFB`
- `CTR`
- `XTS`
- `GCM`

`AES___ == 128` ve ilgili makrolar açıksa şu modlar da eklenebilir:

- `CCM`
- `OCB`
- `EAX`
- `GCM-SIV`
- `SIV`

## Chunk Modülü

Chunk mantığı ayrı modüle taşınmıştır.

Dosyalar:

- `chunk.h`
- `chunk.c`

Makrolar:

```c
#define CHUNK_GCM_DEMO 1
#define CHUNK_GCM_SIZE 8
#define CHUNK_XTS_DEMO 1
#define CHUNK_XTS_SIZE 16
```

Bu makrolar `chunk.h` içindedir.

Anlamları:

- `CHUNK_GCM_DEMO`
  - `1`: chunk demo derlenir ve çalıştırılır
  - `0`: chunk demo tamamen devre dışı kalır
- `CHUNK_GCM_SIZE`
  - yalnızca `8`, `16` veya `32` olabilir
  - plaintext chunk boyunu belirler
- `CHUNK_XTS_DEMO`
  - `1`: XTS chunk demo derlenir ve çalıştırılır
  - `0`: XTS chunk demo devre dışı kalır
- `CHUNK_XTS_SIZE`
  - yalnızca `16` veya `32` olabilir
  - XTS plaintext chunk boyunu belirler

Geçersiz bir değer verilirse derleme aşamasında hata oluşur.

Örnek:

```c
#define CHUNK_GCM_DEMO 1
#define CHUNK_GCM_SIZE 16
#define CHUNK_XTS_DEMO 1
#define CHUNK_XTS_SIZE 32
```

veya derleme anında:

```powershell
gcc -g -DCHUNK_GCM_SIZE=32 -DCHUNK_XTS_SIZE=32 *.c -o .\bin\main_chunk32.exe
```

`main.c` içinde chunk demo doğrudan değil, bu makrolar üzerinden çağrılır.

## Chunk Mantığı

Chunk akışı şu anda `GCM` ve `XTS` için eklenmiştir.

Bu akışta veri:

- sabit boyutlu chunk'lara bölünür
- her chunk bağımsız şifrelenir
- moduna göre her chunk için ayrı nonce veya tweak türetilir
- `GCM` tarafında metadata `AAD` yapılır
- decrypt tarafında yalnızca tek chunk buffer'ı ile çözüm yapılır

Seçilen plaintext chunk boyu mod başına sabittir.

Yani:

- `GCM` için `CHUNK_GCM_SIZE = 8`, `16` veya `32`
- `XTS` için `CHUNK_XTS_SIZE = 16` veya `32`

Giriş boyu seçilen chunk boyunun katı değilse chunk demo çalıştırılmaz.

`XTS` için `8 byte` desteklenmez. Bunun nedeni bu kütüphanedeki `AES_XTS_encrypt/decrypt` fonksiyonlarının en az `16 byte` veri istemesidir.

Bu, hafıza kısıtı olan sistemlerde tüm mesajı bufferlamak yerine parça parça işlem yapma fikrini göstermek içindir.

### Chunk Metadata

Her chunk kaydında şu alanlar kullanılır:

- `message_counter`
- `chunk_index`
- `flags`

Bu alanlar açık olarak kayıtta bulunur. `GCM` akışında aynı zamanda `AAD` olarak doğrulanırlar. `XTS` akışında doğrulama etiketi olmadığı için kayıt bütünlüğü bu katmanda sağlanmaz.

### Chunk Nonce / Tweak

`GCM` tarafında nonce, `XTS` tarafında tweak şu mantıkla üretilir:

- temel `iv` alınır
- `message_counter` eklenir
- `chunk_index` eklenir

Amaç:

- her chunk için farklı değer kullanmak
- `GCM` tarafında aynı `key + nonce` ikilisini tekrar etmemek
- `XTS` tarafında her chunk için farklı tweak üretmek

### Chunk Çıktı Formatı

Encrypted chunk dosyasındaki her satır bir chunk kaydıdır:

```txt
message_counter|chunk_index|flags|ciphertext_hex_or_ciphertext_plus_tag_hex
```

`GCM` için son alan `ciphertext + tag`, `XTS` için yalnızca `ciphertext` taşır.

Örnek olarak `CHUNK_GCM_SIZE = 16` için:

```txt
1|0|0|aabbccddeeff00112233445566778899...
1|1|1|112233445566778899aabbccddeeff00...
```

Burada:

- ilk alan = mesaj sayacı
- ikinci alan = chunk sırası
- üçüncü alan = son chunk bilgisi
- son alan = `GCM` için `ciphertext + tag`, `XTS` için `ciphertext`

Decrypt çıktısında her satır bir plaintext chunk'tır.

Örnek olarak `CHUNK_GCM_SIZE = 16` için:

```txt
00112233445566778899aabbccddeeff
00112233445566778899aabbccddeeff
```

## CAN ile İlişki

Bu modül doğrudan CAN sürücüsü değildir. Ama şu fikri göstermek için hazırlanmıştır:

- tüm mesajı tek parça şifrelemek yerine küçük chunk'lara böl
- her chunk'ı bağımsız doğrula
- alıcı tarafta düşük RAM ile çalış

`CHUNK_GCM_SIZE = 8` olduğunda bu yaklaşım klasik `8-byte CAN payload` fikrine en yakın örnektir. `XTS` tarafında aynı yaklaşım en az `16 byte` chunk ile gösterilebilir.

Önemli fark:

- dosyadaki encrypted çıktı `hex text` formatındadır
- gerçek CAN gönderiminde bunun string hali değil, binary byte karşılığı kullanılmalıdır

Dosya içindeki şu kayıt:

```txt
1|0|0|7051434403051b2a8f156efa57a6a19c
```

CAN hattına bu haliyle gönderilmemelidir. Bu satır yalnızca debug ve inceleme içindir.

Doğru yaklaşım:

- `message_counter|chunk_index|flags|...` metnini doğrudan taşıma
- `|` ayraçlarını taşıma
- hex string karakterlerini taşıma
- kaydı sabit genişlikli binary pakete çevir

Bu repodaki chunk header mantığı zaten `8 byte` olacak şekilde kuruludur:

- `message_counter` = `4 byte`
- `chunk_index` = `2 byte`
- `flags` = `1 byte`
- `reserved` = `1 byte`

Yani header tek başına tam `8 byte` eder.

Örneğin şu kayıt:

```txt
1|0|0|7051434403051b2a8f156efa57a6a19c
```

`XTS chunk16` örneği gibi düşünülürse binary karşılığı şu mantıktadır:

```txt
00 00 00 01 00 00 00 00 70 51 43 44 03 05 1b 2a 8f 15 6e fa 57 a6 a1 9c
```

Burada:

- ilk `8 byte` = header
- sonraki `16 byte` = ciphertext

Toplam `24 byte` eder ve bu veri CAN üzerinde `3` adet `8-byte` frame olarak taşınabilir:

```txt
F0: 00 00 00 01 00 00 00 00
F1: 70 51 43 44 03 05 1b 2a
F2: 8f 15 6e fa 57 a6 a1 9c
```

Benzer şekilde:

- `GCM chunk8` = `8 byte header + 24 byte ciphertext+tag = 32 byte = 4 CAN frame`
- `GCM chunk16` = `8 byte header + 32 byte ciphertext+tag = 40 byte = 5 CAN frame`
- `GCM chunk32` = `8 byte header + 48 byte ciphertext+tag = 56 byte = 7 CAN frame`
- `XTS chunk16` = `8 byte header + 16 byte ciphertext = 24 byte = 3 CAN frame`
- `XTS chunk32` = `8 byte header + 32 byte ciphertext = 40 byte = 5 CAN frame`

Özet:

- dosya satırı formatı = debug amaçlı text gösterim
- CAN taşıması = fixed-width binary header + binary payload
- frame'lere bölme işlemi binary paket üzerinde yapılmalıdır

Örnek:

```txt
078a8bec9a70ca33
```

Bu bir yazı değildir. Gerçek byte karşılığı:

- `0x07`
- `0x8a`
- `0x8b`
- `0xec`
- `0x9a`
- `0x70`
- `0xca`
- `0x33`

CAN frame'lere bölünecek olan da bu byte dizisidir.

## AAD Nedir

`AAD` = `Authenticated Additional Data`

Yani:

- şifrelenmeyen
- ama doğrulanan veri

`GCM` chunk örneğinde:

- `message_counter`
- `chunk_index`
- `flags`

şifrelenmez, ama değiştirilirse doğrulama bozulur.

Bu, taşıma katmanı metadata'sını korumak için önemlidir.

## Terimler

Bu repo içinde sık geçen bazı terimler:

- `plaintext`
  Şifrelenmeden önceki gerçek veridir.

- `ciphertext`
  Şifreleme sonrası oluşan veridir.

- `decrypt`
  Şifreli veriyi tekrar çözüp plaintext'e dönüştürme işlemidir.

- `chunk`
  Büyük verinin sabit boyutlu küçük parçalara bölünmüş halidir. Bu repoda `GCM` için `8`, `16` veya `32`, `XTS` için `16` veya `32` byte olabilir.

- `chunk_index`
  Chunk'ın kaçıncı parça olduğunu gösteren sıra numarasıdır.

- `message_counter`
  Aynı mesaj ailesi veya akış içindeki mantıksal mesaj numarasıdır. Nonce veya tweak türetirken tekrar kullanım riskini azaltmak için kullanılır.

- `IV`
  `Initialization Vector` ifadesinin kısaltmasıdır. Bazı modlarda şifreleme başlangıç değeri olarak kullanılır.

- `nonce`
  Tekrar kullanılmaması gereken, mod başına benzersiz değer anlamına gelir. Bu repoda `GCM` chunk akışında `iv + message_counter + chunk_index` mantığıyla türetilir.

- `AAD`
  Şifrelenmeyen ama doğrulanan ek veridir. Bu repoda `GCM` chunk akışında `message_counter`, `chunk_index` ve `flags` gibi metadata alanları için kullanılır.

- `tag`
  AEAD modlarında üretilen doğrulama verisidir. `GCM` tarafında `ciphertext` ile birlikte taşınır. Decrypt sırasında veri veya metadata değişmişse doğrulama başarısız olur.

- `tweak`
  Özellikle `XTS` gibi modlarda her veri birimi için değişen ek parametredir. `XTS` tarafında nonce yerine tweak kullanılır.

- `AEAD`
  `Authenticated Encryption with Associated Data` anlamına gelir. Hem gizlilik hem de bütünlük sağlar. `GCM` bu sınıfa girer; `XTS` girmez.

- `binary`
  Verinin yazı olarak değil, gerçek byte dizisi olarak tutulması veya taşınmasıdır. CAN hattında gönderilmesi gereken şey genelde hex string değil, binary byte karşılığıdır.

- `hex text`
  Byte verinin okunabilir metin gösterimidir. Örneğin `0x8a` byte'ı dosyada `8a` olarak yazılır. Bu repo debug amaçlı çıktılarını çoğunlukla hex text olarak üretir.

## Güvenlik Notları

- `ECB` gerçek sistemlerde önerilmez
- `CTR` tek başına bütünlük sağlamaz
- düşük hafızalı sistemlerde mümkünse `AEAD` modları tercih edilmelidir
- `GCM/CCM/EAX/OCB/SIV` gibi modlar gizlilik yanında doğrulama da sağlar
- aynı `key + nonce` birleşimi tekrar kullanılmamalıdır
- decrypt başarısızsa plaintext işlenmemelidir

`GCM` gizlilik + doğrulama sağlar. `XTS` ise blok veriyi tweak ile şifrelemek için uygundur ama kendi başına `AAD/tag` sağlamaz.

## Mevcut Sınırlar

- giriş dosyası `raw binary` değil, `hex text`tir
- çıktı dosyaları debug amaçlı yine `hex text`tir
- `outputs/` klasörü kod tarafından oluşturulmaz
- chunk demo şu an `GCM` ve `XTS` için eklenmiştir
- chunk kayıt formatı dosya tabanlıdır, doğrudan CAN frame formatı değildir

## Geliştirme İçin Sonraki Mantıklı Adımlar

- raw binary input desteği eklemek
- raw binary encrypted output üretmek
- doğrudan `tx_chunk()` / `rx_chunk()` API'si tanımlamak
- chunk header'ı gerçek CAN frame formatına dönüştürmek
- replay koruması için `message_counter` yönetimi eklemek
- chunk timeout / sıra kontrolü / eksik frame kontrolü eklemek

## Özet

Bu repo şu anda üç katman gösteriyor:

- temel `µAES` kütüphanesi
- dosyadan hex veri okuyup mod bazlı şifreleme yapan demo
- `GCM` ve `XTS` için makroya bağlı chunk fikrini gösteren ayrı modül

Eğer hedefin CAN üzerinde küçük parçalarla güvenli veri taşımaksa, bu repo şu anda başlangıç için uygun bir deney alanıdır; ama üretim kullanımından önce:

- gerçek binary taşıma
- net frame formatı
- nonce yönetimi
- hata ve replay koruması

katmanlarının ayrıca tasarlanması gerekir.
