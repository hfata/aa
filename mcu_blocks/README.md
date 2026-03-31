# MCU Blocks

Bu klasör, ana demo akışından bağımsız olarak MCU içine gömülebilecek encrypt/decrypt bloklarını içerir.

Amaç:

- CAN üzerinden gelecek fixed-width binary packet'i almak
- bunu `GCM` veya `XTS` için çözmek
- plaintext'i byte veya hex olarak elde etmek
- aynı metadata ve plaintext ile tekrar binary packet üretmek

Bu klasörde dosya okuma/yazma yoktur. Kod doğrudan byte buffer üzerinden çalışır.

## Dosyalar

- `packet_codec.h`
- `packet_codec.c`
- `example_xts.c`

## Paket Formatı

Bu klasörde kullanılan paket formatı:

- `8 byte header`
- `payload`

Header yerleşimi:

- `message_counter` = `4 byte`
- `chunk_index` = `2 byte`
- `flags` = `1 byte`
- `reserved` = `1 byte`

Yani header her zaman tam `8 byte` eder.

Örnek `XTS chunk16` packet'i:

```txt
00000001000000007051434403051b2a8f156efa57a6a19c
```

Burada:

- ilk `8 byte` = `0000000100000000`
- sonraki `16 byte` = ciphertext

Bu packet, eski debug gösterimindeki şu satırın binary karşılığıdır:

```txt
1|0|0|7051434403051b2a8f156efa57a6a19c
```

MCU tarafında kullanılacak olan şey text satır değil, binary packet'tir.

## Sunulan Fonksiyonlar

Yardımcılar:

- `mcu_hex_bytes_len(...)`
- `mcu_hex_to_bytes(...)`
- `mcu_bytes_to_hex(...)`
- `mcu_build_packet_header(...)`
- `mcu_parse_packet_header(...)`
- `mcu_pack_chunk(...)`
- `mcu_unpack_chunk(...)`

`GCM`:

- `mcu_gcm_encrypt_packet(...)`
- `mcu_gcm_decrypt_packet(...)`

`XTS`:

- `mcu_xts_encrypt_packet(...)`
- `mcu_xts_decrypt_packet(...)`

Not:

- `GCM` fonksiyonları normal AES anahtarı kullanır
- `XTS` fonksiyonları `2 * keysize` uzunluğunda key pair ister

## XTS Örneği

Bu binary packet:

```txt
00000001000000007051434403051b2a8f156efa57a6a19c
```

şu plaintext'e çözülür:

```txt
00112233445566778899aabbccddeeff
```

Bu dönüşüm `example_xts.c` içinde gösterilir.

## Derleme

Repo kökünden örnek derleme:

```powershell
gcc -g -I. .\mcu_blocks\packet_codec.c .\mcu_blocks\example_xts.c .\micro_aes.c -o .\bin\mcu_xts_example.exe
```

Çalıştırma:

```powershell
.\bin\mcu_xts_example.exe
```

Beklenen çıktı:

```txt
packet in : 00000001000000007051434403051b2a8f156efa57a6a19c
plaintext : 00112233445566778899aabbccddeeff
packet out: 00000001000000007051434403051b2a8f156efa57a6a19c
match     : yes
```

## Notlar

- `XTS` için desteklenen chunk boyları `16` ve `32` byte
- `GCM` için desteklenen chunk boyları `8`, `16` ve `32` byte
- Bu modül binary packet ile çalışır
- CAN frame'lere bölme işlemi bu packet üzerinde yapılmalıdır
