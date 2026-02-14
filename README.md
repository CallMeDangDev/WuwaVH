# WuWa Việt Hóa

Bản Việt hóa cho **Wuthering Waves**.

---

## Hướng dẫn cài đặt

### 1. Tải file

Vào trang [**Releases**](../../releases) và tải về các file sau:

| File | Mô tả |
|------|--------|
| `WuWaVH_99_P.pak` | File Việt hóa chính |
| `VongXuyen_100_P.pak` | Font tiếng Việt |
| `version.dll` | Loader tự động mount bản dịch |
| `antiCheatOffForSteam_99_P.pak` | Tắt anti-cheat cho bản Steam *(tùy chọn nếu dùng ver Steam)* |

### 2. Cài đặt

**Bước 1** — Copy các file `.pak` vào thư mục:

```
{Thư mục game}\Client\Binaries\Win64\wuwaVietHoa\
```

> Nếu chưa có thư mục `wuwaVietHoa`, hãy tạo mới.

**Bước 2** — Copy `version.dll` vào cùng thư mục với file `.exe` của game:

```
{Thư mục game}\Client\Binaries\Win64\
```

### Cấu trúc sau khi cài

```
Client\Binaries\Win64\
├── version.dll
├── Client-Win64-Shipping.exe
└── wuwaVietHoa\
    ├── WuWaVH_99_P.pak
    ├── VongXuyen_100_P.pak
    └── antiCheatOffForSteam_99_P.pak   ← tùy chọn
```

### 3. Gỡ cài đặt

Xóa file `version.dll` và thư mục `wuwaVietHoa` là xong.

---

## Ghi chú

- Bản Việt hóa hoạt động bằng cách mount thêm file `.pak` qua `version.dll` proxy — **không** chỉnh sửa file gốc của game.
- Sau mỗi bản cập nhật game, có thể cần tải lại file Việt hóa mới từ Releases.

## Credits

- **[Lai-Hoang](https://github.com/Lai-Hoang)** — Cảm ơn bạn và repo [wuwa-viet-hoa](https://github.com/Lai-Hoang/wuwa-viet-hoa) cho code injector method và `antiCheatOffForSteam_99_P.pak`.

## License

[MIT](LICENSE)
