<div align="center">

# Codex Worker Orchestrator

**Nền tảng điều phối nhiều AI worker trên máy cục bộ, chú trọng ranh giới quyền hạn và bảo mật.**

*Codex điều phối · Worker tư vấn · Người dùng phê duyệt*

[English](../README.md) · **Tiếng Việt**

</div>

> [!IMPORTANT]
> Đây là dự án đang phát triển, **chưa phải ứng dụng hoàn chỉnh dành cho người dùng phổ thông**. Endpoint gọi nhiều API **mặc định từ chối** nếu chưa có cơ chế USER phê duyệt độc lập đã được kiểm chứng.

## Ý tưởng

Hệ thống tách rõ trách nhiệm:

- **USER:** giữ quyền quyết định cuối cùng và phê duyệt việc gửi dữ liệu hoặc thay đổi dự án.
- **Codex:** AI điều phối duy nhất, giao việc, so sánh và tổng hợp kết quả.
- **HTTP Broker / Provider Registry:** hạ tầng xác định, xác thực, kiểm tra cấu hình và chuyển tiếp yêu cầu.
- **Antigravity CLI và nhiều API/model:** worker ngang hàng, chỉ đưa ra phân tích/tư vấn.
- **Controlled Execution Broker (CEB):** thành phần dự kiến trong tương lai, **chưa triển khai**.

## Thành phần đã có

| Chức năng | Tình trạng |
|---|---|
| Provider Registry và cấu hình nhiều API/model | Đã xây dựng |
| Adapter Antigravity CLI | Có mã và kiểm thử mock |
| Adapter OpenAI-compatible | Có mã và kiểm thử mock |
| Gọi nhiều worker song song có giới hạn | Đã triển khai trong Registry |
| Nạp cấu hình runtime từ JSON | Đã triển khai |
| HTTP `/health`, `/v1/analyze` | Đã triển khai, có kiểm thử tương thích |
| HTTP `/v1/analyze/batch` | Có xác thực nhưng **chưa cấp phép dispatch thật** |
| Approval Core kiểm tra chữ ký | Đã xây dựng độc lập, chưa nối vào HTTP |
| Windows Approval Agent / IPC an toàn | Chưa triển khai |
| CEB và giao diện thân thiện | Định hướng phát triển |

**Kết quả cuối cùng được báo cáo từ máy phát triển:** 76/76 kiểm thử PASS (13/10/2026). Các bài kiểm thử dùng mock, không chứng minh API hoặc AGY thật đã được kiểm tra đầy đủ.

## Chạy kiểm thử

Cần Node.js LTS và PowerShell trên Windows:

```powershell
cd C:\dev\orchestrator
node --test
```

Khởi động Broker:

```powershell
.\broker\start-broker.ps1
```

Kiểm tra ở một cửa sổ PowerShell khác:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

## Cấu hình nhiều provider

Xem [`broker/config/providers.json`](../broker/config/providers.json) và [`broker/config/providers.example.json`](../broker/config/providers.example.json). Mỗi provider có danh sách model được phép, endpoint HTTPS định trước và tên biến môi trường chứa API key.

Không lưu API key trong Git, JSON, ảnh chụp màn hình hay log. Đừng công khai cổng HTTP Broker ra mạng Internet.

## Đồng bộ GitHub tiện lợi

Sau khi cấu hình remote `origin`, mỗi lần phát triển:

```powershell
# Chỉ thêm đúng file đã xem xét
git add broker/providers/approval-core.js broker/test/approval-core.test.js

# Kiểm thử, commit rồi push
.\scripts\sync.ps1 -Message "feat: update approval core"
```

Nếu đã có commit và chỉ muốn push:

```powershell
.\scripts\sync.ps1
```

Nếu sửa từ thiết bị khác, trước khi bắt đầu việc mới chạy `git pull --ff-only`.

## Nguyên tắc bảo mật

- Codex không được tự phê duyệt dữ liệu gửi ra API ngoài.
- Token xác thực HTTP khác với sự đồng ý của USER.
- Worker không có quyền ghi file, điều phối lẫn nhau hoặc đổi chính sách.
- Approval Core hiện chỉ chống sử dụng lại grant **trong một tiến trình**, chưa chứng minh chống replay trên nhiều tiến trình hoặc qua sự cố hệ thống.
- Endpoint batch mặc định từ chối cho tới khi có kênh USER Approval riêng và đáng tin cậy.

Đọc thêm [SECURITY.md](../SECURITY.md) và [CONTRIBUTING.md](../CONTRIBUTING.md).

## Định hướng

Hệ thống sẽ tiếp tục được mở rộng thành sản phẩm dễ cài đặt và sử dụng hơn: cấu hình nhiều API/model, giao diện Windows/web, phê duyệt độc lập, kiểm soát chi phí và khả năng đóng góp cộng đồng. Những chức năng này là **kế hoạch**, chưa phải tính năng đã phát hành.

**Giấy phép:** chưa chọn. Cần bổ sung giấy phép nguồn mở trước khi cho phép cộng đồng tái sử dụng hoặc phân phối.

<sub>Dự án cộng đồng độc lập, không phải bản phát hành chính thức của OpenAI, Codex hoặc Antigravity.</sub>
