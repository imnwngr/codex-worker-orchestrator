# Báo cáo kỹ thuật Phase 15

Ngày rà soát: 11/11/2026. Đây là bản phát triển chưa ký, chưa commit và chưa phát hành.

## 1. Executive Summary

**Kết quả tổng thể: PARTIAL.** Đã triển khai Windows GUI Agent, cầu nối xác thực,
bộ thực thi có hậu điều kiện, kiểm thử, evidence và công cụ provenance. Build và
các bộ kiểm tra không cần desktop tương tác đã được xác minh. Luồng thao tác
desktop thật chưa được xác minh trong môi trường hiện tại.

Repository gốc ở nhánh `main`, HEAD `662a864f03adabd09ede33ba1bbad20a2e83faf3`,
tree `cd0bc0f78cd6025cc7193b064d2832ec38777c57`, sạch khi reconnaissance. Do giới hạn
ghi của sandbox, triển khai và kiểm thử dùng bản sao `orchestrator-phase15` dưới
thư mục người dùng, cùng HEAD. Patch về bản gốc phải qua kiểm tra HEAD, index và
quyền ghi của nền tảng. Vị trí staging cuối được ghi trong `commit-review.json`
ngoài source. Không có commit mới, push, tag, release hoặc CommittedRelease.

Probe trực tiếp ghi nhận `CodexSandboxDesktop-*`, `inputDesktop=false`. Agent từ
chối desktop này. Không dùng quyền chạy build/test để suy diễn quyền điều khiển
desktop khác. Không có ảnh GUI mới được dùng làm bằng chứng PASS.

## 2. Architecture

Luồng triển khai:

```text
Codex / local synthetic runner
  -> ExecutionEngine: kế hoạch, hậu điều kiện, lịch sử, retry quan sát
  -> ControlledDesktopBroker: schema, task scope, quyết định audit
  -> DesktopBridge: kiểm tra binary pins, inherited pipes + HMAC-SHA256
  -> DesktopAgent.Core: policy, session, reservation chống lặp, evidence
  -> DesktopAgent.Windows: Win32 + UI Automation trong desktop hiện tại
  -> observation/PNG + SHA-256 -> kiểm tra evidence -> kiểm tra trạng thái
```

`POST /v1/desktop/execute` là điểm tích hợp tùy chọn của broker hiện hữu. Cần token
riêng và controller được cấu hình rõ phạm vi; entry point production không cài
controller này. ProviderRegistry, advisory workers, approval core và WPF/browser
hiện hữu giữ vai trò cũ. Mock approval không trở thành quyền thực thi production.

Chi tiết schema, lỗi, timeout và cancellation: [PROTOCOL.md](../desktop-agent/PROTOCOL.md).
Hướng dẫn cài đặt, chạy và xử lý lỗi: [README](../desktop-agent/README.md).

## 3. Implementation

| Thành phần | Năng lực | Mức xác minh |
| --- | --- | --- |
| Agent Windows | Session/station/desktop, cửa sổ/dialog theo PID đã pin, UIA/focus, screenshot, input và file dialog có allowlist | IMPLEMENTED; build VERIFIED; GUI thực tế BLOCKED |
| Core | Schema chặt, HMAC, DEFAULT_DENY, session mismatch, timeout, chống lặp bền vững, log/evidence | VERIFIED bằng 39 bài fake backend và IPC từ chối thực tế |
| Bridge/controller | Authenticated pipes, request/task/correlation/worker binding, watchdog, cancellation, evidence integrity, HTTP seam mặc định khóa | VERIFIED qua harness; production consent chưa có |
| ExecutionEngine | Plan/act/observe/verify/recover, tái lấy target, hậu điều kiện duy nhất, retry giới hạn, không tự phát lại input | VERIFIED bằng harness |
| Phase 14 drivers | A11Y01 và A11Y05 Edge/Firefox với dữ liệu mới; kiểm tra request/context và artifact riêng | IMPLEMENTED; real GUI BLOCKED |
| Provenance | Manifest, source inventory, môi trường build, SHA-256 payload, hai build với intermediate độc lập | VERIFIED cùng máy; package-to-commit và cross-host chưa xác minh |

Chỉ có bảy action: heartbeat, observe, capture, focus, key, click, setFile. Không
có shell/script/URL hoặc nhập text tùy ý. Window token hết hạn sau ba giây; PID,
process start ticks, executable hash và UIA runtime ID được kiểm tra lại.

Mỗi acquisition có tối đa năm lần thử; mỗi bước có tối đa năm lần polling hậu
điều kiện. Chỉ retry quan sát. Lỗi sau input, mất kết nối/xác thực, cancellation
hoặc mất evidence có thể tạo `UNKNOWN`; không phát lại thao tác. Claim của command
và task được ghi trước hành động. Sau crash cần kiểm tra trạng thái trước khi tạo
task mới; không xóa claim để ép chạy lại.

Screenshot sử dụng PrintWindow và kiểm tra vùng client, tránh chấp nhận ảnh chỉ
có viền cửa sổ. Đây là heuristic phát hiện ảnh trống, chưa chứng minh chất lượng
render WPF hoặc focus indicator. File-dialog screenshot bị từ chối; UIA của dialog
chỉ giữ control IDs được phép và che tên. Không chụp toàn desktop có cửa sổ cá nhân.

Danh sách đầy đủ file được chuẩn bị cho commit nằm trong
[PHASE_15_CHANGED_FILES.txt](PHASE_15_CHANGED_FILES.txt). Không sửa mã WPF hoặc
browser production hiện hữu. Ba file hiện hữu thay đổi là CI, `.gitignore` và
điểm gắn route trong `broker/broker.js`; phần còn lại là module/test/tài liệu mới.

## 4. Dependencies

Không thêm package NuGet/npm hoặc tải driver trong giai đoạn này. Dùng SDK/runtime
đã có: .NET SDK **8.0.425**, Windows Desktop runtime **8.0.31**, Node **24.19.0**,
PowerShell **7.5.4**, Git **2.55.0.windows.5**; Windows **10.0.22631 x64**.

Agent dùng Win32/UI Automation/WPF của Microsoft, Node built-ins và console test
harness không cần test package. Không có lockfile mới hoặc thay đổi dependency của
ứng dụng cũ. Phiên bản cài sẵn được ghi nhận; không tuyên bố đã xác minh chữ ký hay
nguồn cài đặt ban đầu của runtime. EdgeDriver/geckodriver chỉ cần khi mở được môi
trường GUI phù hợp; nguồn chính thức và yêu cầu pin hash nằm trong hướng dẫn.

## 5. Verification

| Kiểm tra | Kết quả thực tế | Phạm vi |
| --- | --- | --- |
| Node toàn repository | 267/267 đạt, 0 skip | Mock/unit/HTTP integration; bản cuối chạy `--test-isolation=none` |
| Desktop Core | 39/39 đạt | Fake backend; schema/auth/policy/timeout/replay/evidence |
| Approval Agent regression | 151/151 đạt | Model/view-model và interoperability, không phải WPF GUI |
| WebAuthn fake lab | 60/60 đạt | Fake-only; không gọi credential thật |
| Offline assurance | 197 đạt, 0 lỗi | Structural/synthetic fixtures |
| Release-tool regression | 56/56 đạt | Disposable fixtures; không chạy CommittedRelease |
| Fresh demo | Đạt headless interoperability/replay/DEFAULT_DENY | Không phải A11Y05 thực tế |
| Build agent, fixture, WPF | Đạt, 0 warning/error trong log giữ lại | Release development build |
| Agent process IPC | HMAC, DEFAULT_DENY, session mismatch, shutdown, audit hash đạt | Denial-only; không gửi GUI input |
| GUI fixture / A11Y01 / A11Y05 | BLOCKED | Chưa có input desktop được phép từ sandbox |

Các lỗi an ninh được kiểm tra gồm command lạ, JSON trùng/thừa thuộc tính, sai MAC,
sai correlation, target token không hợp lệ, desktop/session sai, stale target,
timeout/cancel, disconnect, giới hạn retry, trùng execution, sửa evidence và package.
Mô phỏng stale target/screenshot failure không chứng minh Win32 hoạt động thật.

Lần chạy Node dùng subprocess trong sandbox gặp `spawn EPERM`. Đã chuyển runner
sang chế độ cùng tiến trình để chạy nguyên bộ test mà không nới quyền desktop.
Log lỗi môi trường được ghi nhận riêng với kết quả thực thi lại. Các bài kiểm tra
phát hiện và bảo vệ sửa lỗi mới về UNKNOWN, capture evidence và file dialog;
không hạ tiêu chuẩn để tạo PASS.

Log/checksum trước đó ở `%TEMP%/phase15-final-verification-20261111`; 12 checksum
đã kiểm tra khớp. Log Node cuối, desktop probe, bản diff và biên bản privacy ở
`%TEMP%/phase15-review-20261111`. Manifest/build logs/payload của lần đóng gói cuối
ở `%TEMP%/phase15-package-final-20261111`. Báo cáo ngoài source chứa hash chính xác
để tránh vòng tự tham chiếu giữa report và source inventory.

CI đã bổ sung build Windows, core tests và IPC denial-only. Chưa chạy remote CI;
không tuyên bố kết quả GitHub Actions mới. Không dùng external AI/API để review.

## 6. Phase 14 Status và provenance

[Ma trận acceptance](PHASE_15_ACCEPTANCE.md) phân biệt lịch sử và quan sát mới.
Không tìm thấy report/package Phase 14 có thể kiểm tra lại trong các thư mục
evidence hiện còn đọc được. Không suy diễn trạng thái lịch sử từ file name hoặc
model test. A11Y01/A11Y05 chưa có PASS GUI mới; GUI13 và A11Y02–A11Y04 vẫn BLOCKED.
Hạ tầng chung đã có, nhưng hành vi phụ thuộc cấu hình của nhóm sau chưa được tự
động hóa đầy đủ.

Hai build development dùng intermediate directories độc lập so sánh toàn bộ 17
payload files. Source manifest gồm HEAD/tree và hash raw working files, kể cả
source mới chưa commit. `dirty=true` có nghĩa package được tạo từ working tree;
không có nghĩa binary tương đương nguyên commit HEAD. Cần phân biệt:

1. Source identity: raw-file inventory tại thời điểm build.
2. Binary reproducibility: hai build cùng máy cho payload giống nhau.
3. Package provenance: hash manifest/payload cần được giữ và review độc lập;
   hash không chứng thực publisher hay approval.

Exact Phase 14 package-to-commit equivalence và cross-host reproducibility vẫn
NOT_VERIFIED. Không thay thế pin lịch sử bằng pin tự tạo để kết luận tương đương.

## 7. Security Review

Production giữ DEFAULT_DENY / NO_GO. Không gọi provider thật, đọc credential,
thay đổi policy production, cấu hình Windows, lịch sử Git hoặc tài khoản ngoài.
Auth token HTTP độc lập với API keys. Session key HMAC 256 bit được tạo trong RAM,
truyền bằng inherited pipe, xóa khi đóng; không ghi argv/env/config/log.

Controller kiểm tra scope và audit trước dispatch. Agent kiểm tra desktop/process/
control. Audit ghi identity, action, timing, decision và evidence reference;
thông báo lỗi dùng mã cố định, không đẩy raw exception ra log chia sẻ. Password
controls bị che, screenshot có password bị chặn. Synthetic scope giới hạn nội
dung có thể xuất hiện trong ảnh; chưa có bộ che mọi loại dữ liệu nhạy cảm.

Không chống được malware cùng quyền user, controller/runtime đã bị xâm phạm,
UIA provider đối nghịch hoặc mọi TOCTOU race. Bootstrap scope là quyết định của
trusted launcher; chưa là bằng chứng human consent. Hash chain cần tail hash giữ
ngoài evidence để phát hiện viết lại/cắt đuôi. HTTP từ chối trước controller chưa
có persistent audit riêng; chỉ những request đã vào controller/agent được lưu.

Rà soát staging chỉ đưa source/test/tài liệu vào commit; loại binary, log thô,
ảnh, profile browser, session key, file local policy. Pattern scan và đọc diff
không phải bằng chứng tuyệt đối rằng không thể có lỗi hay secret.

## 8. Known Limitations

Real desktop workflow, Win32 screenshots/UIA/input và actual browser/WPF roundtrip
chưa được xác minh. Cần Windows account/VM test riêng, WinSta0/Default đang mở khóa,
manifest pin đã review và driver phù hợp. Không được chuyển khỏi sandbox để ép
chạy test. A11Y01 vẫn cần người review focus indicator trong ảnh đúng phiên.

Không có production installer/service, signed distribution, protected consent,
autonomous LLM planner hay điều khiển desktop tổng quát. ExecutionEngine chạy plan
có schema/hậu điều kiện do caller chuẩn bị. Native UIA/PrintWindow bị treo được
watchdog kết thúc cả agent; không giả định native calls tự hủy hợp tác.

Các đường dẫn, HWND/UIA selector, phiên bản Windows/browser và foreground races
cần kiểm tra tại môi trường đích. Browser drivers chưa được cài; cấu hình cá nhân
không thay đổi. Build manifest mô tả raw files của bản sao dùng để test. Khi áp
dụng patch sang checkout khác, Git có thể đổi LF/CRLF; staged Git content tương
đương không tự chứng minh raw-file hash hay binary tương đương.

## 9. Commit Proposal

Đề xuất một commit:

```text
feat(desktop): add scoped Windows GUI agent and verifiable execution harness
```

Phạm vi là toàn bộ file trong inventory kèm theo. Biên bản staging ngoài source
gồm `git diff --cached`, thống kê, tên file, checksum patch, privacy scan và kết
quả `git diff --cached --check`. Index phải khớp working tree; không chứa evidence
cá nhân hoặc thay đổi ngoài phạm vi. Log full test và manifest được giữ ngoài Git.

**Chờ USER phê duyệt commit.** Không suy diễn phê duyệt từ im lặng. Chưa commit,
push, tag, phát hành, chạy CommittedRelease hoặc thay đổi production. Khi chuyển
patch về repository gốc cần giữ nguyên mọi thay đổi mới của người dùng và tuân thủ
quyền ghi của nền tảng.
