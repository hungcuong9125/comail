# Comail public website

Website tĩnh tiếng Việt để duyệt thiết kế trước khi triển khai. HTML/CSS/JavaScript thuần; không cần Node, build frontend, cơ sở dữ liệu hay đăng nhập. Skill Impeccable được đọc tham khảo trực tiếp, không cài đặt và không chạy launcher có thể tải binary.

## Xem trước

```sh
cd upstreams/comail-website
python3 -m http.server 8088 --directory site
# http://localhost:8088
```

Hoặc mở `site/index.html` trực tiếp; các trang dùng đường dẫn tương đối. Docker/Nginx là môi trường cần dùng để kiểm tra headers, redirect và HTTP 404.

```sh
docker compose up -d --build
# http://localhost:8088
docker compose down
```

Nếu container duyệt `comail-site-review` đang dùng cổng 8088, dừng container đó trước khi chạy Compose: `docker stop comail-site-review`.

## Các trang

- `/`: giới thiệu, hộp thư demo có tab, tính năng, quyền riêng tư, FAQ.
- `/privacy-policy/`: dữ liệu, OAuth, Limited Use, AI/MCP, bên thứ ba, lưu trữ, thu hồi quyền và xóa.
- `/terms-of-service/`: điều khoản sử dụng, AI/tự động hóa, giấy phép và giới hạn trách nhiệm.
- `/support/`: hướng dẫn kết nối, xóa dữ liệu và liên hệ.
- `/healthz`: health check; đường dẫn không có thật trả HTTP 404.

URL không có dấu `/` cuối được Nginx chuyển đến thư mục tương ứng; nội dung chính sách không bao giờ fallback về trang chủ. Mọi nội dung pháp lý có sẵn trong HTML khi tắt JavaScript. Font Be Vietnam Pro tự lưu trữ, giấy phép trong `site/assets/OFL.txt`. Không tải CDN, analytics hay font bên ngoài khi mở website.

## Dokploy

Khuyến nghị tạo Application mới, không thay cấu hình desktop app:

1. Kết nối repository/branch đã chứa thư mục website này. Thư mục mới hiện cần được commit/push trước khi Dokploy lấy được.
2. Chọn Dockerfile build. **Build context/path**: `upstreams/comail-website`. **Dockerfile**: `Dockerfile` tương đối với context đó. Nếu UI yêu cầu đường dẫn từ repo root, chọn `upstreams/comail-website/Dockerfile` và vẫn giữ context là thư mục website.
3. Container port: **8080**. Website không cần biến môi trường hay volume.
4. Gắn domain `comail.hungcuong.dev`, path `/`, container port `8080`; bật HTTPS và chuyển HTTP sang HTTPS ở Dokploy/Traefik.
5. Trỏ DNS A/AAAA đến máy chủ đúng. Xóa bản ghi AAAA sai nếu chưa cấu hình IPv6. Không bật Basic Auth, OAuth proxy hoặc bot challenge cho website.
6. Deploy; kiểm tra `/healthz`, `/`, `/privacy-policy`, `/terms-of-service`, `/support` từ trình duyệt ẩn danh và mạng ngoài.

Compose đi kèm dùng port localhost 8088 cho duyệt trên máy. Nếu dùng Dokploy Compose, cấu hình domain trỏ service `website`, port 8080, theo network routing của Dokploy; không cần công khai host port 8088.

Nginx chạy non-root, tắt access log, có CSP và các security headers. Log tại reverse proxy/hosting là lớp riêng: cần xác định retention thực tế trước khi công bố chính sách. Base image dùng tag stable-alpine; pin digest trong quy trình phát hành nếu cần build tái lập.

## Checklist trước khi gửi Google

- [ ] Xác nhận tên thương hiệu chính xác là **Comail** trên website và OAuth consent screen.
- [ ] Xác nhận đơn vị vận hành đang ghi là **Hùng Cường**. Bổ sung tên pháp lý/địa chỉ nếu pháp luật áp dụng yêu cầu.
- [ ] **Bổ sung email hỗ trợ/bảo mật do bạn kiểm soát** ở trang support và privacy; hiện dùng hồ sơ GitHub và repo fork từ git remote, chưa xác nhận Issues của fork có được bật. Không dùng email hỗ trợ upstream để đại diện cho chủ tên miền.
- [ ] Duyệt chính sách theo bản app thực tế: scopes, AI provider, MCP, ảnh người gửi, dữ liệu cục bộ và thời hạn log hạ tầng. Cam kết không huấn luyện AI tổng quát cần được bảo đảm cả với provider đã bật; website không thể cưỡng chế điều này trong ứng dụng.
- [ ] Thêm ngày hiệu lực chính thức khi phê duyệt nội dung (hiện là phiên bản 1.0). Đây là bản nội dung để duyệt, không thay thế tư vấn pháp lý.
- [ ] Homepage `https://comail.hungcuong.dev/` và Privacy Policy `https://comail.hungcuong.dev/privacy-policy/` mở công khai qua HTTPS, nội dung khác nhau; dùng URL cuối sau redirect trong consent screen.
- [ ] Thêm `hungcuong.dev` vào Authorized domains trong Google Auth Platform; cấu hình homepage/privacy/terms tương ứng. Không thay redirect URI desktop OAuth theo URL website nếu chưa kiểm tra luồng OAuth.
- [ ] Xác minh quyền sở hữu **hungcuong.dev** bằng Google Search Console Domain property và DNS TXT. Dùng tài khoản phù hợp với dự án OAuth; liên kết/quyền owner cần khớp hướng dẫn Google.
- [ ] Theo thông báo Google, đợi ít nhất **24 giờ sau khi xác minh** rồi gửi kiểm tra lại.
- [ ] Kiểm tra màn hình consent, scopes thực tế và video hướng dẫn nếu Google yêu cầu. Scope `https://mail.google.com/` là quyền rộng/restricted; có thể cần xác minh hoặc đánh giá bổ sung tùy cách xử lý dữ liệu.

Website giải quyết phần nội dung và khả năng phục vụ công khai khi được triển khai đúng. Không bảo đảm Google phê duyệt; DNS, SSL, quyền sở hữu và trạng thái OAuth nằm ngoài mã HTML này.

## Căn cứ nội dung

Đã đối chiếu README dự án, OAuth providers/tokens, luồng remove_account và xử lý avatars. Tính năng AI, MCP và phạm vi đa nền tảng dựa trên README. Không tuyên bố dữ liệu không bao giờ rời thiết bị, toàn bộ database mã hóa hoặc OAuth đã được Google duyệt. Các tên và thư trong demo là dữ liệu minh họa; không phải ảnh chụp ứng dụng thật. Liên kết tải xuống upstream được ghi rõ không nhất thiết tương ứng bản OAuth của tên miền này.

## Thiết kế và chỉnh sửa

- `site/index.html`: landing page.
- `site/assets/style.css`: màu, font, bố cục responsive, motion và reduced-motion.
- `site/assets/main.js`: tab demo có keyboard navigation; reveal không làm ẩn nội dung khi JS tắt.
- Ba thư mục legal/support chứa HTML độc lập. Header/footer lặp có chủ đích để không cần runtime/template engine; khi sửa navigation hãy đồng bộ các trang.
- `preview/`: ảnh desktop/mobile để duyệt, không copy vào Docker image.

Không thay đổi mã desktop app, tài liệu có sẵn hay `upstreams/releases-comm-central`.
