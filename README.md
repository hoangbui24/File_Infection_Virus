# File_Infection_Virus
- Viết chương trình lây nhiễm virus vào tập tin thực thi (tập tin thực thi trên Windows 
  – PE file 32 bits) có tính năng đơn giản (mục đích demo giáo dục) như yêu cầu bên 
dưới.
- Về chức năng, mục đích:
  - Hiển thị thông điệp ra màn hình thông qua cửa sổ “pop-up” với tiêu đề cửa sổ là 
“Infection by NT230” và cấu trúc thông điệp là “MSSV01_MSSV02_MSSV03” 
(thông tin MSSV của các thành viên trong nhóm). Lưu ý: không có dấu “”.
  - Hoàn trả chức năng gốc ban đầu của chương trình bị lây nhiễm (không phá hủy 
chức năng của chương trình vật chủ).
  - Tóm lại: một tập tin bị nhiễm virus sẽ in ra thông điệp khi người dùng kích hoạt 
chương trình, cố gắng lây nhiễm sang tập tin khác trong cùng thư mục, rồi thực 
thi chức năng ban đầu của tập tin. Đối với việc lây nhiễm sang một tập tin khác, 
nếu đối tượng là một tập tin đã bị nhiễm, chương trình virus sẽ bỏ qua. Nếu đối tượng là tập tin không bị nhiễm, hoạt động lây nhiễm payload vào tập tin thực thi 
sẽ được kích hoạt.
- Về cách lây nhiễm:
  - Mức yêu cầu 01 - RQ01 (3đ): Thực hiện chèn mã độc vào process bình thường bằng 
kỹ thuật process hollowing hoặc sử dụng section .reloc trong tập tin thực thi để 
tiêm payload của virus.
  - Mức yêu cầu 02 - RQ02 (2đ): Virus đạt được RQ01 và có khả năng lây nhiễm qua 
các file thực thi khác cùng thư mục khi người dùng kích hoạt tập tin vật chủ.
  - Mức yêu cầu 03 - RQ03 (5đ): Thay vì thay đổi Entry-point của chương trình, Hãy 
áp dụng lần lượt 02 chiến lược lây nhiễm trong nhóm kỹ thuật Entry-Point 
Obscuring (EPO) virus – che giấu điểm đầu vào thực thi của mã virus (virus code)
cho Virus đã thực hiện ở RQ01/RQ02. Một số dạng EPO-virus có thể xem xét để 
thực hiện yêu cầu này bao gồm:<br>
      o Call hijacking EPO virus<br>
      o Import Address Table-replacing EPO virus.<br>
      o TLS-based EPO virus.
